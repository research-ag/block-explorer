// Bitcoin block-body index canister.
//
// Pairs with `block_explorer`. For every header that explorer knows
// about, this canister can store a compact summary of the block's
// transaction list (not the transactions themselves), verified
// against the header's merkle root.
//
// Storage trick: we add txids to the trie in block order, and the
// trie's enumeration assigns consecutive `txdbidx`s. So we only
// store `(tx_count, first_txdbidx)` per block (8 bytes total) and
// the txid at position `i` of block `dbidx` is found by:
//
//     body     = bodies.get(dbidx)
//     txdbidx  = body.first_txdbidx + i
//     txid     = txidTrie.get(txdbidx)
//
// And the inverse `txid -> (dbidx, position)`:
//
//     (dbidx_blob, txdbidx) = txidTrie.lookup(txid)
//     body                  = bodies.get(decode(dbidx_blob))
//     position              = txdbidx - body.first_txdbidx
//
// Stable layout:
//   - body region:  8 bytes/slot indexed by dbidx
//                   (24-bit tx_count + 40-bit first_txdbidx)
//   - txid trie:    key 32 bytes, value 4 bytes (dbidx Nat32 LE)
//                   pointer_size = 5 (40-bit txdbidx capacity)

import Blob "mo:core/Blob";
import Cycles "mo:core/Cycles";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";

import StableTrie "mo:stable-trie/Enumeration";
import PT "mo:promtracker";
import Http "mo:promtracker/mixins/http";

import BlockBodyStore "BlockBodyStore";
import Merkle "Merkle";

persistent actor BlockBodies {

  // ------------------------------------------------------------------
  // Prometheus metrics — exposed at `/metrics` via the http mixin.
  // System metrics cover cycles_balance, rts_memory_size,
  // rts_heap_size, canister_version, etc. Data-structure pull
  // values for the txid trie and body region are registered after
  // those structures exist (further down). All metrics here are
  // PullValues backed by the underlying data structures, so there
  // is one source of truth per metric.
  // ------------------------------------------------------------------
  transient let renderer = PT.Renderer();
  renderer.addCanisterLabel(BlockBodies);
  renderer.addValue(PT.allSystemMetrics);
  include Http(renderer.renderExposition, "/metrics");


  // ------------------------------------------------------------------
  // block_explorer interface (subset).
  // ------------------------------------------------------------------

  type HeaderRef = { dbidx : Nat; merkle_root : Blob };

  type BlockExplorer = actor {
    lookup_header : (Blob) -> async ?HeaderRef;
  };

  transient let blockExplorerId : Principal = Principal.fromText(
    switch (Runtime.envVar<system>("PUBLIC_CANISTER_ID:block_explorer")) {
      case (?id) id;
      case null Runtime.trap("PUBLIC_CANISTER_ID:block_explorer not set");
    }
  );

  transient let blockExplorer : BlockExplorer =
    actor (Principal.toText(blockExplorerId));

  // ------------------------------------------------------------------
  // Stable storage.
  // ------------------------------------------------------------------

  var bodyData : ?BlockBodyStore.StableData = null;
  transient let bodies : BlockBodyStore.BlockBodyStore = BlockBodyStore.BlockBodyStore();

  // Stable trie: txid -> dbidx (4 bytes LE). The enumeration index
  // assigned to each new key serves as the persistent `txdbidx`; we
  // recover it via lookup/get on the trie itself.
  // pointer_size = 5 caps the trie at 2^39 leaves (~550 B txids).
  transient let txidTrie = StableTrie.Enumeration({
    pointer_size = 5;
    aridity = 4;
    root_aridity = ?262144;
    key_size = 32;
    value_size = 4;
  });
  var txidTrieData : ?StableTrie.StableData = null;

  switch (bodyData) {
    case (?d) bodies.unshare(d);
    case null {};
  };
  switch (txidTrieData) {
    case (?d) txidTrie.unshare(d);
    case null {};
  };

  system func preupgrade() {
    bodyData := ?bodies.share();
    txidTrieData := ?txidTrie.share();
  };

  // Data-structure Prometheus pull values (registered now that the
  // trie and body region exist).
  renderer.addValue(PT.newValue("indexed_txids", [], func() = txidTrie.size()));
  renderer.addValue(PT.newValue("txid_trie_byte_size", [], func() = txidTrie.memoryStats().byte_size));
  renderer.addValue(PT.newValue("txid_trie_leaf_count", [], func() = txidTrie.memoryStats().leaf_count));
  renderer.addValue(PT.newValue("txid_trie_node_count", [], func() = txidTrie.memoryStats().node_count));
  renderer.addValue(PT.newValue("body_region_byte_size", [], func() = bodies.byteSize()));
  renderer.addValue(PT.newValue("body_capacity_blocks", [], func() = bodies.capacityBlocks()));

  // ------------------------------------------------------------------
  // Helpers.
  // ------------------------------------------------------------------

  // Encode dbidx as 4-byte LE for storage as the trie value.
  func encodeDbidx(dbidx : Nat) : Blob {
    if (dbidx > 0xFFFF_FFFF) Runtime.trap("dbidx overflow");
    let d = Nat32.fromNat(dbidx);
    let mut = VarArray.repeat<Nat8>(0, 4);
    mut[0] := Nat8.fromNat(((d) & 0xff).toNat());
    mut[1] := Nat8.fromNat(((d >> 8) & 0xff).toNat());
    mut[2] := Nat8.fromNat(((d >> 16) & 0xff).toNat());
    mut[3] := Nat8.fromNat(((d >> 24) & 0xff).toNat());
    Blob.fromVarArray(mut);
  };

  func decodeDbidx(b : Blob) : Nat {
    b[0].toNat()
    + b[1].toNat() * 0x100
    + b[2].toNat() * 0x1_0000
    + b[3].toNat() * 0x100_0000;
  };

  func eq32(a : Blob, b : Blob) : Bool {
    if (a.size() != 32 or b.size() != 32) return false;
    var i = 0;
    while (i < 32) { if (a[i] != b[i]) return false; i += 1 };
    true;
  };

  func leafAt(hashes : Blob, i : Nat) : Blob {
    let mut = VarArray.repeat<Nat8>(0, 32);
    let off = i * 32;
    var j = 0;
    while (j < 32) { mut[j] := hashes[off + j]; j += 1 };
    Blob.fromVarArray(mut);
  };

  // ------------------------------------------------------------------
  // Public upload API.
  // ------------------------------------------------------------------

  public type PutOk = {
    dbidx : Nat;
    tx_count : Nat;
    first_txdbidx : Nat;
    duplicate : Bool; // true if this body was already stored
  };

  // Result of a put_bodies batch: per-block details aren't returned;
  // the caller can recover them by re-reading bodies. `accepted` and
  // `duplicate` together count the entries that completed without
  // error (so the failed entry, if any, is at index
  // `accepted + duplicate` in the input batch).
  public type BatchPutResult = {
    accepted : Nat;       // bodies newly stored in this call
    duplicate : Nat;      // bodies already stored; no-op'd
    last_error : ?Text;   // first failure that halted the batch
  };

  // Per-call ingress cap. The IC ingress limit is ~2 MiB; each txid is
  // 32 bytes, so a hashes-only payload of MAX_BATCH_TXIDS * 32 = ~1 MiB
  // leaves comfortable headroom for the block hashes, length prefixes,
  // and Candid framing on top. 1 000 blocks max keeps the per-message
  // queueing cost bounded; on early-chain blocks (1 tx each) you'll
  // hit the 1 000-block limit first, on modern blocks (≈2000 txs) the
  // 31_250-txid limit caps you at a handful per call.
  let MAX_BATCH_BLOCKS : Nat = 1_000;
  let MAX_BATCH_TXIDS : Nat = 31_250;

  // Body of put_body, factored out so put_bodies can call it in a
  // loop. Returns the same Result.Result<PutOk, Text>.
  func putBodyImpl(
    block_hash_internal : Blob,
    tx_count : Nat,
    hashes : Blob,
  ) : async Result.Result<PutOk, Text> {
    if (block_hash_internal.size() != 32) {
      return #err("block hash must be 32 bytes");
    };
    if (tx_count == 0) return #err("tx_count must be >= 1");
    if (hashes.size() != tx_count * 32) {
      return #err(
        "hashes blob length " # debug_show hashes.size()
        # " != tx_count*32 (" # debug_show (tx_count * 32) # ")"
      );
    };

    let ref = switch (await blockExplorer.lookup_header(block_hash_internal)) {
      case null return #err("unknown block header hash");
      case (?r) r;
    };

    switch (bodies.get(ref.dbidx)) {
      case (?body) {
        return #ok({
          dbidx = ref.dbidx;
          tx_count = body.tx_count;
          first_txdbidx = body.first_txdbidx;
          duplicate = true;
        });
      };
      case null {};
    };

    let computed = Merkle.root(hashes, tx_count);
    if (not eq32(computed, ref.merkle_root)) {
      return #err("merkle root mismatch");
    };

    // Insert all txids; capture first_txdbidx from the first insert
    // and require every subsequent insert at position i to land at
    // first_txdbidx + i. Any deviation means a non-coinbase txid was
    // already in the trie from a different block — which would break
    // the consecutive-txdbidx invariant. We refuse the upload in
    // that case rather than corrupt the index.
    //
    // BIP30 (real cases at heights 91722/91880 and 91812/91842) is a
    // looser kind of duplicate: pure 1-tx blocks whose coinbase txid
    // is reused. Because the loop body only runs for i >= 1 and these
    // blocks have tx_count == 1, the invariant check never fires for
    // them. What happens instead, by accident-on-purpose:
    //
    //   * txidTrie.add(coinbase) returns the existing txdbidx and
    //     overwrites the stored block-dbidx value with the later
    //     block's. The trie does not grow.
    //   * bodies.put stores (1, existing_txdbidx) for the later
    //     block; the earlier block still has its own slot pointing
    //     to the same txdbidx.
    //   * tx_at(either_block, 0) returns the shared coinbase txid —
    //     correct, since both blocks really do have the same
    //     coinbase.
    //   * lookup_txid(coinbase) returns the *later* block; the
    //     earlier block becomes unreachable via the inverse index.
    //     Forward lookups (which is what an explorer mostly serves)
    //     stay correct.
    //
    // We accept this loss in the inverse direction rather than
    // refusing the 4 historical duplicate blocks entirely. The
    // explicit check below is still load-bearing for any hypothetical
    // future block whose coinbase collides AND has additional txs.
    let dbidxValue = encodeDbidx(ref.dbidx);
    let firstTxdbidx = txidTrie.add(leafAt(hashes, 0), dbidxValue);
    var i = 1;
    while (i < tx_count) {
      let txid = leafAt(hashes, i);
      let got = txidTrie.add(txid, dbidxValue);
      let expected : Nat = firstTxdbidx + i;
      if (got != expected) {
        return #err(
          "txid at position " # debug_show i
          # " breaks consecutive-txdbidx invariant"
          # " (got txdbidx " # debug_show got
          # ", expected " # debug_show expected
          # "). Cross-block duplicate txid; not BIP30 since BIP30"
          # " duplicates are 1-tx and don't reach this check."
        );
      };
      i += 1;
    };

    bodies.put(ref.dbidx, tx_count, firstTxdbidx);

    #ok({
      dbidx = ref.dbidx;
      tx_count;
      first_txdbidx = firstTxdbidx;
      duplicate = false;
    });
  };

  // Single-block upload — thin wrapper around the shared impl so
  // existing single-call clients still work.
  public func put_body(
    block_hash_internal : Blob,
    tx_count : Nat,
    hashes : Blob,
  ) : async Result.Result<PutOk, Text> {
    await putBodyImpl(block_hash_internal, tx_count, hashes);
  };

  // Batched upload. Processes entries in order; stops at the first
  // real validation failure (returns it in last_error). "Duplicate"
  // entries (block already stored) are counted but don't halt the
  // batch — same semantics as the single-block path.
  public func put_bodies(
    batch : [(Blob, Nat, Blob)],
  ) : async Result.Result<BatchPutResult, Text> {
    if (batch.size() == 0) return #err("empty batch");
    if (batch.size() > MAX_BATCH_BLOCKS) {
      return #err(
        "batch too large: " # debug_show batch.size() #
        " blocks > MAX_BATCH_BLOCKS=" # debug_show MAX_BATCH_BLOCKS
      );
    };
    var totalTxids : Nat = 0;
    for (entry in batch.vals()) {
      totalTxids += entry.1;
    };
    if (totalTxids > MAX_BATCH_TXIDS) {
      return #err(
        "batch too large: " # debug_show totalTxids #
        " txids > MAX_BATCH_TXIDS=" # debug_show MAX_BATCH_TXIDS
      );
    };

    var accepted : Nat = 0;
    var duplicate : Nat = 0;
    var lastErr : ?Text = null;
    label loopB for ((block_hash, tx_count, hashes) in batch.vals()) {
      let r = await putBodyImpl(block_hash, tx_count, hashes);
      switch r {
        case (#ok ok) {
          if (ok.duplicate) duplicate += 1 else accepted += 1;
        };
        case (#err msg) {
          lastErr := ?msg;
          break loopB;
        };
      };
    };
    #ok({ accepted; duplicate; last_error = lastErr });
  };

  // ------------------------------------------------------------------
  // Debug queries.
  // ------------------------------------------------------------------

  public type TxLocation = { dbidx : Nat; position : Nat };

  // Reverse-lookup: txid (32 bytes, internal LE) ->
  // (dbidx, position-within-block).
  public query func lookup_txid(txid : Blob) : async ?TxLocation {
    if (txid.size() != 32) return null;
    switch (txidTrie.lookup(txid)) {
      case null null;
      case (?(v, txdbidx)) {
        let dbidx = decodeDbidx(v);
        switch (bodies.get(dbidx)) {
          case null null; // shouldn't happen if invariants hold
          case (?body) ?{
            dbidx;
            position = (txdbidx - body.first_txdbidx : Nat);
          };
        };
      };
    };
  };

  // Just the txdbidx (raw enumeration index) for a given txid.
  public query func lookup_txdbidx(txid : Blob) : async ?Nat {
    if (txid.size() != 32) return null;
    switch (txidTrie.lookup(txid)) {
      case null null;
      case (?(_v, idx)) ?idx;
    };
  };

  // Inverse: txdbidx -> txid.
  public query func txid_of_txdbidx(idx : Nat) : async ?Blob {
    switch (txidTrie.get(idx)) {
      case null null;
      case (?(k, _v)) ?k;
    };
  };

  // tx_count for a given block dbidx, or null if no body stored.
  public query func tx_count_of(dbidx : Nat) : async ?Nat {
    bodies.txCountOf(dbidx);
  };

  // Block-body summary: tx_count and the txdbidx of the first tx.
  public query func get_body(dbidx : Nat) : async ?BlockBodyStore.Body {
    bodies.get(dbidx);
  };

  // Resolve the txid at position `position` of block `dbidx`.
  public query func tx_at(dbidx : Nat, position : Nat) : async ?Blob {
    switch (bodies.get(dbidx)) {
      case null null;
      case (?body) {
        if (position >= body.tx_count) return null;
        let txdbidx = body.first_txdbidx + position;
        switch (txidTrie.get(txdbidx)) {
          case null null;
          case (?(k, _v)) ?k;
        };
      };
    };
  };

  public type Stats = {
    indexed_txids : Nat;
    body_capacity_blocks : Nat;
  };

  public query func stats() : async Stats {
    {
      indexed_txids = txidTrie.size();
      body_capacity_blocks = bodies.capacityBlocks();
    };
  };

  // Stable-trie memory stats (bytes used + node/leaf counts), same
  // shape as block_explorer's `header_db_memory_stats`.
  public type StableTrieStats = {
    byte_size : Nat;
    leaf_count : Nat;
    node_count : Nat;
  };

  public query func txid_trie_memory_stats() : async StableTrieStats {
    txidTrie.memoryStats();
  };

  // Bytes of stable memory currently allocated to the body region.
  public query func body_region_byte_size() : async Nat {
    bodies.byteSize();
  };

  public query func cycles_balance() : async Nat { Cycles.balance() };

};
