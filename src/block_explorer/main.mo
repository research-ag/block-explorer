// Bitcoin block-header importer with full reorg support.
//
// Two ways to add headers:
//   - import_next(n)        : pull next N from the official Bitcoin canister
//                             (ghsi2-tqaaa-aaaan-aaaca-cai)
//   - push_header(raw)      : push a single 80-byte raw header (blob);
//                             push_header_hex is the hex convenience wrapper
//
// Every accepted header is stored forever, indexed by hash. Forks are
// tracked; the canonical chain is whichever fork has the most cumulative
// proof-of-work.
//
// All chain state lives in top-level stable `let`s (the two tries plus a
// `Chain.State` bundle); EOP persists them directly, so no share/unshare or
// pre/post-upgrade hooks are needed.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Cycles "mo:core/Cycles";
import Int "mo:core/Int";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Time "mo:core/Time";

import Prim "mo:⛔";

import Sha256 "mo:sha2/Sha256";

import PT "mo:promtracker";
import StableTrie "mo:stable-trie/Enumeration";

import Header "Header";
import HeaderValue "HeaderValue";
import Headers "Headers";
import Chain "Chain";
import Esplora "Esplora";

persistent actor BlockExplorer {

  // ---------------------------------------------------------------------
  // Prometheus metrics — exposed via the Esplora HTTP handler at
  // `/metrics`. We only use PullValues here: every metric is derived
  // from data structures the canister already maintains for its own
  // operation, so there's a single source of truth per metric.
  //
  // System metrics (cycles_balance, rts_memory_size, rts_heap_size,
  // canister_version, …) come from `PT.allSystemMetrics`. Chain-
  // specific values are registered below once `chain` exists.
  // ---------------------------------------------------------------------
  transient let renderer = PT.Renderer();
  renderer.addCanisterLabel(BlockExplorer);
  renderer.addValue(PT.allSystemMetrics);

  // Stateful batch gauges (watermarks reset on upgrade, like the renderer).
  // Each Gauge emits <prefix>_last/_sum/_count plus high/low watermarks.
  transient let tracker = PT.Tracker.new();
  renderer.addValue(PT.Tracker.toValue(tracker));
  // Heap size (rts_heap_size) sampled at the end of each batch — including
  // batches stopped early by the heap limit.
  transient let heapAfterHeadersBatch = PT.Tracker.newGauge(tracker, "heap_size_after_headers_batch", [], []);
  transient let heapAfterTxidsBatch = PT.Tracker.newGauge(tracker, "heap_size_after_txids_batch", [], []);
  // Number of batch entries actually processed (may be less than submitted
  // when the batch halts on an error or the heap limit).
  transient let batchSizeHeaders = PT.Tracker.newGauge(tracker, "batch_size_headers", [], []);
  transient let batchSizeTxids = PT.Tracker.newGauge(tracker, "batch_size_txids", [], []);

  // Stop processing further batch entries once the heap reaches this size.
  // Headroom below the 4 GB wasm32 ceiling for the response, the GC and the
  // next message. Callers learn how far the batch got from the result's
  // accepted/duplicate counts and retry the rest later.
  //
  // Constants are `transient` so upgrades pick up new values from the code —
  // a plain `let` in a persistent actor is stable and would silently keep
  // the value the canister was installed with.
  transient let HEAP_LIMIT : Nat = 1_073_741_824; // 1 GiB

  func heapExceeded() : Bool = Prim.rts_heap_size() >= HEAP_LIMIT;

  // One SHA-256 engine for the canister's whole lifetime (re-created on
  // upgrade), threaded into every hashing call: constructing a Digest costs
  // ~3.3 KB of heap, reuse via reset() is ~0.4 KB per hash. A module-level
  // instance is impossible (M0014), so the actor owns it. Safe to share:
  // each use is synchronous within one message, never held across an await.
  transient let sha = Sha256.Digest(#sha256);

  // ---------------------------------------------------------------------
  // Bitcoin canister interface (ghsi2-tqaaa-aaaan-aaaca-cai).
  // ---------------------------------------------------------------------

  type Network = { #mainnet; #testnet };

  type GetBlockHeadersRequest = {
    start_height : Nat32;
    end_height : ?Nat32;
    network : Network;
  };

  type GetBlockHeadersResponse = {
    tip_height : Nat32;
    block_headers : [Blob];
  };

  type BitcoinCanister = actor {
    bitcoin_get_block_headers : (GetBlockHeadersRequest) -> async GetBlockHeadersResponse;
  };

  transient let bitcoin_canister : BitcoinCanister = actor ("ghsi2-tqaaa-aaaan-aaaca-cai");

  var cyclesPerCall : Nat = 10_000_000_000;
  transient let MAX_BATCH : Nat = 100;

  // ---------------------------------------------------------------------
  // Chain state.
  //
  // All chain state is held in top-level stable `let`s — the two stable-trie
  // Enumerations directly, and the heap structures bundled into `chain :
  // Chain.State` (see Chain.mo). There is no class, no share/unshare and no
  // pre/postupgrade hook: a top-level `let` initializer runs ONLY on fresh
  // install, so on upgrade EOP restores each value as-is. Operations use
  // dot-notation, e.g. `chain.push(...)` == `Chain.push(chain, ...)`.
  // ---------------------------------------------------------------------

  // Single top-level stable root. The two tries are fields (chain.headerTrie /
  // chain.txTrie); building them inline keeps each trie referenced from exactly
  // one place.
  let chain : Chain.State = Chain.newState(
    Chain.newHeaderTrie(Headers.KEY_SIZE),
    Chain.newTxTrie(Chain.TX_ROOT_ARIDITY),
  );

  func nowSecs() : Int { Time.now() / 1_000_000_000 };
  func nowSecsNat32() : Nat32 {
    let s = nowSecs();
    if (s <= 0) 0 else Nat32.fromNat(Int.abs(s) % 0x1_0000_0000);
  };

  // Fresh install only: seed genesis. Runs on every actor start, but the
  // `initialized` guard (persisted) makes it a no-op after the first install.
  if (not chain.initialized) {
    Chain.initGenesis(chain, sha, nowSecsNat32(), Principal.fromActor(BlockExplorer));
  };

  // Chain-level pull values, read from `chain` directly so the metric output
  // is always consistent with what the canister currently sees.
  renderer.addValue(PT.newValue("headers_total", [], func() = chain.size()));
  renderer.addValue(PT.newValue("tip_height", [], func() = chain.tipHeight()));
  renderer.addValue(PT.newValue("bodies_height", [], func() = chain.bodiesHeight()));
  renderer.addValue(PT.newValue("uploader_count", [], func() = chain.uploaderStats().size()));
  // Memory stats of both stable-trie Enumerations (stable_trie_node_count /
  // _leaf_count / _byte_size families, with a kind="used"|"total" label),
  // distinguished by a `trie` label.
  renderer.addValue(PT.bundle([StableTrie.toValue(chain.headerTrie)], [("trie", "headers")]));
  renderer.addValue(PT.bundle([StableTrie.toValue(chain.txTrie)], [("trie", "txids")]));
  // Heap data-structure stats: fork-store sizes and reorg history
  // (chain_fork_* / chain_reorg_* families), computed once per scrape.
  renderer.addValue(chain.heapStatsValue());

  // ---------------------------------------------------------------------
  // Candid-facing types & projections.
  // ---------------------------------------------------------------------

  public type BlockInfo = {
    height : Nat;
    version : Nat32;
    prev_hash_be_hex : Text;
    merkle_root_be_hex : Text;
    time : Nat32;
    bits : Nat32;
    nonce : Nat32;
    hash_be_hex : Text;
    difficulty_x1e8 : Nat;
    cum_work : Nat;
    is_canonical : Bool;
    first_seen : Nat32; // unix seconds when first stored
    uploader : Principal; // principal that pushed this header
  };

  func toBlockInfo(b : Chain.StoredBlock, isCanonical_ : Bool) : BlockInfo {
    let v = b.value;
    let bits = HeaderValue.bitsOf(v);
    let target = Header.nBitsToTarget(bits);
    let difficulty_x1e8 : Nat = if (target == 0) 0 else Header.POW_LIMIT_TARGET * 100_000_000 / target;
    let prevHashLE = Chain.prevHashOf(b);
    let merkleLE = HeaderValue.merkleOf(v);
    {
      height = b.height;
      version = HeaderValue.versionOf(v);
      prev_hash_be_hex = Header.bytesToHex(Header.reverse32(prevHashLE));
      merkle_root_be_hex = Header.bytesToHex(Header.reverse32(merkleLE));
      time = HeaderValue.timeOf(v);
      bits;
      nonce = HeaderValue.nonceOf(v);
      hash_be_hex = Header.bytesToHex(Header.reverse32(b.hash));
      difficulty_x1e8;
      cum_work = b.cumWork;
      is_canonical = isCanonical_;
      first_seen = HeaderValue.firstSeenOf(v);
      uploader = chain.uploaderOf(b.hash);
    };
  };

  // ---------------------------------------------------------------------
  // Push API.
  // ---------------------------------------------------------------------

  // The standard push interface (single and batched) is raw-byte based:
  // headers go in as 80-byte blobs, results come back as counts / raw
  // hashes — no hex anywhere on the path. push_header_hex is the single
  // hex convenience wrapper for manual / console use.

  public type BatchPushResult = {
    accepted : Nat; // number of headers successfully appended
    tip_height : Nat; // canonical tip height after the batch
    last_error : ?Text; // first failure encountered (stops the batch)
  };

  // Maximum headers per push_headers call.
  // 20_000 * 80 = 1_600_000 bytes of raw header data (under the 2 MB
  // ingress message limit).
  transient let MAX_PUSH_BATCH : Nat = 20_000;

  // Standard single push: raw 80-byte header in, raw hash out.
  public shared ({ caller }) func push_header(raw_header : Blob) : async Result.Result<Chain.PushOk, Text> {
    chain.push(sha, raw_header, nowSecs(), caller);
  };

  // Hex convenience wrapper (single only): hex header in, hex hash out.
  public type PushOkHex = {
    height : Nat;
    hash_be_hex : Text;
    is_canonical : Bool;
    reorg_depth : Nat;
  };

  public shared ({ caller }) func push_header_hex(raw_hex : Text) : async Result.Result<PushOkHex, Text> {
    Result.mapOk<Chain.PushOk, PushOkHex, Text>(
      chain.push(sha, Header.hexToBlob(raw_hex), nowSecs(), caller),
      func(ok) = {
        height = ok.height;
        hash_be_hex = Header.bytesToHex(Header.reverse32(ok.hash));
        is_canonical = ok.is_canonical;
        reorg_depth = ok.reorg_depth;
      },
    );
  };

  // Loop body of push_headers, also reusable by inspect_message as a true
  // dry-run. Pushes headers in order, halting at the first rejection. Any
  // state mutations made from inspect_message's invocation are discarded by
  // the IC when inspect returns, so calling this from there is safe.
  func pushHeadersImpl(headers : [Blob], caller : Principal) : BatchPushResult {
    let now = nowSecs();
    var accepted : Nat = 0;
    var lastErr : ?Text = null;
    label loopH for (h in headers.vals()) {
      switch (chain.push(sha, h, now, caller)) {
        case (#ok _) accepted += 1;
        case (#err msg) { lastErr := ?msg; break loopH };
      };
      if (heapExceeded()) {
        lastErr := ?("heap limit reached: batch stopped after " # debug_show accepted # " headers; retry the rest");
        break loopH;
      };
    };
    PT.Gauge.update(heapAfterHeadersBatch, Prim.rts_heap_size());
    PT.Gauge.update(batchSizeHeaders, accepted);
    {
      accepted;
      tip_height = chain.tipHeight();
      last_error = lastErr;
    };
  };

  // Push a batch of raw 80-byte headers in order. Stops at the first
  // rejection and reports how many were accepted plus the error message.
  public shared ({ caller }) func push_headers(headers : [Blob]) : async Result.Result<BatchPushResult, Text> {
    if (headers.size() > MAX_PUSH_BATCH) return #err("batch too large: max " # debug_show MAX_PUSH_BATCH # " headers per call");
    #ok(pushHeadersImpl(headers, caller));
  };

  // ---------------------------------------------------------------------
  // Block bodies (canonical transaction index).
  //
  // Index a canonical block's transaction ids, verified against the
  // header's merkle root. Bodies must be uploaded in strict height order
  // (genesis first); the txid trie stores every canonical transaction
  // consecutively in chain order, and each block records the index of
  // its first transaction (firstTxIndex) in the header value.
  // ---------------------------------------------------------------------

  public type BodyBatchResult = {
    accepted : Nat; // bodies newly indexed in this call
    duplicate : Nat; // bodies already indexed; no-op'd
    last_error : ?Text; // first failure that halted the batch
  };

  public func push_body(block_hash_internal : Blob, tx_count : Nat, hashes : Blob) : async Result.Result<Chain.PushBodyOk, Text> {
    chain.pushBody(sha, block_hash_internal, tx_count, hashes);
  };

  // Batched upload; processes entries in order, stopping at the first
  // real failure (returned in last_error). Already-indexed bodies are
  // counted as duplicates and don't halt the batch.
  public func push_bodies(batch : [(Blob, Nat, Blob)]) : async Result.Result<BodyBatchResult, Text> {
    if (batch.size() == 0) return #err("empty batch");
    var accepted = 0;
    var duplicate = 0;
    var lastErr : ?Text = null;
    label loopB for ((block_hash, tx_count, hashes) in batch.vals()) {
      switch (chain.pushBody(sha, block_hash, tx_count, hashes)) {
        case (#ok ok) if (ok.duplicate) duplicate += 1 else accepted += 1;
        case (#err msg) { lastErr := ?msg; break loopB };
      };
      if (heapExceeded()) {
        lastErr := ?("heap limit reached: batch stopped after " # debug_show (accepted + duplicate) # " bodies; retry the rest");
        break loopB;
      };
    };
    PT.Gauge.update(heapAfterTxidsBatch, Prim.rts_heap_size());
    PT.Gauge.update(batchSizeTxids, accepted + duplicate);
    #ok({ accepted; duplicate; last_error = lastErr });
  };

  // tx_count of the canonical block at `height`, or null if its body
  // is not yet known.
  public query func tx_count_of(height : Nat) : async ?Nat = async chain.txCountAt(height);

  // tx_count of any block (canonical or fork) by big-endian display hash,
  // or null if unknown / no body. Works for fork blocks whose bodies were
  // uploaded into the heap fork-body store.
  public query func tx_count_of_hash(hash_be_hex : Text) : async ?Nat {
    let bytes = Header.hexToBlob(hash_be_hex);
    if (bytes.size() != 32) return null;
    chain.txCountOfHash(Header.reverse32(bytes));
  };

  // Body summary (tx_count + first_tx_index) for a canonical block.
  public query func get_body(height : Nat) : async ?Chain.BodyInfo = async chain.bodyAt(height);

  // All known blocks containing `txid` (32 bytes, internal LE): the
  // canonical block's height (if any) plus the big-endian display hashes of
  // every fork block that holds it. Callers that only care about the
  // canonical chain can ignore `fork_block_hashes_be`.
  public type TxLocation = {
    canonical_height : ?Nat;
    fork_block_hashes_be : [Text];
  };

  public query func lookup_txid(txid : Blob) : async TxLocation {
    let r = chain.lookupTxid(txid);
    {
      canonical_height = r.canonical;
      fork_block_hashes_be = Array.map<Blob, Text>(
        r.forks,
        func(h) = Header.bytesToHex(Header.reverse32(h)),
      );
    };
  };

  // The next height whose body may be uploaded (= count of indexed bodies).
  public query func bodies_next_height() : async Nat = async chain.bodiesHeight();

  // Total transactions indexed across the canonical chain.
  public query func total_indexed_txids() : async Nat = async chain.totalIndexedTxids();

  // Summary of the indexed-transaction frontier for the UI.
  public type TxidStatus = {
    total_txids : Nat; // total canonical txids indexed
    txid_height : ?Nat; // highest canonical height whose body is indexed
    txid_tip_time : ?Nat32; // timestamp of the block at txid_height
  };

  public query func txid_status() : async TxidStatus {
    let total = chain.totalIndexedTxids();
    let bh = chain.bodiesHeight(); // # canonical blocks with bodies; heights [0, bh)
    if (bh == 0) {
      return { total_txids = total; txid_height = null; txid_tip_time = null };
    };
    let h : Nat = bh - 1;
    let time = switch (chain.canonicalAt(h)) {
      case (?b) ?HeaderValue.timeOf(b.value);
      case null null;
    };
    { total_txids = total; txid_height = ?h; txid_tip_time = time };
  };

  // ---------------------------------------------------------------------
  // Transaction lookups.
  // ---------------------------------------------------------------------

  // One occurrence of a transaction: the block that contains it, with the
  // block's height, canonical/fork status, timestamp, and the tx's position
  // within the block.
  public type TxOccurrence = {
    block_hash_be_hex : Text;
    height : Nat;
    is_canonical : Bool;
    block_time : Nat32;
    position : Nat;
  };

  // A transaction view: every block (canonical + forks) that contains the
  // txid, plus its global serial number in the canonical tx ordering (if
  // it's in a canonical block).
  public type TxView = {
    txid_be_hex : Text;
    canonical_index : ?Nat;
    occurrences : [TxOccurrence];
  };

  // Find a transaction by big-endian display txid. Returns null if no known
  // block contains it.
  public query func find_tx(txid_be_hex : Text) : async ?TxView {
    let bytes = Header.hexToBlob(txid_be_hex);
    if (bytes.size() != 32) return null;
    let txid = Header.reverse32(bytes);
    let loc = chain.txLocations(txid);
    let canonOcc : ?TxOccurrence = switch (loc.canonical) {
      case (?c) switch (chain.canonicalAt(c.height)) {
        case (?b) ?{
          block_hash_be_hex = Header.bytesToHex(Header.reverse32(b.hash));
          height = c.height;
          is_canonical = true;
          block_time = HeaderValue.timeOf(b.value);
          position = c.position;
        };
        case null null;
      };
      case null null;
    };
    let forkOccs = Array.map<Chain.TxForkLoc, TxOccurrence>(
      loc.forks,
      func(f) {
        let t = switch (chain.byHashInternal(f.hash)) {
          case (?b) HeaderValue.timeOf(b.value);
          case null (0 : Nat32);
        };
        {
          block_hash_be_hex = Header.bytesToHex(Header.reverse32(f.hash));
          height = f.height;
          is_canonical = false;
          block_time = t;
          position = f.position;
        };
      },
    );
    let occurrences = switch (canonOcc) {
      case (?o) Array.tabulate<TxOccurrence>(forkOccs.size() + 1, func(i) = if (i == 0) o else forkOccs[i - 1]);
      case null forkOccs;
    };
    if (occurrences.size() == 0) return null;
    ?{
      txid_be_hex = Header.bytesToHex(Header.reverse32(txid));
      canonical_index = switch (loc.canonical) { case (?c) ?c.index; case null null };
      occurrences;
    };
  };

  // The txid (big-endian display) at a global canonical serial index, or null.
  public query func txid_at_index(index : Nat) : async ?Text {
    switch (chain.txidAtIndex(index)) {
      case (?t) ?Header.bytesToHex(Header.reverse32(t));
      case null null;
    };
  };

  // The transaction ids (big-endian display) of a block, in block order,
  // paginated (limit capped at 1000). Works for canonical and fork blocks.
  public query func block_txids(block_hash_be_hex : Text, offset : Nat, limit : Nat) : async [Text] {
    let bytes = Header.hexToBlob(block_hash_be_hex);
    if (bytes.size() != 32) return [];
    let cap = if (limit > 1000) 1000 else limit;
    Array.map<Blob, Text>(
      chain.blockTxids(Header.reverse32(bytes), offset, cap),
      func(t) = Header.bytesToHex(Header.reverse32(t)),
    );
  };

  // ---------------------------------------------------------------------
  // Ingress inspection.
  //
  // inspect_message runs at the boundary node before an ingress call
  // is forwarded to the actor. Returning `false` rejects the call
  // outright. For the three push methods we run the same code as
  // the real handler as a dry-run: the IC discards any state
  // mutations made during inspect, so calling chain.push /
  // pushHeadersImpl here is safe and gives us an exact prediction
  // of whether the call would make progress.
  //
  //   push_header        — accept iff chain.push returns #ok.
  //   push_headers       — accept iff at least one header would be
  //                        newly added (`accepted > 0`). Rejects
  //                        empty / oversize / all-known / error-
  //                        before-first-add uniformly.
  //   push_header_hex    — same as push_header, after hex decode.
  //
  // All other methods pass through unchanged.
  // ---------------------------------------------------------------------
  // NOTE: inspect_message is intentionally DISABLED (commented out below).
  // When enabled it ran the full push (validation + storage + any reorg)
  // as a boundary-node dry run whose state changes the IC discards — an
  // exact accept/reject predictor that spam-filtered bad/duplicate/orphan/
  // stale headers, at the cost of doing that work twice per accepted push.
  // With it disabled, all ingress messages are accepted at the boundary and
  // filtering happens only in the real call. To re-enable, uncomment.
  /*
  system func inspect({
    caller : Principal;
    arg : Blob;
    msg : {
      #blocks_by_uploader : () -> (p : Principal, offset : Nat, limit : Nat);
      #bodies_next_height : () -> ();
      #cycles_balance : () -> ();
      #get_body : () -> (height : Nat);
      #get_by_hash : () -> (hash_be_hex : Text);
      #get_cycles_per_call : () -> ();
      #get_view : () -> (height : ?Nat);
      #have_hashes : () -> (hashes_be_hex : [Text]);
      #header_db_memory_stats : () -> ();
      #http_request : () -> (req : Esplora.Request);
      #import_next : () -> (max_batch : Nat);
      #lookup_txid : () -> (txid : Blob);
      #push_body : () -> (block_hash_internal : Blob, tx_count : Nat, hashes : Blob);
      #push_bodies : () -> (batch : [(Blob, Nat, Blob)]);
      #push_header : () -> (raw_header : Blob);
      #push_header_hex : () -> (raw_hex : Text);
      #push_headers : () -> (headers : [Blob]);
      #reorg_log : () -> (offset : Nat, limit : Nat);
      #set_cycles_per_call : () -> (n : Nat);
      #total_indexed_txids : () -> ();
      #tx_count_of : () -> (height : Nat);
      #tx_count_of_hash : () -> (hash_be_hex : Text);
      #uploader_leaderboard : () -> (top : Nat)
    };
  }) : Bool {
    ignore arg;
    switch (msg) {
      case (#push_header fetch) {
        let raw_hex = fetch();
        switch (chain.push(sha, Header.hexToBlob(raw_hex), nowSecs(), caller)) {
          case (#ok _) true;
          case (#err _) false;
        };
      };
      case (#push_headers fetch) {
        let headers = fetch();
        if (headers.size() > MAX_PUSH_BATCH) return false;
        pushHeadersImpl(headers, caller).accepted > 0;
      };
      case (#push_headers_hex fetch) {
        let headers_hex = fetch();
        if (headers_hex.size() > MAX_PUSH_BATCH) return false;
        let headers = Array.tabulate<Blob>(
          headers_hex.size(),
          func(i) = Header.hexToBlob(headers_hex[i]),
        );
        pushHeadersImpl(headers, caller).accepted > 0;
      };
      case (_) true;
    };
  };
  */

  // ---------------------------------------------------------------------
  // Pull API.
  // ---------------------------------------------------------------------

  // Headers fetched from the Bitcoin canister are attributed to the
  // anonymous principal rather than to the caller of `import_next`,
  // since the caller is only triggering the relay — the content
  // originates from the IC's Bitcoin integration, not from a user.
  transient let ANONYMOUS_PRINCIPAL : Principal = Principal.fromText("2vxsx-fae");

  // Only this principal may invoke `import_next`. The function spends
  // canister cycles on every call, so it's restricted to a single
  // operator identity.
  transient let IMPORT_OPERATOR : Principal = Principal.fromText(
    "5yxw4-okdhg-twoqv-qjshi-uammo-kn5yg-guwus-r3u4m-codgm-3lle6-oae"
  );

  public shared ({ caller }) func import_next(max_batch : Nat) : async Result.Result<Nat, Text> {
    if (caller != IMPORT_OPERATOR) {
      return #err("unauthorized: import_next is restricted");
    };
    let nextHeight = chain.tipHeight() + 1;
    let batch = if (max_batch == 0) 1 else if (max_batch > MAX_BATCH) MAX_BATCH else max_batch;

    let req : GetBlockHeadersRequest = {
      start_height = Nat32.fromNat(nextHeight);
      end_height = ?Nat32.fromNat(nextHeight + batch - 1 : Nat);
      network = #mainnet;
    };

    let resp = try {
      await (with cycles = cyclesPerCall)
      bitcoin_canister.bitcoin_get_block_headers(req);
    } catch (_) {
      return #err("call to bitcoin canister failed");
    };

    var imported : Nat = 0;
    var firstErr : ?Text = null;
    label loopH for (h in resp.block_headers.vals()) {
      switch (chain.push(sha, h, nowSecs(), ANONYMOUS_PRINCIPAL)) {
        case (#ok _) imported += 1;
        case (#err msg) { firstErr := ?msg; break loopH };
      };
      if (heapExceeded()) break loopH;
    };
    PT.Gauge.update(heapAfterHeadersBatch, Prim.rts_heap_size());
    PT.Gauge.update(batchSizeHeaders, imported);
    switch (firstErr) {
      case (?msg) if (imported == 0) return #err(msg);
      case null {};
    };
    #ok(imported);
  };

  // ---------------------------------------------------------------------
  // Queries.
  // ---------------------------------------------------------------------

  // Combined "page view" query: returns the tip, the requested block (if
  // any), all siblings at that height, total blocks stored and the current
  // fork list — everything the frontend needs for one screen, in a single
  // round trip.
  public type ChainView = {
    tip : BlockInfo;
    total_blocks : Nat;
    forks : [Chain.Fork];
    block : ?BlockInfo; // canonical block at the requested height
    siblings : [BlockInfo]; // all blocks at that height (incl. canonical)
  };

  public query func get_view(height : ?Nat) : async ChainView {
    let tipBlock = chain.tipBlock();
    let h : Nat = switch height {
      case (?x) x;
      case null tipBlock.height;
    };
    let block_ : ?BlockInfo = switch (chain.canonicalAt(h)) {
      case (?b) ?toBlockInfo(b, true);
      case null null;
    };
    let siblings_ : [BlockInfo] = Array.map<Chain.StoredBlock, BlockInfo>(
      chain.allAt(h),
      func(b) = toBlockInfo(b, Chain.isOnCanonical(b)),
    );
    {
      tip = toBlockInfo(tipBlock, true);
      total_blocks = chain.size();
      forks = chain.forks();
      block = block_;
      siblings = siblings_;
    };
  };

  // Single-block lookup by hash (for the search box).
  public query func get_by_hash(hash_be_hex : Text) : async ?BlockInfo {
    switch (chain.byHashBE(hash_be_hex)) {
      case (?b) ?toBlockInfo(b, Chain.isOnCanonical(b));
      case null null;
    };
  };

  // Batched membership check. Used by client-side pre-filters to avoid
  // shipping headers whose hash is already stored or whose parent is
  // unknown. Returns one Bool per input, in the same order.
  transient let MAX_HAVE_HASHES : Nat = 50_000;
  public query func have_hashes(hashes_be_hex : [Text]) : async [Bool] {
    if (hashes_be_hex.size() > MAX_HAVE_HASHES) {
      // Best-effort: trap rather than silently truncate.
      Runtime.trap("have_hashes: too many entries (max " # debug_show MAX_HAVE_HASHES # ")");
    };
    Array.tabulate<Bool>(
      hashes_be_hex.size(),
      func(i) = chain.hasHashBE(hashes_be_hex[i]),
    );
  };

  // Stable-trie memory stats (bytes used + node/leaf counts).
  public type StableTrieStats = {
    byte_size : Nat;
    leaf_count : Nat;
    node_count : Nat;
  };

  public query func header_db_memory_stats() : async StableTrieStats {
    let m = chain.memoryStats();
    {
      byte_size = m.total_bytes; // renamed in stable-trie 0.1.4; candid field kept
      leaf_count = m.used_leaf_count;
      node_count = m.used_node_count;
    };
  };

  // ---------------------------------------------------------------------
  // Uploader leaderboard.
  // ---------------------------------------------------------------------

  public type UploaderEntry = { uploader : Principal; count : Nat };

  // Top `top` uploaders by number of distinct headers stored,
  // descending. Ties broken by registration order (older first).
  // Pass 0 to get the full list.
  public query func uploader_leaderboard(top : Nat) : async [UploaderEntry] {
    let stats = chain.uploaderStats();
    let sorted = Array.sort<(Principal, Nat)>(
      stats,
      func(a, b) = Nat.compare(b.1, a.1),
    );
    let limit = if (top == 0 or top > sorted.size()) sorted.size() else top;
    Array.tabulate<UploaderEntry>(
      limit,
      func(i) = { uploader = sorted[i].0; count = sorted[i].1 },
    );
  };

  // Page through the headers uploaded by `p`, newest-first. `offset`
  // is 0 for the most recent. `limit` is capped at 1000 to keep
  // response sizes bounded. Returns [] for the anonymous principal
  // (we don't track its individual blocks; see Chain.uploaders).
  public query func blocks_by_uploader(p : Principal, offset : Nat, limit : Nat) : async [BlockInfo] {
    let cap : Nat = if (limit > 1000) 1000 else limit;
    let hashes = chain.blocksByUploader(p, offset, cap);
    Array.tabulate<BlockInfo>(
      hashes.size(),
      func(i) {
        switch (chain.byHashInternal(hashes[i])) {
          case (?b) toBlockInfo(b, Chain.isOnCanonical(b));
          case null Runtime.trap(
            "blocks_by_uploader: hash " # debug_show hashes[i] # " missing"
          );
        };
      },
    );
  };

  // ---------------------------------------------------------------------
  // Reorg log.
  // ---------------------------------------------------------------------

  // Page through recorded reorg events, newest first. `offset` is 0 for
  // the most recent. `limit` is capped at 1000.
  public query func reorg_log(offset : Nat, limit : Nat) : async [Chain.ReorgEvent] {
    let all = chain.reorgs();
    let n = all.size();
    if (offset >= n) return [];
    let cap : Nat = if (limit > 1000) 1000 else limit;
    if (cap == 0) return [];
    let remaining : Nat = n - offset;
    let take = if (cap < remaining) cap else remaining;
    Array.tabulate<Chain.ReorgEvent>(
      take,
      func(k) = all[n - 1 - offset - k],
    );
  };

  // ---------------------------------------------------------------------
  // Cycles.
  // ---------------------------------------------------------------------

  public query func cycles_balance() : async Nat { Cycles.balance() };

  public query func get_cycles_per_call() : async Nat { cyclesPerCall };

  public shared ({ caller }) func set_cycles_per_call(n : Nat) : async () {
    if (not Principal.isController(caller)) {
      Runtime.trap("unauthorized: set_cycles_per_call is controller-only");
    };
    cyclesPerCall := n;
  };

  // ---------------------------------------------------------------------
  // HTTP gateway: serves /metrics (Prometheus exposition) and a subset
  // of the Esplora REST API under /api/... See src/Esplora.mo for the
  // route list. We define `http_request` ourselves (rather than using
  // the PromHttp mixin) so the same handler can dispatch all routes.
  // ---------------------------------------------------------------------

  public query func http_request(req : Esplora.Request) : async Esplora.Response {
    Esplora.handle(chain, renderer.renderExposition, req);
  };
};
