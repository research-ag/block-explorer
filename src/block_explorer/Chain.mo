// Bitcoin block-header chain with full reorg support.
//
// Storage model
// -------------
//   Canonical chain (stable):  HeaderDb — a mo:stable-trie Enumeration
//     that holds ONLY the canonical chain, in height order. The
//     enumeration index equals the canonical height (genesis = 0,
//     tip = size-1). Append with `add`; retract the tip with
//     `removeLast`/`truncate` on a reorg. Values are compressed: no
//     prev_hash/parent pointer is stored because the parent of index i
//     is index i-1 (its key is the prev_hash).
//
//   Fork store (heap, EOP-stable): all NON-canonical blocks, stored in
//     full (including prev_hash). Two cooperating maps:
//       forkByHash   : Map<hash, ForkBlock>     — lookup / attach / dedup
//       forkByHeight : Map<height, [hash]>      — siblings at a height
//     Fork tips are derived on demand (a fork block is a tip iff no
//     other fork block names it as parent).
//
//   Uploader registry (heap, EOP-stable): a mo:enumeration BlobEnumeration
//     mapping uploader principal <-> id, plus per-id push-ordered block
//     hash lists. The anonymous principal is registered but its blocks
//     are not individually stored (only counted).
//
//   Reorg log (heap, EOP-stable): one record per reorg event.
//
// The class is `transient` in the actor; persistence goes through
// `share()`/`unshare()`.
//
// Hash convention
// ---------------
// Internally everything is in Bitcoin "internal" little-endian order
// (natural sha-256d output order). Big-endian (display) hex is only used
// at API boundaries.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Int "mo:core/Int";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Set "mo:core/Set";

import Enum "mo:enumeration";
import StableTrie "mo:stable-trie/Enumeration";

import Header "Header";
import HeaderDb "HeaderDb";
import HeaderValue "HeaderValue";
import Merkle "Merkle";

module {

  // ---------------------------------------------------------------------
  // Public types.
  // ---------------------------------------------------------------------

  // A "stored block" view returned by queries. Built on demand from the
  // canonical trie or the fork store; not persisted in this shape.
  public type StoredBlock = {
    hash : Blob; // internal LE order, 32 bytes
    height : Nat;
    cumWork : Nat;
    value : Blob; // 76-byte HeaderValue blob
    prevHash : Blob; // internal LE order, 32 bytes (zero for genesis)
    isCanonical : Bool;
  };

  public type PushOk = {
    height : Nat;
    hash_be_hex : Text;
    is_canonical : Bool;
    reorg_depth : Nat;
  };

  public type Fork = {
    tip_height : Nat;
    tip_hash_be_hex : Text;
    length : Nat;
    branch_height : Nat;
    branch_hash_be_hex : Text;
  };

  // The body of a fork block: its transaction ids (flat 32-byte blob, in
  // block order) plus its first-tx serial number F in the would-be
  // canonical ordering. Present only once all of the block's ancestors'
  // bodies are known (so F is determined) — see pushBody.
  public type ForkBody = {
    txids : Blob;
    firstTxIndex : Nat;
  };

  // A non-canonical block, stored in full in the heap-side fork store.
  // `body` is the optional transaction list (see ForkBody).
  public type ForkBlock = {
    hash : Blob; // internal LE order, 32 bytes
    prevHash : Blob; // internal LE order, 32 bytes
    version : Nat32;
    merkle : Blob; // internal LE order, 32 bytes
    time : Nat32;
    bits : Nat32;
    nonce : Nat32;
    height : Nat;
    cumWork : Nat;
    firstSeen : Nat32;
    body : ?ForkBody;
  };

  // One reorg event, appended to the reorg log whenever the canonical
  // chain is switched to a heavier branch.
  public type ReorgEvent = {
    time : Int; // timestamp threaded into push (seconds, as firstSeen)
    common_height : Nat; // height of the last shared canonical block
    fork_length : Nat; // # new-branch blocks promoted above the common ancestor
    displaced : Nat; // # old-canonical blocks rolled back
    old_tip_hash_be_hex : Text;
    old_tip_height : Nat;
    new_tip_hash_be_hex : Text;
    new_tip_height : Nat;
  };

  type BlobEnum = Enum.BlobEnumeration.BlobEnumeration;

  // A promtracker pull `Value` (structurally `PT.Value`): one `read()`
  // returns several `(name, labels, value)` samples per scrape.
  public type MetricValue = { read : () -> [(Text, Text, Nat)] };

  // Body summary for a canonical block whose transactions are indexed.
  public type BodyInfo = {
    height : Nat;
    tx_count : Nat;
    // F: this block's first tx in the canonical tx order. Only meaningful
    // when canonical_indexed; 0 otherwise.
    first_tx_index : Nat;
    canonical_indexed : Bool; // txids live in the canonical txid trie
  };

  public type PushBodyOk = {
    height : Nat;
    tx_count : Nat;
    first_tx_index : Nat;
    // true if the txids are now in the canonical txid trie; false if the
    // body was stored in the heap fork-body store (block not canonical,
    // or ahead of the canonical body frontier).
    canonical_indexed : Bool;
    duplicate : Bool; // body was already known
  };

  public type StableData = {
    headerDb : HeaderDb.StableData;
    tipWork : Nat;
    forkByHash : Map.Map<Blob, ForkBlock>;
    forkByHeight : Map.Map<Nat, [Blob]>;
    uploaderEnum : BlobEnum;
    uploaderBlocks : List.List<List.List<Blob>>;
    anonymousCount : Nat;
    reorgLog : List.List<ReorgEvent>;
    // Block-body index (canonical transactions, in chain order).
    txTrie : StableTrie.Enumeration;
    bodiesNextHeight : Nat; // canonical bodies known contiguously for [0, this)
    txCountOverride : Map.Map<Nat, Nat>; // blocks with duplicate txids (BIP30)
    // Fork-block bodies live in the ForkBlock records (forkByHash).
  };

  // ---------------------------------------------------------------------
  // Helpers (module-local).
  // ---------------------------------------------------------------------

  func bytesToHexBE(b : Blob) : Text {
    Header.bytesToHex(Header.reverse32(b));
  };

  // 32-byte all-zero blob (genesis prev_hash).
  let ZERO_HASH_BLOB : Blob = "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00";

  // The IC anonymous principal, used as the default uploader for blocks
  // whose hash isn't individually attributed (see uploader registry).
  func anonymousPrincipal() : Principal = Principal.fromText("2vxsx-fae");

  func nat32OfNowSecs(s : Int) : Nat32 {
    if (s <= 0) 0 else Nat32.fromNat(Int.abs(s) % 0x1_0000_0000);
  };

  // One year in seconds (365 days). Freshness check on pushed headers.
  let ONE_YEAR_SECS : Nat = 31_536_000;

  // Extract the byte at little-endian position `i` (0..3) from a Nat32.
  func le32Byte(v : Nat32, i : Nat) : Nat8 {
    Nat8.fromNat(Nat32.toNat((v >> (Nat32.fromNat(i) * 8)) & 0xff));
  };

  // Encode a block height as a 4-byte little-endian blob (txid-trie value).
  func encodeHeight(h : Nat) : Blob {
    if (h > 0xFFFF_FFFF) Runtime.trap("Chain: height overflow for txid trie value");
    let v = Nat32.fromNat(h);
    Blob.fromArray([le32Byte(v, 0), le32Byte(v, 1), le32Byte(v, 2), le32Byte(v, 3)]);
  };

  func decodeHeight(b : Blob) : Nat {
    Nat8.toNat(b[0]) + Nat8.toNat(b[1]) * 0x100 + Nat8.toNat(b[2]) * 0x1_0000 + Nat8.toNat(b[3]) * 0x100_0000;
  };

  // Slice the 32-byte txid at index `i` out of a flat hashes blob.
  func txidAt(hashes : Blob, i : Nat) : Blob {
    let arr = Blob.toArray(hashes);
    let off = i * 32;
    Blob.fromArray(Array.tabulate<Nat8>(32, func(j) = arr[off + j]));
  };

  // ---------------------------------------------------------------------
  // Chain class.
  // ---------------------------------------------------------------------

  // `keySize` is the canonical-trie key width. Production passes
  // HeaderDb.KEY_SIZE (28); tests may pass HeaderDb.HASH_SIZE (32) to
  // store synthetic non-PoW headers (see HeaderDb).
  public class Chain(keySize : Nat) {

    let headerDb : HeaderDb.HeaderDb = HeaderDb.HeaderDb(keySize);
    var tipWork : Nat = 0;

    // Fork store.
    var forkByHash : Map.Map<Blob, ForkBlock> = Map.empty<Blob, ForkBlock>();
    var forkByHeight : Map.Map<Nat, [Blob]> = Map.empty<Nat, [Blob]>();

    // Uploader registry.
    var uploaderEnum : BlobEnum = Enum.BlobEnumeration.empty();
    var uploaderBlocks : List.List<List.List<Blob>> = List.empty<List.List<Blob>>();
    var anonymousCount : Nat = 0;
    // Heap-only reverse index hash -> uploader id (non-anonymous only),
    // rebuilt in `unshare`.
    var uploaderOfHash : Map.Map<Blob, Nat> = Map.empty<Blob, Nat>();

    // Reorg log.
    var reorgLog : List.List<ReorgEvent> = List.empty<ReorgEvent>();

    // Block-body index: txid -> height, in canonical chain order. The
    // enumeration index of each txid is its position in the chain-wide
    // transaction ordering (genesis coinbase = 0). Value is the 4-byte
    // little-endian height of the block the tx belongs to.
    var txTrie : StableTrie.Enumeration = StableTrie.empty({
      pointer_size = 6;
      aridity = 4;
      root_aridity = ?262144;
      key_size = 32;
      value_size = 4;
    });
    // Canonical bodies are known contiguously for heights [0, this); the
    // canonical txid trie holds exactly those, in chain order.
    var bodiesNextHeight : Nat = 0;
    // Heights whose stored txid count is less than their real tx_count
    // because a txid was a cross-block duplicate (the historical BIP30
    // coinbase reuse at heights 91842 / 91880). Keyed by height -> real
    // tx_count. Tiny (<=2 entries on mainnet).
    var txCountOverride : Map.Map<Nat, Nat> = Map.empty<Nat, Nat>();

    var initialized : Bool = false;

    // -----------------------------------------------------------------
    // Uploader bookkeeping.
    // -----------------------------------------------------------------

    // Register `p` and return its id, growing `uploaderBlocks` to match.
    func findOrAddUploader(p : Principal) : Nat {
      let id = Enum.BlobEnumeration.add(uploaderEnum, Principal.toBlob(p));
      while (List.size(uploaderBlocks) <= id) {
        List.add(uploaderBlocks, List.empty<Blob>());
      };
      id;
    };

    // Record that block `hash` was pushed by `uploader`. Called once,
    // at the block's first insertion (canonical or fork).
    func recordUploader(hash : Blob, uploader : Principal) {
      let id = findOrAddUploader(uploader);
      if (Principal.isAnonymous(uploader)) {
        anonymousCount += 1;
      } else {
        switch (List.get(uploaderBlocks, id)) {
          case (?lst) List.add(lst, hash);
          case null Runtime.trap("recordUploader: missing block list for id " # debug_show id);
        };
        Map.add<Blob, Nat>(uploaderOfHash, Blob.compare, hash, id);
      };
    };

    func rebuildUploaderOfHash() {
      uploaderOfHash := Map.empty<Blob, Nat>();
      let n = Enum.BlobEnumeration.size(uploaderEnum);
      var id = 0;
      while (id < n) {
        let p = Principal.fromBlob(Enum.BlobEnumeration.at(uploaderEnum, id));
        if (not Principal.isAnonymous(p)) {
          switch (List.get(uploaderBlocks, id)) {
            case (?lst) for (h in List.values(lst)) Map.add<Blob, Nat>(uploaderOfHash, Blob.compare, h, id);
            case null {};
          };
        };
        id += 1;
      };
    };

    // -----------------------------------------------------------------
    // Initialization / persistence.
    // -----------------------------------------------------------------

    public func initGenesis(firstSeenSecs : Nat32, uploader : Principal) {
      initRoot(Header.hexToBlob(Header.GENESIS_HEADER_HEX), firstSeenSecs, uploader);
    };

    // Seed the chain's index-0 root from an arbitrary 80-byte header.
    // Production uses this with the Bitcoin genesis (via initGenesis);
    // tests use it to anchor at a checkpoint block so a short fork can
    // be exercised without replaying the whole chain. The root is height
    // 0 with cumWork = its own block work; its real prev_hash is ignored
    // (height-0 blocks report a zero prev_hash).
    public func initRoot(raw : Blob, firstSeenSecs : Nat32, uploader : Principal) {
      if (initialized) return;
      let parsed = switch (Header.parseHeader(raw)) {
        case (?p) p;
        case null Runtime.trap("root header invalid");
      };
      let hash = Header.headerHashBlob(raw);
      let work = Header.chainWork(parsed.bits);
      let value = HeaderValue.encode({
        version = parsed.version;
        firstTxIndex = 0;
        merkle = parsed.merkle;
        time = parsed.time;
        bits = parsed.bits;
        nonce = parsed.nonce;
        height = 0;
        cumWork = work;
        firstSeen = firstSeenSecs;
      });
      let idx = headerDb.add(hash, value);
      assert idx == 0;
      recordUploader(hash, uploader);
      tipWork := work;
      initialized := true;
    };

    public func share() : StableData = {
      headerDb = headerDb.share();
      tipWork;
      forkByHash;
      forkByHeight;
      uploaderEnum;
      uploaderBlocks;
      anonymousCount;
      reorgLog;
      txTrie;
      bodiesNextHeight;
      txCountOverride;
    };

    public func unshare(d : StableData) {
      headerDb.unshare(d.headerDb);
      tipWork := d.tipWork;
      forkByHash := d.forkByHash;
      forkByHeight := d.forkByHeight;
      uploaderEnum := d.uploaderEnum;
      uploaderBlocks := d.uploaderBlocks;
      anonymousCount := d.anonymousCount;
      reorgLog := d.reorgLog;
      txTrie := d.txTrie;
      bodiesNextHeight := d.bodiesNextHeight;
      txCountOverride := d.txCountOverride;
      rebuildUploaderOfHash();
      initialized := true;
    };

    // -----------------------------------------------------------------
    // Internal: building StoredBlock views.
    // -----------------------------------------------------------------

    func canonPrevHash(idx : Nat) : Blob {
      if (idx == 0) return ZERO_HASH_BLOB;
      switch (headerDb.get(idx - 1)) {
        case (?(h, _)) h;
        case null Runtime.trap("canonPrevHash: missing index " # debug_show(idx - 1 : Nat));
      };
    };

    func storedCanonAt(idx : Nat) : StoredBlock {
      switch (headerDb.get(idx)) {
        case (?(hash, value)) {
          {
            hash;
            height = idx;
            cumWork = HeaderValue.cumWorkOf(value);
            value;
            prevHash = canonPrevHash(idx);
            isCanonical = true;
          };
        };
        case null Runtime.trap("storedCanonAt: missing index " # debug_show idx);
      };
    };

    func storedFork(fb : ForkBlock) : StoredBlock {
      let value = HeaderValue.encode({
        version = fb.version;
        firstTxIndex = 0;
        merkle = fb.merkle;
        time = fb.time;
        bits = fb.bits;
        nonce = fb.nonce;
        height = fb.height;
        cumWork = fb.cumWork;
        firstSeen = fb.firstSeen;
      });
      {
        hash = fb.hash;
        height = fb.height;
        cumWork = fb.cumWork;
        value;
        prevHash = fb.prevHash;
        isCanonical = false;
      };
    };

    // -----------------------------------------------------------------
    // Internal: fork-store maintenance.
    // -----------------------------------------------------------------

    func forkAt(height : Nat) : [Blob] {
      switch (Map.get<Nat, [Blob]>(forkByHeight, Nat.compare, height)) {
        case (?xs) xs;
        case null [];
      };
    };

    func addFork(fb : ForkBlock) {
      Map.add<Blob, ForkBlock>(forkByHash, Blob.compare, fb.hash, fb);
      let cur = forkAt(fb.height);
      let next = Array.tabulate<Blob>(
        cur.size() + 1,
        func(i) = if (i < cur.size()) cur[i] else fb.hash,
      );
      Map.add<Nat, [Blob]>(forkByHeight, Nat.compare, fb.height, next);
    };

    func removeFork(hash : Blob, height : Nat) {
      Map.remove<Blob, ForkBlock>(forkByHash, Blob.compare, hash);
      switch (Map.get<Nat, [Blob]>(forkByHeight, Nat.compare, height)) {
        case null {};
        case (?xs) {
          let kept = Array.filter<Blob>(xs, func(x) = x != hash);
          if (kept.size() == 0) {
            Map.remove<Nat, [Blob]>(forkByHeight, Nat.compare, height);
          } else {
            Map.add<Nat, [Blob]>(forkByHeight, Nat.compare, height, kept);
          };
        };
      };
    };

    // -----------------------------------------------------------------
    // Internal: ancestor walking (canonical or fork).
    // -----------------------------------------------------------------

    public func byHashInternal(hash : Blob) : ?StoredBlock {
      if (hash.size() != 32) return null;
      switch (Map.get<Blob, ForkBlock>(forkByHash, Blob.compare, hash)) {
        case (?fb) ?storedFork(fb);
        case null {
          switch (headerDb.lookup(hash)) {
            case (?(value, idx)) ?{
              hash;
              height = idx;
              cumWork = HeaderValue.cumWorkOf(value);
              value;
              prevHash = canonPrevHash(idx);
              isCanonical = true;
            };
            case null null;
          };
        };
      };
    };

    func parentOf(b : StoredBlock) : ?StoredBlock {
      if (b.height == 0) return null;
      if (b.isCanonical) return ?storedCanonAt(b.height - 1);
      byHashInternal(b.prevHash);
    };

    // Ancestor of `start` at `targetHeight` (<= start.height).
    func ancestorAt(start : StoredBlock, targetHeight : Nat) : ?StoredBlock {
      if (targetHeight > start.height) return null;
      var cur = start;
      loop {
        if (cur.height == targetHeight) return ?cur;
        if (cur.isCanonical) return ?storedCanonAt(targetHeight);
        switch (parentOf(cur)) {
          case (?p) cur := p;
          case null return null;
        };
      };
    };

    func lastNTimestamps(start : StoredBlock, n : Nat) : [Nat32] {
      let buf = List.empty<Nat32>();
      var cur : ?StoredBlock = ?start;
      var i = 0;
      label loop_ loop {
        if (i >= n) break loop_;
        switch (cur) {
          case null break loop_;
          case (?b) {
            List.add(buf, HeaderValue.timeOf(b.value));
            i += 1;
            cur := parentOf(b);
          };
        };
      };
      List.toArray(buf);
    };

    func expectedBitsFor(parent : StoredBlock, newHeight : Nat) : Nat32 {
      let parentBits = HeaderValue.bitsOf(parent.value);
      if (
        newHeight % Header.RETARGET_INTERVAL == 0 and newHeight >= Header.RETARGET_INTERVAL
      ) {
        let firstHeight = newHeight - Header.RETARGET_INTERVAL : Nat;
        switch (ancestorAt(parent, firstHeight)) {
          case (?first) {
            Header.computeRetargetNBits(
              HeaderValue.timeOf(parent.value),
              parentBits,
              HeaderValue.timeOf(first.value),
            );
          };
          case null parentBits;
        };
      } else {
        parentBits;
      };
    };

    // -----------------------------------------------------------------
    // Internal: reorg.
    // -----------------------------------------------------------------

    // Switch the canonical chain to the heavier branch ending at
    // `newTipHash` if it outweighs the current tip. Returns the number
    // of canonical blocks displaced (0 if no reorg happened).
    func maybeReorg(newTipHash : Blob, newWork : Nat, now : Int) : Nat {
      if (newWork <= tipWork) return 0;

      // 1. Walk the new branch from its tip down to the common ancestor
      //    (the first canonical block we hit). `branch` is tip-first.
      let branch = List.empty<ForkBlock>();
      var curHash = newTipHash;
      var commonHeight : Nat = 0;
      label findCommon loop {
        let fb = switch (Map.get<Blob, ForkBlock>(forkByHash, Blob.compare, curHash)) {
          case (?x) x;
          case null Runtime.trap("maybeReorg: branch block missing from fork store");
        };
        List.add(branch, fb);
        switch (headerDb.lookup(fb.prevHash)) {
          case (?(_, idx)) { commonHeight := idx; break findCommon };
          case null curHash := fb.prevHash;
        };
      };

      let oldTipHeight = tipHeight();
      let oldTipHash = switch (headerDb.get(oldTipHeight)) {
        case (?(h, _)) h;
        case null Runtime.trap("maybeReorg: missing old tip");
      };
      let displaced : Nat = oldTipHeight - commonHeight;

      // Bodies: before removing any header, extract each displaced canonical
      // block's transactions (with its F) from the txid trie so they travel
      // with the block into the fork store, then truncate the trie back to
      // the common ancestor. Reads canonical headers + trie, still present.
      let demotedBodies = Map.empty<Nat, ForkBody>();
      if (bodiesNextHeight > commonHeight + 1) {
        let truncPoint = switch (headerDb.get(commonHeight + 1)) {
          case (?(_, v)) HeaderValue.firstTxIndexOf(v);
          case null Runtime.trap("maybeReorg: missing first displaced block");
        };
        var h = commonHeight + 1;
        while (h < bodiesNextHeight) {
          let value = switch (headerDb.get(h)) {
            case (?(_, v)) v;
            case null Runtime.trap("maybeReorg: missing displaced body block");
          };
          let lo = HeaderValue.firstTxIndexOf(value);
          let hi = if (h + 1 < bodiesNextHeight) {
            switch (headerDb.get(h + 1)) {
              case (?(_, v)) HeaderValue.firstTxIndexOf(v);
              case null Runtime.trap("maybeReorg: missing displaced body block");
            };
          } else StableTrie.size(txTrie);
          Map.add<Nat, ForkBody>(demotedBodies, Nat.compare, h, { txids = extractTxids(lo, hi); firstTxIndex = lo });
          Map.remove<Nat, Nat>(txCountOverride, Nat.compare, h);
          h += 1;
        };
        StableTrie.truncate(txTrie, truncPoint);
        bodiesNextHeight := commonHeight + 1;
      };

      // 2. Roll back the canonical tip into the fork store, one block at
      //    a time, until the common ancestor is the last entry.
      while (tipHeight() > commonHeight) {
        let h = tipHeight();
        let (rmHash, rmValue) = switch (headerDb.removeLast()) {
          case (?x) x;
          case null Runtime.trap("maybeReorg: removeLast on empty trie");
        };
        let prevH = switch (headerDb.get(h - 1)) {
          case (?(ph, _)) ph;
          case null Runtime.trap("maybeReorg: missing parent of displaced block");
        };
        addFork({
          hash = rmHash;
          prevHash = prevH;
          version = HeaderValue.versionOf(rmValue);
          merkle = HeaderValue.merkleOf(rmValue);
          time = HeaderValue.timeOf(rmValue);
          bits = HeaderValue.bitsOf(rmValue);
          nonce = HeaderValue.nonceOf(rmValue);
          height = h;
          cumWork = HeaderValue.cumWorkOf(rmValue);
          firstSeen = HeaderValue.firstSeenOf(rmValue);
          body = Map.get<Nat, ForkBody>(demotedBodies, Nat.compare, h);
        });
      };

      // 3. Append the new branch (ancestor-first) into the canonical trie.
      var k = List.size(branch);
      while (k > 0) {
        k -= 1;
        let fb = switch (List.get(branch, k)) {
          case (?x) x;
          case null Runtime.trap("maybeReorg: branch index out of range");
        };
        removeFork(fb.hash, fb.height);
        let value = HeaderValue.encode({
          version = fb.version;
          firstTxIndex = 0;
          merkle = fb.merkle;
          time = fb.time;
          bits = fb.bits;
          nonce = fb.nonce;
          height = fb.height;
          cumWork = fb.cumWork;
          firstSeen = fb.firstSeen;
        });
        ignore headerDb.add(fb.hash, value);
        // If the promoted block's body is known, re-index it in chain order.
        // The all-ancestors-known invariant keeps fork bodies contiguous from
        // the common ancestor, so this advances the frontier without gaps.
        switch (fb.body) {
          case (?b) if (fb.height == bodiesNextHeight) {
            appendCanonicalBody(fb.height, value, b.txids);
            bodiesNextHeight += 1;
          };
          case null {};
        };
      };

      tipWork := newWork;

      List.add(reorgLog, {
        time = now;
        common_height = commonHeight;
        fork_length = List.size(branch);
        displaced;
        old_tip_hash_be_hex = bytesToHexBE(oldTipHash);
        old_tip_height = oldTipHeight;
        new_tip_hash_be_hex = bytesToHexBE(newTipHash);
        new_tip_height = tipHeight();
      });

      displaced;
    };

    func storeAndMaybeReorg(
      raw : Blob,
      bits : Nat32,
      hash : Blob,
      parent : StoredBlock,
      firstSeenSecs : Nat32,
      uploader : Principal,
      now : Int,
    ) : PushOk {
      let newHeight = parent.height + 1;
      let cumWork = parent.cumWork + Header.chainWork(bits);
      let parsed = switch (Header.parseHeader(raw)) {
        case (?p) p;
        case null Runtime.trap("storeAndMaybeReorg: unparseable header");
      };

      recordUploader(hash, uploader);

      var isCanonical = false;
      var reorgDepth : Nat = 0;

      if (parent.isCanonical and parent.height == tipHeight()) {
        let value = HeaderValue.encode({
          version = parsed.version;
          firstTxIndex = 0;
          merkle = parsed.merkle;
          time = parsed.time;
          bits = parsed.bits;
          nonce = parsed.nonce;
          height = newHeight;
          cumWork;
          firstSeen = firstSeenSecs;
        });
        ignore headerDb.add(hash, value);
        tipWork := cumWork;
        isCanonical := true;
      } else {
        addFork({
          hash;
          prevHash = parsed.prev_hash;
          version = parsed.version;
          merkle = parsed.merkle;
          time = parsed.time;
          bits = parsed.bits;
          nonce = parsed.nonce;
          height = newHeight;
          cumWork;
          firstSeen = firstSeenSecs;
          body = null;
        });
        reorgDepth := maybeReorg(hash, cumWork, now);
        if (reorgDepth > 0) isCanonical := true;
      };

      {
        height = newHeight;
        hash_be_hex = bytesToHexBE(hash);
        is_canonical = isCanonical;
        reorg_depth = reorgDepth;
      };
    };

    // -----------------------------------------------------------------
    // Public mutating API.
    // -----------------------------------------------------------------

    public func push(raw : Blob, nowSecs : Int, uploader : Principal) : Result.Result<PushOk, Text> {
      if (raw.size() != 80) return #err("header is not 80 bytes");
      let parsed = switch (Header.parseHeader(raw)) {
        case (?p) p;
        case null return #err("could not parse header");
      };
      let hash = Header.headerHashBlob(raw);
      switch (byHashInternal(hash)) {
        case (?_) return #err("duplicate: hash already present");
        case null {};
      };
      let parent = switch (byHashInternal(parsed.prev_hash)) {
        case (?p) p;
        case null return #err("unknown previous block hash");
      };
      // Reject headers whose timestamp is more than ONE_YEAR_SECS before
      // the current canonical tip's timestamp.
      let tipTimeNat = Nat32.toNat(HeaderValue.timeOf(tipBlock().value));
      let parsedTimeNat = Nat32.toNat(parsed.time);
      if (parsedTimeNat + ONE_YEAR_SECS < tipTimeNat) {
        return #err(
          "header timestamp " # debug_show parsedTimeNat #
          " is more than 1 year before current tip timestamp " #
          debug_show tipTimeNat
        );
      };
      let newHeight = parent.height + 1;
      let expectedBits = expectedBitsFor(parent, newHeight);
      let stamps = lastNTimestamps(parent, if (newHeight < 11) newHeight else 11);
      let mtp = Header.medianTimePast(stamps);

      switch (
        Header.validateAgainst(raw, expectedBits, parsed.prev_hash, mtp, nowSecs)
      ) {
        case (#err msg) return #err(msg);
        case (#ok()) {};
      };
      let firstSeen = nat32OfNowSecs(nowSecs);
      #ok(storeAndMaybeReorg(raw, parsed.bits, hash, parent, firstSeen, uploader, nowSecs));
    };

    public func pushUnchecked(raw : Blob, nowSecs : Int, uploader : Principal) : Result.Result<PushOk, Text> {
      if (raw.size() != 80) return #err("header is not 80 bytes");
      let parsed = switch (Header.parseHeader(raw)) {
        case (?p) p;
        case null return #err("could not parse header");
      };
      let hash = Header.headerHashBlob(raw);
      switch (byHashInternal(hash)) {
        case (?_) return #err("duplicate: hash already present");
        case null {};
      };
      let parent = switch (byHashInternal(parsed.prev_hash)) {
        case (?p) p;
        case null return #err("unknown previous block hash");
      };
      #ok(storeAndMaybeReorg(raw, parsed.bits, hash, parent, nat32OfNowSecs(nowSecs), uploader, nowSecs));
    };

    // -----------------------------------------------------------------
    // Public queries.
    // -----------------------------------------------------------------

    // Total headers ever stored (canonical + fork).
    public func size() : Nat = headerDb.size() + Map.size(forkByHash);

    public func memoryStats() : HeaderDb.MemoryStats = headerDb.memoryStats();

    public func tipHeight() : Nat = headerDb.size() - 1 : Nat;

    public func tipBlock() : StoredBlock = storedCanonAt(tipHeight());

    public func canonicalAt(height : Nat) : ?StoredBlock {
      if (height > tipHeight()) null else ?storedCanonAt(height);
    };

    public func allAt(height : Nat) : [StoredBlock] {
      let out = List.empty<StoredBlock>();
      if (height <= tipHeight()) {
        List.add(out, storedCanonAt(height));
      };
      for (h in forkAt(height).vals()) {
        switch (Map.get<Blob, ForkBlock>(forkByHash, Blob.compare, h)) {
          case (?fb) List.add(out, storedFork(fb));
          case null {};
        };
      };
      List.toArray(out);
    };

    public func byHashBE(hex : Text) : ?StoredBlock {
      let bytes = Header.hexToBlob(hex);
      if (bytes.size() != 32) return null;
      byHashInternal(Header.reverse32(bytes));
    };

    // Cheap membership check.
    public func hasHashBE(hex : Text) : Bool {
      let bytes = Header.hexToBlob(hex);
      if (bytes.size() != 32) return false;
      let internal = Header.reverse32(bytes);
      if (Map.containsKey<Blob, ForkBlock>(forkByHash, Blob.compare, internal)) return true;
      switch (headerDb.lookup(internal)) {
        case (?_) true;
        case null false;
      };
    };

    public func isOnCanonical(b : StoredBlock) : Bool = b.isCanonical;

    public func canonicalChildOf(b : StoredBlock) : ?StoredBlock {
      canonicalAt(b.height + 1);
    };

    public func prevHashOf(b : StoredBlock) : Blob = b.prevHash;

    // Bitcoin-Core "median time past": median of `b` and its 10 ancestors.
    public func mediantimeOf(b : StoredBlock) : Nat32 {
      let stamps = lastNTimestamps(b, 11);
      let sorted = Array.sort<Nat32>(stamps, Nat32.compare);
      sorted[sorted.size() / 2];
    };

    // Reconstruct the canonical 80-byte raw header from stored data.
    public func rawHeaderOf(b : StoredBlock) : Blob {
      let v = b.value;
      let version = HeaderValue.versionOf(v);
      let time = HeaderValue.timeOf(v);
      let bits = HeaderValue.bitsOf(v);
      let nonce = HeaderValue.nonceOf(v);
      let prevA = Blob.toArray(b.prevHash);
      let merkleA = Blob.toArray(HeaderValue.merkleOf(v));
      let buf = Array.tabulate<Nat8>(
        80,
        func(i) {
          if (i < 4) le32Byte(version, i) else if (i < 36) prevA[i - 4 : Nat] else if (i < 68) merkleA[i - 36 : Nat] else if (i < 72) le32Byte(time, i - 68 : Nat) else if (i < 76) le32Byte(bits, i - 72 : Nat) else le32Byte(nonce, i - 76 : Nat);
        },
      );
      Blob.fromArray(buf);
    };

    // All current forks (non-canonical branches), one entry per tip.
    public func forks() : [Fork] {
      // A fork block is a tip iff no other fork block names it as parent.
      let referenced = Set.empty<Blob>();
      for ((_, fb) in Map.entries(forkByHash)) {
        if (Map.containsKey<Blob, ForkBlock>(forkByHash, Blob.compare, fb.prevHash)) {
          Set.add<Blob>(referenced, Blob.compare, fb.prevHash);
        };
      };
      let out = List.empty<Fork>();
      for ((hash, fb) in Map.entries(forkByHash)) {
        if (not Set.contains<Blob>(referenced, Blob.compare, hash)) {
          // Walk down from the tip to the canonical branch point.
          var cur = storedFork(fb);
          var length : Nat = 0;
          var branch : StoredBlock = cur;
          label walk loop {
            length += 1;
            switch (parentOf(cur)) {
              case (?p) {
                if (p.isCanonical) { branch := p; break walk };
                cur := p;
              };
              case null Runtime.trap("forks: walked past genesis");
            };
          };
          List.add(out, {
            tip_height = fb.height;
            tip_hash_be_hex = bytesToHexBE(fb.hash);
            length;
            branch_height = branch.height;
            branch_hash_be_hex = bytesToHexBE(branch.hash);
          });
        };
      };
      List.toArray(out);
    };

    public func reorgs() : [ReorgEvent] = List.toArray(reorgLog);

    // -----------------------------------------------------------------
    // Uploader queries.
    // -----------------------------------------------------------------

    // Resolve the uploader principal for a block hash. Blocks that were
    // not individually attributed (anonymous) default to the anonymous
    // principal.
    public func uploaderOf(hash : Blob) : Principal {
      switch (Map.get<Blob, Nat>(uploaderOfHash, Blob.compare, hash)) {
        case (?id) Principal.fromBlob(Enum.BlobEnumeration.at(uploaderEnum, id));
        case null anonymousPrincipal();
      };
    };

    // (uploader, headers-pushed) for every distinct uploader, in
    // registration order. Caller sorts / truncates for a leaderboard.
    public func uploaderStats() : [(Principal, Nat)] {
      let n = Enum.BlobEnumeration.size(uploaderEnum);
      Array.tabulate<(Principal, Nat)>(
        n,
        func(i) {
          let p = Principal.fromBlob(Enum.BlobEnumeration.at(uploaderEnum, i));
          let count = if (Principal.isAnonymous(p)) {
            anonymousCount;
          } else {
            switch (List.get(uploaderBlocks, i)) {
              case (?lst) List.size(lst);
              case null 0;
            };
          };
          (p, count);
        },
      );
    };

    // Page through the block hashes uploaded by `p`, newest first.
    // Anonymous returns []: we don't track its blocks individually.
    public func blocksByUploader(p : Principal, offset : Nat, limit : Nat) : [Blob] {
      if (Principal.isAnonymous(p) or limit == 0) return [];
      let id = switch (Enum.BlobEnumeration.lookup(uploaderEnum, Principal.toBlob(p))) {
        case (?i) i;
        case null return [];
      };
      let lst = switch (List.get(uploaderBlocks, id)) {
        case (?l) l;
        case null return [];
      };
      let n = List.size(lst);
      if (offset >= n) return [];
      let remaining : Nat = n - offset;
      let take = if (limit < remaining) limit else remaining;
      Array.tabulate<Blob>(
        take,
        func(k) {
          let pos : Nat = n - 1 - offset - k;
          switch (List.get(lst, pos)) {
            case (?h) h;
            case null Runtime.trap("blocksByUploader: index out of range");
          };
        },
      );
    };

    // -----------------------------------------------------------------
    // Block bodies.
    //
    // A block's body (transaction-id list) may be uploaded only once the
    // bodies of ALL its ancestors are known — i.e. its first-tx serial
    // number F is determined:
    //   * canonical block: its height must equal the body frontier
    //     (bodiesNextHeight), so canonical bodies are filled in strict
    //     chain order and go straight into the stable txid trie;
    //   * fork block: its parent's body must be known (a canonical block
    //     under the frontier, or a fork block that already has a body); the
    //     body is stored in the ForkBlock record.
    // A fork body whose ancestor bodies aren't all known is rejected (for
    // symmetry with the canonical rule). This guarantees that when a fork
    // is reorged in, its transactions are contiguous and can be appended to
    // the canonical trie immediately.
    // -----------------------------------------------------------------

    // Canonical bodies are known contiguously for heights [0, this).
    public func bodiesHeight() : Nat = bodiesNextHeight;

    // Transactions currently in the canonical txid trie.
    public func totalIndexedTxids() : Nat = StableTrie.size(txTrie);

    // Number of fork blocks that currently carry a body.
    public func forkBodyCount() : Nat {
      var n = 0;
      for ((_, fb) in Map.entries(forkByHash)) {
        switch (fb.body) { case (?_) n += 1; case null {} };
      };
      n;
    };

    // Re-encode a header value with a new firstTxIndex (F); other fields kept.
    func withFirstTxIndex(value : Blob, f : Nat) : Blob {
      HeaderValue.encode({
        version = HeaderValue.versionOf(value);
        firstTxIndex = f;
        merkle = HeaderValue.merkleOf(value);
        time = HeaderValue.timeOf(value);
        bits = HeaderValue.bitsOf(value);
        nonce = HeaderValue.nonceOf(value);
        height = HeaderValue.heightOf(value);
        cumWork = HeaderValue.cumWorkOf(value);
        firstSeen = HeaderValue.firstSeenOf(value);
      });
    };

    // Read txids stored in the canonical trie at indices [lo, hi) into a
    // flat blob (moves a demoted block's body into the fork store).
    func extractTxids(lo : Nat, hi : Nat) : Blob {
      let keys = Array.tabulate<[Nat8]>(
        hi - lo : Nat,
        func(k) = Blob.toArray(
          switch (StableTrie.get(txTrie, lo + k)) {
            case (?(key, _)) key;
            case null Runtime.trap("extractTxids: missing txid " # debug_show(lo + k));
          }
        ),
      );
      Blob.fromArray(Array.tabulate<Nat8>((hi - lo : Nat) * 32, func(j) = keys[j / 32][j % 32]));
    };

    // Append one block's body (flat txid blob) to the tail of the canonical
    // txid trie, setting its F, recording a BIP30 override if a txid was a
    // cross-block duplicate (so tx_count stays correct).
    func appendCanonicalBody(height : Nat, value : Blob, body : Blob) {
      let f = StableTrie.size(txTrie);
      headerDb.put(height, withFirstTxIndex(value, f));
      let n = body.size() / 32;
      let hv = encodeHeight(height);
      var i = 0;
      while (i < n) { ignore StableTrie.add(txTrie, txidAt(body, i), hv); i += 1 };
      if (StableTrie.size(txTrie) - f < n) Map.add<Nat, Nat>(txCountOverride, Nat.compare, height, n);
    };

    // Body stored in a fork block's record, if any.
    func forkBodyOf(hash : Blob) : ?ForkBody {
      switch (Map.get<Blob, ForkBlock>(forkByHash, Blob.compare, hash)) {
        case (?fb) fb.body;
        case null null;
      };
    };

    // Is this block's body already known?
    func bodyKnown(b : StoredBlock) : Bool {
      (b.isCanonical and b.height < bodiesNextHeight) or (switch (forkBodyOf(b.hash)) { case (?_) true; case null false });
    };

    // F of the block immediately after `parent` (= F(parent) + N(parent)),
    // if `parent`'s body is known; else null. Used to determine a fork
    // block's first-tx serial number at upload time.
    func firstTxAfter(parent : StoredBlock) : ?Nat {
      if (parent.isCanonical) {
        if (parent.height < bodiesNextHeight) {
          ?(HeaderValue.firstTxIndexOf(parent.value) + trieTxCount(parent.height));
        } else null;
      } else switch (forkBodyOf(parent.hash)) {
        case (?body) ?(body.firstTxIndex + body.txids.size() / 32);
        case null null;
      };
    };

    // tx_count of a canonical block currently indexed in the trie.
    func trieTxCount(height : Nat) : Nat {
      switch (Map.get<Nat, Nat>(txCountOverride, Nat.compare, height)) {
        case (?n) return n;
        case null {};
      };
      let f = switch (headerDb.get(height)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return 0 };
      let next = if (height + 1 < bodiesNextHeight) {
        switch (headerDb.get(height + 1)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return 0 };
      } else StableTrie.size(txTrie);
      next - f : Nat;
    };

    func bodyResult(b : StoredBlock, duplicate : Bool) : PushBodyOk {
      if (b.isCanonical and b.height < bodiesNextHeight) {
        let f = switch (headerDb.get(b.height)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null 0 };
        return { height = b.height; tx_count = trieTxCount(b.height); first_tx_index = f; canonical_indexed = true; duplicate };
      };
      switch (forkBodyOf(b.hash)) {
        case (?body) ({ height = b.height; tx_count = body.txids.size() / 32; first_tx_index = body.firstTxIndex; canonical_indexed = false; duplicate });
        case null ({ height = b.height; tx_count = 0; first_tx_index = 0; canonical_indexed = false; duplicate });
      };
    };

    // Index a block's body — allowed only when all ancestor bodies are known
    // (so F is determined). Canonical bodies go to the txid trie in chain
    // order; fork bodies into the ForkBlock record. Re-upload is a no-op.
    public func pushBody(blockHashInternal : Blob, txCount : Nat, hashes : Blob) : Result.Result<PushBodyOk, Text> {
      if (blockHashInternal.size() != 32) return #err("block hash must be 32 bytes");
      if (txCount == 0) return #err("tx_count must be >= 1");
      if (hashes.size() != txCount * 32) {
        return #err("hashes length " # debug_show hashes.size() # " != tx_count*32");
      };
      let b = switch (byHashInternal(blockHashInternal)) {
        case (?b) b;
        case null return #err("unknown block header hash");
      };
      if (bodyKnown(b)) return #ok(bodyResult(b, true));
      if (Merkle.root(hashes, txCount) != HeaderValue.merkleOf(b.value)) return #err("merkle root mismatch");

      if (b.isCanonical) {
        if (b.height != bodiesNextHeight) {
          return #err(
            "ancestor bodies unknown: expected canonical body for height " #
            debug_show bodiesNextHeight # ", got " # debug_show b.height
          );
        };
        appendCanonicalBody(b.height, b.value, hashes);
        bodiesNextHeight += 1;
        #ok(bodyResult(b, false));
      } else {
        let parent = switch (parentOf(b)) {
          case (?p) p;
          case null return #err("fork block has no parent");
        };
        let f = switch (firstTxAfter(parent)) {
          case (?f) f;
          case null return #err("ancestor bodies unknown for this fork block");
        };
        let fb = switch (Map.get<Blob, ForkBlock>(forkByHash, Blob.compare, b.hash)) {
          case (?x) x;
          case null return #err("fork block missing from store");
        };
        Map.add<Blob, ForkBlock>(forkByHash, Blob.compare, b.hash, { fb with body = ?{ txids = hashes; firstTxIndex = f } });
        #ok(bodyResult(b, false));
      };
    };

    // tx_count of any block by internal hash (canonical-indexed or
    // fork-stored), or null if its body is not known.
    public func txCountOfHash(hash : Blob) : ?Nat {
      switch (byHashInternal(hash)) {
        case null null;
        case (?b) {
          if (b.isCanonical and b.height < bodiesNextHeight) ?trieTxCount(b.height) else switch (forkBodyOf(b.hash)) {
            case (?body) ?(body.txids.size() / 32);
            case null null;
          };
        };
      };
    };

    // tx_count of the canonical block at `height`, or null if not yet indexed.
    public func txCountAt(height : Nat) : ?Nat {
      if (height < bodiesNextHeight) ?trieTxCount(height) else null;
    };

    public func bodyAt(height : Nat) : ?BodyInfo {
      if (height >= bodiesNextHeight) return null;
      let f = switch (headerDb.get(height)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return null };
      ?{ height; tx_count = trieTxCount(height); first_tx_index = f; canonical_indexed = true };
    };

    // Does the flat txid blob `body` contain `txid`?
    func bodyContains(body : Blob, txid : Blob) : Bool {
      let n = body.size() / 32;
      var i = 0;
      while (i < n) { if (txidAt(body, i) == txid) return true; i += 1 };
      false;
    };

    // Every known block containing `txid` (internal LE): the canonical
    // height (from the canonical txid trie) plus all fork blocks whose stored
    // body holds it. Fork lookup scans the fork store (small: real forks only).
    public func lookupTxid(txid : Blob) : { canonical : ?Nat; forks : [Blob] } {
      if (txid.size() != 32) return { canonical = null; forks = [] };
      let canonical = switch (StableTrie.lookup(txTrie, txid)) {
        case (?(v, _)) ?decodeHeight(v);
        case null null;
      };
      let forks = List.empty<Blob>();
      for ((hash, fb) in Map.entries(forkByHash)) {
        switch (fb.body) {
          case (?body) if (bodyContains(body.txids, txid)) List.add(forks, hash);
          case null {};
        };
      };
      { canonical; forks = List.toArray(forks) };
    };

    // -----------------------------------------------------------------
    // Metrics (promtracker pull Values).
    // -----------------------------------------------------------------

    // memoryStats of the canonical header trie (stable_trie_* families).
    public func headerTrieValue() : MetricValue = headerDb.toValue();

    // memoryStats of the canonical transaction (txid) trie.
    public func txTrieValue() : MetricValue = StableTrie.toValue(txTrie);

    // Heap fork-store + reorg-history metrics, computed once per scrape.
    public func heapStatsValue() : MetricValue = {
      read = func() : [(Text, Text, Nat)] {
        let fs = forks();
        var longest : Nat = 0;
        var highestTip : Nat = 0;
        var highestTipCommon : Nat = 0;
        for (f in fs.vals()) {
          if (f.length > longest) longest := f.length;
          if (f.tip_height > highestTip) {
            highestTip := f.tip_height;
            highestTipCommon := f.branch_height;
          };
        };
        var reorgLastCommon : Nat = 0;
        var reorgMaxDisplaced : Nat = 0;
        // Iteration is in insertion order, so the final assignment to
        // reorgLastCommon is the most recent reorg's common height.
        for (e in List.values(reorgLog)) {
          reorgLastCommon := e.common_height;
          if (e.displaced > reorgMaxDisplaced) reorgMaxDisplaced := e.displaced;
        };
        let nr = List.size(reorgLog);
        [
          ("chain_fork_tips", "", fs.size()),
          ("chain_fork_blocks", "", Map.size(forkByHash)),
          ("chain_fork_bodies", "", forkBodyCount()),
          ("chain_fork_longest", "", longest),
          ("chain_fork_highest_tip_height", "", highestTip),
          ("chain_fork_highest_tip_common_height", "", highestTipCommon),
          ("chain_reorg_count", "", nr),
          ("chain_reorg_last_common_height", "", reorgLastCommon),
          ("chain_reorg_max_displaced", "", reorgMaxDisplaced),
        ];
      };
    };
  };

  // ---------------------------------------------------------------------
  // Convenience: fresh chain seeded with genesis.
  // ---------------------------------------------------------------------

  public func empty() : Chain {
    let c = Chain(HeaderDb.KEY_SIZE);
    c.initGenesis(0, Principal.fromText("aaaaa-aa"));
    c;
  };

  // Test-only: a chain whose canonical trie uses full 32-byte keys, so
  // synthetic (non-PoW) headers can be stored without tripping the
  // trailing-zero truncation invariant.
  public func emptyForTest() : Chain {
    let c = Chain(HeaderDb.HASH_SIZE);
    c.initGenesis(0, Principal.fromText("aaaaa-aa"));
    c;
  };

  // Test helper: a chain anchored at an arbitrary checkpoint header
  // (hex). `keySize` selects the trie key width — pass HeaderDb.KEY_SIZE
  // (28) to exercise the production truncation path with real PoW headers.
  public func fromRootHex(rawHex : Text, keySize : Nat) : Chain {
    let c = Chain(keySize);
    c.initRoot(Header.hexToBlob(rawHex), 0, Principal.fromText("aaaaa-aa"));
    c;
  };

};
