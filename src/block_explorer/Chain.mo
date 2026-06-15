// Bitcoin block-header chain with full reorg support.
//
// This is a plain MODULE (no class, no share/unshare): all state lives in a
// `State` record and every operation is a function taking that record, so
// callers use dot-notation (`chain.push(raw, now, who)` == `Chain.push(chain,
// raw, now, who)`). The actor declares the two tries as top-level `let`s and
// bundles them with the heap structures into one top-level `let chain :
// Chain.State`. Because top-level `let` initializers run only on fresh
// install, an upgrade restores the persisted state directly — no constructor
// re-runs, nothing is re-allocated, and no pre/postupgrade hooks are needed.
//
// Storage model
// -------------
//   Canonical chain (stable):  `headerTrie`, a mo:stable-trie Enumeration
//     holding ONLY the canonical chain in height order (index == height).
//     See Headers.mo. Values are compressed: no prev_hash is stored, since
//     the parent of index i is index i-1.
//   Fork store (stable):       all NON-canonical blocks, in full — `forks`
//     (see ForkStore.mo).
//   Uploader registry (stable): principal <-> id + per-id block lists —
//     `uploaders` (see Uploaders.mo).
//   Txid index (stable):       `txTrie`, txid -> height, in canonical tx order.
//   Reorg log (stable):        one record per reorg event.
//
// Hash convention: internally everything is Bitcoin "internal" little-endian
// (natural sha-256d output order). Big-endian (display) hex appears only at
// API boundaries.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Int "mo:core/Int";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Set "mo:core/Set";

import Sha256 "mo:sha2/Sha256";
import StableTrie "mo:stable-trie/Enumeration";

import ForkStore "mo:heaviest-chain/ForkStore";
import Reorg "mo:heaviest-chain/Reorg";

import Bytes "mo:btc/Bytes";
import Header "mo:btc/Header";
import HeaderValue "HeaderValue";
import Merkle "mo:btc/Merkle";
import Headers "Headers";
import Uploaders "Uploaders";

module {

  // ---------------------------------------------------------------------
  // Public types.
  // ---------------------------------------------------------------------

  // The body of a fork block: its transaction ids (flat 32-byte blob, in
  // block order) plus its first-tx serial number F in the would-be canonical
  // ordering. Present only once all ancestors' bodies are known (see pushBody).
  public type ForkBody = {
    txids : Blob;
    firstTxIndex : Nat;
  };

  // A non-canonical block, stored in full in the generic fork store.
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

  // Raw bytes only — rendering the hash as display hex costs ~5 KB per call
  // (128 Text-concat allocations), and batch callers discard the result
  // anyway. The candid boundary (main.mo) hexifies for the one endpoint
  // that returns it.
  public type PushOk = {
    height : Nat;
    hash : Blob; // internal LE order, 32 bytes
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

  // One reorg event, appended whenever the canonical chain switches branch.
  public type ReorgEvent = {
    time : Int; // seconds (as firstSeen)
    common_height : Nat;
    fork_length : Nat;
    displaced : Nat;
    old_tip_hash_be_hex : Text;
    old_tip_height : Nat;
    new_tip_hash_be_hex : Text;
    new_tip_height : Nat;
  };

  // A promtracker pull `Value`: one `read()` returns several samples.
  public type MetricValue = { read : () -> [(Text, Text, Nat)] };

  // Body summary for a canonical block whose transactions are indexed.
  public type BodyInfo = {
    height : Nat;
    tx_count : Nat;
    first_tx_index : Nat; // F (only meaningful when canonical_indexed)
    canonical_indexed : Bool;
  };

  // A transaction's canonical location.
  public type TxCanonLoc = { height : Nat; position : Nat; index : Nat };
  // A transaction's location in a fork block.
  public type TxForkLoc = { hash : Blob; height : Nat; position : Nat };

  public type PushBodyOk = {
    height : Nat;
    tx_count : Nat;
    first_tx_index : Nat;
    canonical_indexed : Bool;
    duplicate : Bool;
  };

  // The whole chain state. Declared top-level in the actor (the two tries as
  // their own `let`s, then bundled here). `var` fields are the only mutable
  // scalars; every other field is mutated in place through its own module.
  public type State = {
    headerTrie : StableTrie.Enumeration; // canonical chain, index == height
    txTrie : StableTrie.Enumeration; // txid -> height, canonical tx order
    forks : ForkStore.ForkStore<ForkBlock>;
    uploaders : Uploaders.Uploaders;
    reorgLog : List.List<ReorgEvent>;
    var tipWork : Nat; // cumulative work of the canonical tip
    var bodiesNextHeight : Nat; // canonical bodies known for [0, this)
    // Timestamps of the canonical tip and its ancestors, newest first, at
    // most MTP_WINDOW (11) entries — the median-time-past context. Kept in
    // sync on every canonical append / reorg so the per-push MTP check never
    // reads the header trie.
    var recentTimes : [Nat32];
    // Single-entry memo of the nBits -> (target, per-block work) conversion.
    // bits is constant within a 2016-block difficulty period, so this hits
    // on every push except the first of each period, avoiding a 2^256
    // bignum division (chainWork) and an nBitsToTarget per header. The
    // initial { bits = 0; ... } sentinel is itself semantically correct
    // (nBitsToTarget(0) == 0, chainWork(0) == 0).
    var workMemo : WorkMemo;
    var initialized : Bool;
  };

  public type WorkMemo = {
    bits : Nat32;
    target : Nat; // nBitsToTarget(bits)
    work : Nat; // chainWork(bits) = 2^256 / (target + 1)
  };

  // ---------------------------------------------------------------------
  // Construction.
  // ---------------------------------------------------------------------

  // BIP30 duplicate-coinbase handling. Two early blocks repeated an
  // existing coinbase txid (91722's was repeated by 91880; 91812's by
  // 91842). A keyed txid trie cannot hold the same txid twice, so the
  // SINGLE-TX block of each pair is stored "compressed": verified normally,
  // then recorded with an empty txid segment (length 0 by F-arithmetic).
  // Since every real block has >= 1 transaction (the coinbase), a
  // zero-length segment unambiguously means "compressed single-tx block",
  // and its only txid is recovered from the header's merkle root (txid ==
  // merkle root for single-tx blocks). This makes txid attribution match
  // Esplora on both pairs (91812 and 91880 win) and keeps F exact
  // everywhere. The heights are consensus history; BIP30 + BIP34 guarantee
  // no further duplicates can occur.
  func isCompressedBodyHeight(height : Nat) : Bool = height == 91_722 or height == 91_842;

  // Production root_aridity for the txid trie (= 4^14). Allocates a ~1 GB
  // flat root region at trie creation (fine on the IC; tests pass a small
  // value to avoid the upfront allocation).
  public let TX_ROOT_ARIDITY : Nat = 268_435_456;

  // Header trie: 28-byte (or 32 for tests) keys -> 80-byte HeaderValue blobs
  // (raw-header-mirroring layout, see HeaderValue.mo); root_aridity 4^9
  // (root region 262144 x 3 = 768 KB). pointer_size 3 caps the trie at
  // 2^23 ≈ 8.4 M headers — ~140 years of blocks at 144/day.
  public func newHeaderTrie(keySize : Nat) : StableTrie.Enumeration = StableTrie.empty({
    pointer_size = 3;
    aridity = 4;
    root_aridity = ?262144; // = 4^9
    value_size = HeaderValue.SIZE;
    key_size = keySize;
  });

  // Txid trie: 32-byte txids -> 3-byte LE height. See sizing notes on
  // TX_ROOT_ARIDITY (pointer_size 4 caps ~2.1 B txids; value_size 3 = 2^24
  // heights; root_aridity 4^14 ≈ 1 GB flat root, ~1-2 lookup hops at 2 B keys).
  public func newTxTrie(rootAridity : Nat) : StableTrie.Enumeration = StableTrie.empty({
    pointer_size = 4;
    aridity = 4;
    root_aridity = ?rootAridity;
    key_size = 32;
    value_size = 3;
  });

  // Bundle pre-built tries (declared top-level in the actor) with fresh heap
  // structures into a State. Does NOT seed genesis — call initGenesis/initRoot.
  public func newState(headerTrie : StableTrie.Enumeration, txTrie : StableTrie.Enumeration) : State = {
    headerTrie;
    txTrie;
    forks = ForkStore.empty<ForkBlock>();
    uploaders = Uploaders.empty();
    reorgLog = List.empty<ReorgEvent>();
    var tipWork = 0;
    var bodiesNextHeight = 0;
    var recentTimes = [];
    var workMemo = { bits = 0 : Nat32; target = 0; work = 0 };
    var initialized = false;
  };

  // ---------------------------------------------------------------------
  // Module-local helpers.
  // ---------------------------------------------------------------------

  func bytesToHexBE(b : Blob) : Text = Header.bytesToHex(Header.reverse32(b));

  let ZERO_HASH_BLOB : Blob = "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00";

  func nat32OfNowSecs(s : Int) : Nat32 {
    if (s <= 0) 0 else Nat32.fromNat(Int.abs(s) % 0x1_0000_0000);
  };

  // One year in seconds (365 days). Freshness check on pushed headers.
  let ONE_YEAR_SECS : Nat = 31_536_000;

  // Byte at little-endian position `i` (0..3) of a Nat32. Narrow the masked
  // byte Nat32 -> Nat16 -> Nat8 via `let` Prim aliases (no Nat detour).
  func le32Byte(v : Nat32, i : Nat) : Nat8 {
    ((v >> (Nat32.fromNat(i) * 8)) & 0xff).toNat16().toNat8();
  };

  // Encode a block height as a 3-byte little-endian blob (txid-trie value).
  func encodeHeight(h : Nat) : Blob {
    if (h > 0xFF_FFFF) Runtime.trap("Chain: height overflow for txid trie value (> 2^24)");
    let v = Nat32.fromNat(h);
    Blob.fromArray([le32Byte(v, 0), le32Byte(v, 1), le32Byte(v, 2)]);
  };

  func decodeHeight(b : Blob) : Nat {
    Nat8.toNat(b[0]) + Nat8.toNat(b[1]) * 0x100 + Nat8.toNat(b[2]) * 0x1_0000;
  };

  // Slice the 32-byte txid at index `i` out of a flat hashes blob.
  // Bytes.slice32 indexes the Blob directly — a Blob.toArray here would
  // convert the ENTIRE flat blob per txid (quadratic: ~512 MB of churn to
  // index one 4000-tx body).
  func txidAt(hashes : Blob, i : Nat) : Blob = Bytes.slice32(hashes, i * 32);

  // ---------------------------------------------------------------------
  // Initialization.
  // ---------------------------------------------------------------------

  public func initGenesis(self : State, sha : Sha256.Digest, firstSeenSecs : Nat32, uploader : Principal) {
    initRoot(self, sha, Header.hexToBlob(Header.GENESIS_HEADER_HEX), firstSeenSecs, uploader);
  };

  // Seed index-0 from an arbitrary 80-byte header (genesis in production; a
  // checkpoint block in tests). Height 0, cumWork = its own block work; its
  // real prev_hash is ignored (height-0 reports a zero prev_hash).
  public func initRoot(self : State, sha : Sha256.Digest, raw : Blob, firstSeenSecs : Nat32, uploader : Principal) {
    if (self.initialized) return;
    let parsed = switch (Header.parseHeader(raw)) {
      case (?p) p;
      case null Runtime.trap("root header invalid");
    };
    let hash = Header.headerHashBlob(sha, raw);
    let work = targetWorkFor(self, parsed.bits).1;
    let value = HeaderValue.encodeFromRaw(raw, 0, 0, work, firstSeenSecs);
    let idx = Headers.add(self.headerTrie, hash, value);
    assert idx == 0;
    Uploaders.record(self.uploaders, hash, uploader);
    self.tipWork := work;
    self.recentTimes := [parsed.time];
    self.initialized := true;
  };

  // ---------------------------------------------------------------------
  // Internal: building StoredBlock views.
  // ---------------------------------------------------------------------

  func canonPrevHash(self : State, idx : Nat) : Blob {
    if (idx == 0) return ZERO_HASH_BLOB;
    switch (Headers.get(self.headerTrie, idx - 1)) {
      case (?(h, _)) h;
      case null Runtime.trap("canonPrevHash: missing index " # debug_show(idx - 1 : Nat));
    };
  };

  // Narrow reads: fetch a canonical block's 76-byte value by INDEX (no trie
  // descend, no key expansion) and extract single fields at the Blob level
  // (the HeaderValue accessors allocate nothing).
  func canonValueAt(self : State, height : Nat) : Blob {
    switch (Headers.valueAt(self.headerTrie, height)) {
      case (?v) v;
      case null Runtime.trap("canonValueAt: missing index " # debug_show height);
    };
  };

  func canonTimeAt(self : State, height : Nat) : Nat32 = HeaderValue.timeOf(canonValueAt(self, height));

  // ---------------------------------------------------------------------
  // Internal: median-time-past timestamp cache.
  //
  // `recentTimes` mirrors the timestamps of the canonical tip and its
  // ancestors (newest first, <= MTP_WINDOW entries). The hot push path
  // reads its MTP context from here instead of the header trie.
  // ---------------------------------------------------------------------

  let MTP_WINDOW : Nat = 11;

  // Record a new canonical tip timestamp (on append / promote).
  func pushRecentTime(self : State, t : Nat32) {
    let old = self.recentTimes;
    let size = if (old.size() < MTP_WINDOW) old.size() + 1 else MTP_WINDOW;
    self.recentTimes := Array.tabulate<Nat32>(size, func(i) = if (i == 0) t else old[i - 1]);
  };

  // Rebuild the cache from the trie tip downwards (narrow index reads).
  // Needed only when the tip moves backwards (reorg rollback).
  func rebuildRecentTimes(self : State) {
    let tip = tipHeight(self);
    let count = if (tip + 1 < MTP_WINDOW) tip + 1 else MTP_WINDOW;
    self.recentTimes := Array.tabulate<Nat32>(count, func(i) = canonTimeAt(self, tip - i));
  };

  // (target, per-block work) for `bits`, via the single-entry memo. bits is
  // constant within a difficulty period, so the 2^256 division happens once
  // per 2016 blocks instead of once per header.
  func targetWorkFor(self : State, bits : Nat32) : (Nat, Nat) {
    let memo = self.workMemo;
    if (bits == memo.bits) return (memo.target, memo.work);
    let target = Header.nBitsToTarget(bits);
    let work = if (target == 0) 0 else Header.TWO_POW_256 / (target + 1);
    self.workMemo := { bits; target; work };
    (target, work);
  };

  func storedCanonAt(self : State, idx : Nat) : StoredBlock {
    switch (Headers.get(self.headerTrie, idx)) {
      case (?(hash, value)) {
        {
          hash;
          height = idx;
          cumWork = HeaderValue.cumWorkOf(value);
          value;
          prevHash = canonPrevHash(self, idx);
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

  // ---------------------------------------------------------------------
  // Internal: ancestor walking (canonical or fork).
  // ---------------------------------------------------------------------

  public func byHashInternal(self : State, hash : Blob) : ?StoredBlock {
    if (hash.size() != 32) return null;
    switch (ForkStore.get(self.forks, hash)) {
      case (?fb) ?storedFork(fb);
      case null {
        switch (Headers.lookup(self.headerTrie, hash)) {
          case (?(value, idx)) ?{
            hash;
            height = idx;
            cumWork = HeaderValue.cumWorkOf(value);
            value;
            prevHash = canonPrevHash(self, idx);
            isCanonical = true;
          };
          case null null;
        };
      };
    };
  };

  func parentOf(self : State, b : StoredBlock) : ?StoredBlock {
    if (b.height == 0) return null;
    if (b.isCanonical) return ?storedCanonAt(self, b.height - 1);
    // Fork block: its parent is either another fork block (heap map) or the
    // canonical block at height b.height - 1 — check by INDEX and compare
    // hashes instead of descending the trie by hash.
    switch (ForkStore.get(self.forks, b.prevHash)) {
      case (?fb) ?storedFork(fb);
      case null {
        let idx = b.height - 1 : Nat;
        if (idx > tipHeight(self)) return null;
        switch (Headers.get(self.headerTrie, idx)) {
          case (?(h, value)) {
            if (h != b.prevHash) return null;
            ?{
              hash = h;
              height = idx;
              cumWork = HeaderValue.cumWorkOf(value);
              value;
              prevHash = canonPrevHash(self, idx);
              isCanonical = true;
            };
          };
          case null null;
        };
      };
    };
  };

  // Lightweight parent view for the push path: exactly the fields push
  // needs, no prev_hash read, no 76-byte value re-encode for fork blocks.
  type ParentInfo = {
    hash : Blob;
    height : Nat;
    cumWork : Nat;
    bits : Nat32;
    time : Nat32;
    isCanonical : Bool;
  };

  // Resolve a new header's parent by prev_hash.
  //   1. The canonical tip (the overwhelmingly common case) — found with a
  //      single INDEX read and a hash compare; cumWork comes from the
  //      cached tipWork, so nothing is decoded.
  //   2. A fork block — heap map hit, fields read directly.
  //   3. A canonical non-tip block — the one case that needs a trie descend.
  func resolveParent(self : State, prevHash : Blob) : ?ParentInfo {
    let tipIdx = tipHeight(self);
    switch (Headers.get(self.headerTrie, tipIdx)) {
      case (?(h, value)) if (h == prevHash) {
        return ?{
          hash = prevHash;
          height = tipIdx;
          cumWork = self.tipWork;
          bits = HeaderValue.bitsOf(value);
          time = HeaderValue.timeOf(value);
          isCanonical = true;
        };
      };
      case _ {};
    };
    switch (ForkStore.get(self.forks, prevHash)) {
      case (?fb) {
        return ?{
          hash = fb.hash;
          height = fb.height;
          cumWork = fb.cumWork;
          bits = fb.bits;
          time = fb.time;
          isCanonical = false;
        };
      };
      case null {};
    };
    switch (Headers.lookup(self.headerTrie, prevHash)) {
      case (?(value, idx)) ?{
        hash = prevHash;
        height = idx;
        cumWork = HeaderValue.cumWorkOf(value);
        bits = HeaderValue.bitsOf(value);
        time = HeaderValue.timeOf(value);
        isCanonical = true;
      };
      case null null;
    };
  };

  // Timestamps of `start` and its ancestors, newest first, up to n.
  // The canonical-tip case is served from the recentTimes cache (zero trie
  // reads); otherwise canonical segments use narrow index reads (timeOf
  // only — no StoredBlock, no cumWork decode, no prev_hash read) and fork
  // segments read the heap ForkBlock records, with no trie descend even at
  // the fork-to-canonical transition (the parent height is known).
  func lastTimestampsFrom(self : State, startHash : Blob, startHeight : Nat, startIsCanonical : Bool, n : Nat) : [Nat32] {
    if (n == 0) return [];
    if (startIsCanonical and startHeight == tipHeight(self)) {
      let cached = self.recentTimes;
      let take = if (n < cached.size()) n else cached.size();
      return Array.tabulate<Nat32>(take, func(i) = cached[i]);
    };
    let buf = List.empty<Nat32>();
    var remaining = n;
    // Fork segment (if any): walk the heap fork store down to the
    // canonical anchor.
    var canonFrom : ?Nat = if (startIsCanonical) ?startHeight else null;
    if (not startIsCanonical) {
      var curHash = startHash;
      label walk while (remaining > 0) {
        switch (ForkStore.get(self.forks, curHash)) {
          case (?fb) {
            List.add(buf, fb.time);
            remaining -= 1;
            if (fb.height == 0) break walk;
            curHash := fb.prevHash;
            // Parent not in the fork store => canonical at fb.height - 1.
            if (not ForkStore.contains(self.forks, curHash)) {
              canonFrom := ?(fb.height - 1 : Nat);
              break walk;
            };
          };
          case null break walk;
        };
      };
    };
    switch (canonFrom) {
      case (?h0) {
        var h = h0;
        label canon while (remaining > 0) {
          List.add(buf, canonTimeAt(self, h));
          remaining -= 1;
          if (h == 0) break canon;
          h -= 1;
        };
      };
      case null {};
    };
    List.toArray(buf);
  };

  // Timestamp of `parent`'s ancestor at `targetHeight` (for the retarget
  // rule). Canonical parents resolve with one narrow index read; fork
  // parents walk the heap fork store down to the canonical anchor.
  func ancestorTimeAt(self : State, parent : ParentInfo, targetHeight : Nat) : ?Nat32 {
    if (targetHeight > parent.height) return null;
    if (parent.isCanonical) return ?canonTimeAt(self, targetHeight);
    if (targetHeight == parent.height) return ?parent.time;
    var curHash = parent.hash;
    loop {
      switch (ForkStore.get(self.forks, curHash)) {
        case (?fb) {
          if (fb.height == targetHeight) return ?fb.time;
          if (fb.height == 0) return null;
          curHash := fb.prevHash;
        };
        // Left the fork store: every remaining ancestor is canonical.
        case null return ?canonTimeAt(self, targetHeight);
      };
    };
  };

  func expectedBitsFor(self : State, parent : ParentInfo, newHeight : Nat) : Nat32 {
    let parentBits = parent.bits;
    if (newHeight % Header.RETARGET_INTERVAL == 0 and newHeight >= Header.RETARGET_INTERVAL) {
      let firstHeight = newHeight - Header.RETARGET_INTERVAL : Nat;
      switch (ancestorTimeAt(self, parent, firstHeight)) {
        case (?firstTime) Header.computeRetargetNBits(parent.time, parentBits, firstTime);
        case null parentBits;
      };
    } else {
      parentBits;
    };
  };

  // ---------------------------------------------------------------------
  // Internal: reorg.
  // ---------------------------------------------------------------------

  // Switch the canonical chain to the heavier branch ending at `newTipHash`
  // if it outweighs the current tip. Returns the number of canonical blocks
  // displaced (0 if no reorg happened). The fork-choice algorithm itself
  // lives in mo:heaviest-chain/Reorg — this function provides the world:
  // how blocks are stored (trie encode/decode), the body demotion/
  // re-indexing, and the timestamp-cache maintenance.
  func maybeReorg(self : State, newTipHash : Blob, newWork : Nat, now : Int) : Nat {
    if (newWork <= self.tipWork) return 0;

    let oldTipHeight = tipHeight(self);
    let oldTipHash = switch (Headers.get(self.headerTrie, oldTipHeight)) {
      case (?(h, _)) h;
      case null Runtime.trap("maybeReorg: missing old tip");
    };

    // Bodies extracted from the txid trie in beforeRollback travel into the
    // demoted ForkBlocks via this map (shared by the two closures).
    let demotedBodies = Map.empty<Nat, ForkBody>();

    let acc : Reorg.Accessors<ForkBlock> = {
      id = func(b : ForkBlock) : Blob = b.hash;
      parent = func(b : ForkBlock) : Blob = b.prevHash;
      height = func(b : ForkBlock) : Nat = b.height;
    };

    let canon : Reorg.Canonical<ForkBlock> = {
      tipHeight = func() : Nat = tipHeight(self);
      idAt = func(h : Nat) : ?Blob {
        switch (Headers.get(self.headerTrie, h)) {
          case (?(k, _)) ?k;
          case null null;
        };
      };
      // Promote a branch block: encode and append its value, keep the
      // timestamp cache current, and re-index its body if known (the
      // all-ancestors-known invariant keeps fork bodies contiguous from the
      // common ancestor, so the frontier advances without gaps).
      append = func(fb : ForkBlock) {
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
        ignore Headers.add(self.headerTrie, fb.hash, value);
        pushRecentTime(self, fb.time);
        switch (fb.body) {
          case (?b) if (fb.height == self.bodiesNextHeight) {
            appendCanonicalBody(self, fb.height, value, b.txids);
            self.bodiesNextHeight += 1;
          };
          case null {};
        };
      };
      // Demote the canonical tip into a full ForkBlock, attaching the body
      // extracted in beforeRollback (if any).
      demoteTip = func() : ForkBlock {
        let h = tipHeight(self);
        let (rmHash, rmValue) = switch (Headers.removeLast(self.headerTrie)) {
          case (?x) x;
          case null Runtime.trap("maybeReorg: removeLast on empty trie");
        };
        let prevH = switch (Headers.get(self.headerTrie, h - 1)) {
          case (?(ph, _)) ph;
          case null Runtime.trap("maybeReorg: missing parent of displaced block");
        };
        {
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
        };
      };
    };

    let hooks : Reorg.Hooks = {
      // Before any header is removed: extract each displaced canonical
      // block's transactions (with its F) from the txid trie so they travel
      // with the block into the fork store, then truncate the trie to the
      // common ancestor.
      beforeRollback = func(commonHeight : Nat) {
        if (self.bodiesNextHeight > commonHeight + 1) {
          let truncPoint = switch (Headers.get(self.headerTrie, commonHeight + 1)) {
            case (?(_, v)) HeaderValue.firstTxIndexOf(v);
            case null Runtime.trap("maybeReorg: missing first displaced block");
          };
          var h = commonHeight + 1;
          while (h < self.bodiesNextHeight) {
            let value = switch (Headers.get(self.headerTrie, h)) {
              case (?(_, v)) v;
              case null Runtime.trap("maybeReorg: missing displaced body block");
            };
            let lo = HeaderValue.firstTxIndexOf(value);
            let hi = if (h + 1 < self.bodiesNextHeight) {
              switch (Headers.get(self.headerTrie, h + 1)) {
                case (?(_, v)) HeaderValue.firstTxIndexOf(v);
                case null Runtime.trap("maybeReorg: missing displaced body block");
              };
            } else StableTrie.size(self.txTrie);
            Map.add<Nat, ForkBody>(demotedBodies, Nat.compare, h, { txids = extractTxids(self, lo, hi); firstTxIndex = lo });
            h += 1;
          };
          StableTrie.truncate(self.txTrie, truncPoint);
          self.bodiesNextHeight := commonHeight + 1;
        };
      };
      // The rollback moved the tip below the old window — refill the
      // timestamp cache from the surviving canonical tail; the promoted
      // branch's timestamps then come from the ForkBlocks in append.
      afterRollback = func() = rebuildRecentTimes(self);
    };

    switch (Reorg.maybeReorg(self.forks, acc, canon, hooks, newTipHash, newWork, self.tipWork)) {
      case null 0;
      case (?ev) {
        self.tipWork := newWork;
        List.add(self.reorgLog, {
          time = now;
          common_height = ev.commonHeight;
          fork_length = ev.promoted;
          displaced = ev.displaced;
          old_tip_hash_be_hex = bytesToHexBE(oldTipHash);
          old_tip_height = oldTipHeight;
          new_tip_hash_be_hex = bytesToHexBE(newTipHash);
          new_tip_height = tipHeight(self);
        });
        ev.displaced;
      };
    };
  };

  func storeAndMaybeReorg(
    self : State,
    raw : Blob,
    parsed : Header.Parsed,
    hash : Blob,
    parent : ParentInfo,
    firstSeenSecs : Nat32,
    uploader : Principal,
    now : Int,
  ) : PushOk {
    let newHeight = parent.height + 1;
    let cumWork = parent.cumWork + targetWorkFor(self, parsed.bits).1;

    Uploaders.record(self.uploaders, hash, uploader);

    var isCanonical = false;
    var reorgDepth : Nat = 0;

    if (parent.isCanonical and parent.height == tipHeight(self)) {
      // version and merkle|time|bits|nonce are copied straight from the raw
      // header bytes — no re-serialization of parsed fields.
      let value = HeaderValue.encodeFromRaw(raw, 0, newHeight, cumWork, firstSeenSecs);
      ignore Headers.add(self.headerTrie, hash, value);
      pushRecentTime(self, parsed.time);
      self.tipWork := cumWork;
      isCanonical := true;
    } else {
      ForkStore.add(self.forks, hash, newHeight, {
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
      reorgDepth := maybeReorg(self, hash, cumWork, now);
      if (reorgDepth > 0) isCanonical := true;
    };

    {
      height = newHeight;
      hash;
      is_canonical = isCanonical;
      reorg_depth = reorgDepth;
    };
  };

  // ---------------------------------------------------------------------
  // Public mutating API.
  // ---------------------------------------------------------------------

  public func push(self : State, sha : Sha256.Digest, raw : Blob, nowSecs : Int, uploader : Principal) : Result.Result<PushOk, Text> {
    if (raw.size() != 80) return #err("header is not 80 bytes");
    let parsed = switch (Header.parseHeader(raw)) {
      case (?p) p;
      case null return #err("could not parse header");
    };
    let hash = Header.headerHashBlob(sha, raw);
    switch (byHashInternal(self, hash)) {
      case (?_) return #err("duplicate: hash already present");
      case null {};
    };
    let parent = switch (resolveParent(self, parsed.prev_hash)) {
      case (?p) p;
      case null return #err("unknown previous block hash");
    };
    // Reject headers whose timestamp is more than ONE_YEAR_SECS before the
    // current canonical tip's timestamp (tip time from the cache).
    let tipTimeNat = Nat32.toNat(self.recentTimes[0]);
    let parsedTimeNat = Nat32.toNat(parsed.time);
    if (parsedTimeNat + ONE_YEAR_SECS < tipTimeNat) {
      return #err(
        "header timestamp " # debug_show parsedTimeNat #
        " is more than 1 year before current tip timestamp " #
        debug_show tipTimeNat
      );
    };
    let newHeight = parent.height + 1;
    let expectedBits = expectedBitsFor(self, parent, newHeight);
    let stamps = lastTimestampsFrom(self, parent.hash, parent.height, parent.isCanonical, if (newHeight < MTP_WINDOW) newHeight else MTP_WINDOW);
    let mtp = Header.medianTimePast(stamps);

    switch (Header.validateParsed(parsed, hash, expectedBits, parsed.prev_hash, mtp, nowSecs)) {
      case (#err msg) return #err(msg);
      case (#ok()) {};
    };
    let firstSeen = nat32OfNowSecs(nowSecs);
    #ok(storeAndMaybeReorg(self, raw, parsed, hash, parent, firstSeen, uploader, nowSecs));
  };

  public func pushUnchecked(self : State, sha : Sha256.Digest, raw : Blob, nowSecs : Int, uploader : Principal) : Result.Result<PushOk, Text> {
    if (raw.size() != 80) return #err("header is not 80 bytes");
    let parsed = switch (Header.parseHeader(raw)) {
      case (?p) p;
      case null return #err("could not parse header");
    };
    let hash = Header.headerHashBlob(sha, raw);
    switch (byHashInternal(self, hash)) {
      case (?_) return #err("duplicate: hash already present");
      case null {};
    };
    let parent = switch (resolveParent(self, parsed.prev_hash)) {
      case (?p) p;
      case null return #err("unknown previous block hash");
    };
    #ok(storeAndMaybeReorg(self, raw, parsed, hash, parent, nat32OfNowSecs(nowSecs), uploader, nowSecs));
  };

  // ---------------------------------------------------------------------
  // Public queries.
  // ---------------------------------------------------------------------

  // Total headers ever stored (canonical + fork).
  public func size(self : State) : Nat = Headers.size(self.headerTrie) + ForkStore.size(self.forks);

  public func memoryStats(self : State) : Headers.MemoryStats = Headers.memoryStats(self.headerTrie);

  public func tipHeight(self : State) : Nat = Headers.size(self.headerTrie) - 1 : Nat;

  public func tipBlock(self : State) : StoredBlock = storedCanonAt(self, tipHeight(self));

  public func canonicalAt(self : State, height : Nat) : ?StoredBlock {
    if (height > tipHeight(self)) null else ?storedCanonAt(self, height);
  };

  public func allAt(self : State, height : Nat) : [StoredBlock] {
    let out = List.empty<StoredBlock>();
    if (height <= tipHeight(self)) {
      List.add(out, storedCanonAt(self, height));
    };
    for (h in ForkStore.at(self.forks, height).vals()) {
      switch (ForkStore.get(self.forks, h)) {
        case (?fb) List.add(out, storedFork(fb));
        case null {};
      };
    };
    List.toArray(out);
  };

  public func byHashBE(self : State, hex : Text) : ?StoredBlock {
    let bytes = Header.hexToBlob(hex);
    if (bytes.size() != 32) return null;
    byHashInternal(self, Header.reverse32(bytes));
  };

  public func hasHashBE(self : State, hex : Text) : Bool {
    let bytes = Header.hexToBlob(hex);
    if (bytes.size() != 32) return false;
    let internal = Header.reverse32(bytes);
    if (ForkStore.contains(self.forks, internal)) return true;
    switch (Headers.lookup(self.headerTrie, internal)) {
      case (?_) true;
      case null false;
    };
  };

  public func isOnCanonical(b : StoredBlock) : Bool = b.isCanonical;

  public func canonicalChildOf(self : State, b : StoredBlock) : ?StoredBlock {
    canonicalAt(self, b.height + 1);
  };

  public func prevHashOf(b : StoredBlock) : Blob = b.prevHash;

  // Bitcoin-Core "median time past": median of `b` and its 10 ancestors.
  public func mediantimeOf(self : State, b : StoredBlock) : Nat32 {
    let stamps = lastTimestampsFrom(self, b.hash, b.height, b.isCanonical, MTP_WINDOW);
    let sorted = Array.sort<Nat32>(stamps, Nat32.compare);
    sorted[sorted.size() / 2];
  };

  // Reconstruct the canonical 80-byte raw header: the stored value IS the
  // raw header with the prev_hash window repurposed — patch it back in.
  public func rawHeaderOf(b : StoredBlock) : Blob = HeaderValue.toRawHeader(b.value, b.prevHash);

  // Recompute the canonical chain's hashes from stored data, heights
  // start..n: read each value by index, patch the running parent hash into
  // the prev_hash window, sha256d, carry forward. The chain is seeded at
  // `start` with the stored prev_hash of that block (zeros at height 0,
  // otherwise the stored trie key at start-1), so a sub-range can be verified
  // without re-walking from genesis. Returns the hash of the block at height
  // n (internal LE order), or null if n is beyond the tip or start > n. Pure
  // integrity check: the result equals the stored trie key at height n iff
  // the stored headers re-hash into a consistent chain. Touches no state.
  public func rehashChain(self : State, sha : Sha256.Digest, start : Nat, n : Nat) : ?Blob {
    if (start > n or n > tipHeight(self)) return null;
    var prev : Blob = canonPrevHash(self, start);
    var h = start;
    while (h <= n) {
      let raw = HeaderValue.toRawHeader(canonValueAt(self, h), prev);
      prev := Header.headerHashBlob(sha, raw);
      h += 1;
    };
    ?prev;
  };

  // All current forks (non-canonical branches), one entry per tip.
  public func forks(self : State) : [Fork] {
    // A fork block is a tip iff no other fork block names it as parent.
    let referenced = Set.empty<Blob>();
    for ((_, fb) in ForkStore.entries(self.forks)) {
      if (ForkStore.contains(self.forks, fb.prevHash)) {
        Set.add<Blob>(referenced, Blob.compare, fb.prevHash);
      };
    };
    let out = List.empty<Fork>();
    for ((hash, fb) in ForkStore.entries(self.forks)) {
      if (not Set.contains<Blob>(referenced, Blob.compare, hash)) {
        // Walk down from the tip to the canonical branch point.
        var cur = storedFork(fb);
        var length : Nat = 0;
        var branch : StoredBlock = cur;
        label walk loop {
          length += 1;
          switch (parentOf(self, cur)) {
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

  public func reorgs(self : State) : [ReorgEvent] = List.toArray(self.reorgLog);

  // ---------------------------------------------------------------------
  // Uploader queries (thin pass-throughs to the Uploaders module).
  // ---------------------------------------------------------------------

  public func uploaderOf(self : State, hash : Blob) : Principal = Uploaders.of(self.uploaders, hash);

  public func uploaderStats(self : State) : [(Principal, Nat)] = Uploaders.stats(self.uploaders);

  public func blocksByUploader(self : State, p : Principal, offset : Nat, limit : Nat) : [Blob] =
    Uploaders.blocksByUploader(self.uploaders, p, offset, limit);

  // ---------------------------------------------------------------------
  // Block bodies.
  //
  // A block's body may be uploaded only once the bodies of ALL its ancestors
  // are known — i.e. its first-tx serial F is determined:
  //   * canonical block: its height must equal the body frontier
  //     (bodiesNextHeight); bodies fill in strict chain order and go straight
  //     into the stable txid trie;
  //   * fork block: its parent's body must be known; the body is stored in the
  //     ForkBlock record.
  // ---------------------------------------------------------------------

  public func bodiesHeight(self : State) : Nat = self.bodiesNextHeight;

  public func totalIndexedTxids(self : State) : Nat = StableTrie.size(self.txTrie);

  // Number of fork blocks that currently carry a body.
  public func forkBodyCount(self : State) : Nat {
    var n = 0;
    for ((_, fb) in ForkStore.entries(self.forks)) {
      switch (fb.body) { case (?_) n += 1; case null {} };
    };
    n;
  };

  // Read txids stored in the canonical trie at indices [lo, hi) into a flat
  // blob (moves a demoted block's body into the fork store).
  func extractTxids(self : State, lo : Nat, hi : Nat) : Blob {
    let keys = Array.tabulate<Blob>(
      hi - lo : Nat,
      func(k) = switch (StableTrie.get(self.txTrie, lo + k)) {
        case (?(key, _)) key;
        case null Runtime.trap("extractTxids: missing txid " # debug_show(lo + k));
      },
    );
    Blob.fromArray(Array.tabulate<Nat8>((hi - lo : Nat) * 32, func(j) = keys[j / 32][j % 32]));
  };

  // Append one block's body (flat txid blob) to the tail of the canonical
  // txid trie, setting its F. The two BIP30 single-tx blocks are stored
  // compressed (F set, no txids — see isCompressedBodyHeight); any other
  // cross-block duplicate txid would silently corrupt the F-arithmetic, so
  // it traps (impossible on mainnet post-BIP30/34).
  func appendCanonicalBody(self : State, height : Nat, value : Blob, body : Blob) {
    let f = StableTrie.size(self.txTrie);
    Headers.put(self.headerTrie, height, HeaderValue.withFirstTxIndex(value, f));
    if (isCompressedBodyHeight(height)) return;
    let n = body.size() / 32;
    let hv = encodeHeight(height);
    var i = 0;
    while (i < n) { ignore StableTrie.add(self.txTrie, txidAt(body, i), hv); i += 1 };
    if (StableTrie.size(self.txTrie) != f + n) {
      Runtime.trap("appendCanonicalBody: unexpected duplicate txid at height " # debug_show height);
    };
  };

  // Body stored in a fork block's record, if any.
  func forkBodyOf(self : State, hash : Blob) : ?ForkBody {
    switch (ForkStore.get(self.forks, hash)) {
      case (?fb) fb.body;
      case null null;
    };
  };

  // Is this block's body already known?
  func bodyKnown(self : State, b : StoredBlock) : Bool {
    (b.isCanonical and b.height < self.bodiesNextHeight) or (switch (forkBodyOf(self, b.hash)) { case (?_) true; case null false });
  };

  // F of the block immediately after `parent` (= F(parent) + N(parent)), if
  // `parent`'s body is known; else null.
  func firstTxAfter(self : State, parent : StoredBlock) : ?Nat {
    if (parent.isCanonical) {
      if (parent.height < self.bodiesNextHeight) {
        ?(HeaderValue.firstTxIndexOf(parent.value) + trieTxCount(self, parent.height));
      } else null;
    } else switch (forkBodyOf(self, parent.hash)) {
      case (?body) ?(body.firstTxIndex + body.txids.size() / 32);
      case null null;
    };
  };

  // Width of a block's txid segment in the trie: [F(h), F(h+1)).
  func segmentWidth(self : State, height : Nat) : Nat {
    let f = switch (Headers.get(self.headerTrie, height)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return 0 };
    let next = if (height + 1 < self.bodiesNextHeight) {
      switch (Headers.get(self.headerTrie, height + 1)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return 0 };
    } else StableTrie.size(self.txTrie);
    next - f : Nat;
  };

  // tx_count of a canonical block whose body is indexed. A zero-width
  // segment can only be a compressed single-tx block (every real block has
  // a coinbase), so it counts as 1.
  func trieTxCount(self : State, height : Nat) : Nat {
    let w = segmentWidth(self, height);
    if (w == 0) 1 else w;
  };

  func bodyResult(self : State, b : StoredBlock, duplicate : Bool) : PushBodyOk {
    if (b.isCanonical and b.height < self.bodiesNextHeight) {
      let f = switch (Headers.get(self.headerTrie, b.height)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null 0 };
      return { height = b.height; tx_count = trieTxCount(self, b.height); first_tx_index = f; canonical_indexed = true; duplicate };
    };
    switch (forkBodyOf(self, b.hash)) {
      case (?body) ({ height = b.height; tx_count = body.txids.size() / 32; first_tx_index = body.firstTxIndex; canonical_indexed = false; duplicate });
      case null ({ height = b.height; tx_count = 0; first_tx_index = 0; canonical_indexed = false; duplicate });
    };
  };

  // Index a block's body — allowed only when all ancestor bodies are known.
  // Canonical bodies go to the txid trie in chain order; fork bodies into the
  // ForkBlock record. Re-upload is a no-op.
  public func pushBody(self : State, sha : Sha256.Digest, blockHashInternal : Blob, txCount : Nat, hashes : Blob) : Result.Result<PushBodyOk, Text> {
    if (blockHashInternal.size() != 32) return #err("block hash must be 32 bytes");
    if (txCount == 0) return #err("tx_count must be >= 1");
    if (hashes.size() != txCount * 32) {
      return #err("hashes length " # debug_show hashes.size() # " != tx_count*32");
    };
    let b = switch (byHashInternal(self, blockHashInternal)) {
      case (?b) b;
      case null return #err("unknown block header hash");
    };
    if (bodyKnown(self, b)) return #ok(bodyResult(self, b, true));
    if (Merkle.root(sha, hashes, txCount) != HeaderValue.merkleOf(b.value)) return #err("merkle root mismatch");

    if (b.isCanonical) {
      if (b.height != self.bodiesNextHeight) {
        return #err(
          "ancestor bodies unknown: expected canonical body for height " #
          debug_show self.bodiesNextHeight # ", got " # debug_show b.height
        );
      };
      appendCanonicalBody(self, b.height, b.value, hashes);
      self.bodiesNextHeight += 1;
      #ok(bodyResult(self, b, false));
    } else {
      let parent = switch (parentOf(self, b)) {
        case (?p) p;
        case null return #err("fork block has no parent");
      };
      let f = switch (firstTxAfter(self, parent)) {
        case (?f) f;
        case null return #err("ancestor bodies unknown for this fork block");
      };
      let fb = switch (ForkStore.get(self.forks, b.hash)) {
        case (?x) x;
        case null return #err("fork block missing from store");
      };
      ForkStore.update(self.forks, b.hash, { fb with body = ?{ txids = hashes; firstTxIndex = f } });
      #ok(bodyResult(self, b, false));
    };
  };

  // tx_count of any block by internal hash, or null if its body is not known.
  public func txCountOfHash(self : State, hash : Blob) : ?Nat {
    switch (byHashInternal(self, hash)) {
      case null null;
      case (?b) {
        if (b.isCanonical and b.height < self.bodiesNextHeight) ?trieTxCount(self, b.height) else switch (forkBodyOf(self, b.hash)) {
          case (?body) ?(body.txids.size() / 32);
          case null null;
        };
      };
    };
  };

  // tx_count of the canonical block at `height`, or null if not yet indexed.
  public func txCountAt(self : State, height : Nat) : ?Nat {
    if (height < self.bodiesNextHeight) ?trieTxCount(self, height) else null;
  };

  public func bodyAt(self : State, height : Nat) : ?BodyInfo {
    if (height >= self.bodiesNextHeight) return null;
    let f = switch (Headers.get(self.headerTrie, height)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return null };
    ?{ height; tx_count = trieTxCount(self, height); first_tx_index = f; canonical_indexed = true };
  };

  // Does the flat txid blob `body` contain `txid`?
  func bodyContains(body : Blob, txid : Blob) : Bool {
    let n = body.size() / 32;
    var i = 0;
    while (i < n) { if (txidAt(body, i) == txid) return true; i += 1 };
    false;
  };

  // Every known block containing `txid` (internal LE): the canonical height
  // (from the txid trie) plus all fork blocks whose stored body holds it.
  public func lookupTxid(self : State, txid : Blob) : { canonical : ?Nat; forks : [Blob] } {
    if (txid.size() != 32) return { canonical = null; forks = [] };
    let canonical = switch (StableTrie.lookup(self.txTrie, txid)) {
      case (?(v, _)) ?decodeHeight(v);
      case null null;
    };
    let fks = List.empty<Blob>();
    for ((hash, fb) in ForkStore.entries(self.forks)) {
      switch (fb.body) {
        case (?body) if (bodyContains(body.txids, txid)) List.add(fks, hash);
        case null {};
      };
    };
    { canonical; forks = List.toArray(fks) };
  };

  // txid (internal LE) at global canonical serial `index`, or null.
  public func txidAtIndex(self : State, index : Nat) : ?Blob {
    switch (StableTrie.get(self.txTrie, index)) { case (?(k, _)) ?k; case null null };
  };

  // Position of `txid` within `body` (flat txid blob), or null.
  func bodyPositionOf(body : Blob, txid : Blob) : ?Nat {
    let n = body.size() / 32;
    var i = 0;
    while (i < n) { if (txidAt(body, i) == txid) return ?i; i += 1 };
    null;
  };

  // All locations of `txid` (internal LE): the canonical occurrence (with its
  // global serial index and in-block position) plus each fork block holding it.
  public func txLocations(self : State, txid : Blob) : { canonical : ?TxCanonLoc; forks : [TxForkLoc] } {
    if (txid.size() != 32) return { canonical = null; forks = [] };
    let canonical : ?TxCanonLoc = switch (StableTrie.lookup(self.txTrie, txid)) {
      case (?(v, idx)) {
        let height = decodeHeight(v);
        let f = switch (Headers.get(self.headerTrie, height)) { case (?(_, hv)) HeaderValue.firstTxIndexOf(hv); case null 0 };
        ?{ height; position = idx - f : Nat; index = idx };
      };
      case null null;
    };
    let fks = List.empty<TxForkLoc>();
    for ((hash, fb) in ForkStore.entries(self.forks)) {
      switch (fb.body) {
        case (?body) switch (bodyPositionOf(body.txids, txid)) {
          case (?pos) List.add(fks, { hash; height = fb.height; position = pos });
          case null {};
        };
        case null {};
      };
    };
    { canonical; forks = List.toArray(fks) };
  };

  // Txids of the block `hash` (canonical or fork) in block order, internal LE,
  // paginated. Empty if the block or its body isn't known.
  public func blockTxids(self : State, hash : Blob, offset : Nat, limit : Nat) : [Blob] {
    switch (byHashInternal(self, hash)) {
      case null [];
      case (?b) {
        if (b.isCanonical and b.height < self.bodiesNextHeight) {
          // A zero-width segment is a compressed single-tx block (BIP30
          // pair member): its only txid is the header's merkle root.
          if (segmentWidth(self, b.height) == 0) {
            if (offset >= 1 or limit == 0) return [];
            return [HeaderValue.merkleOf(b.value)];
          };
          let f = HeaderValue.firstTxIndexOf(b.value);
          let n = trieTxCount(self, b.height);
          if (offset >= n) return [];
          let rem : Nat = n - offset;
          let take = if (limit < rem) limit else rem;
          Array.tabulate<Blob>(
            take,
            func(i) = switch (StableTrie.get(self.txTrie, f + offset + i)) {
              case (?(k, _)) k;
              case null Runtime.trap("blockTxids: missing txid");
            },
          );
        } else switch (forkBodyOf(self, b.hash)) {
          case (?body) {
            let n = body.txids.size() / 32;
            if (offset >= n) return [];
            let rem : Nat = n - offset;
            let take = if (limit < rem) limit else rem;
            Array.tabulate<Blob>(take, func(i) = txidAt(body.txids, offset + i));
          };
          case null [];
        };
      };
    };
  };

  // ---------------------------------------------------------------------
  // Metrics (promtracker pull Values).
  // ---------------------------------------------------------------------

  // Heap fork-store + reorg-history metrics, computed once per scrape.
  public func heapStatsValue(self : State) : MetricValue = {
    read = func() : [(Text, Text, Nat)] {
      let fs = forks(self);
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
      for (e in List.values(self.reorgLog)) {
        reorgLastCommon := e.common_height;
        if (e.displaced > reorgMaxDisplaced) reorgMaxDisplaced := e.displaced;
      };
      let nr = List.size(self.reorgLog);
      [
        ("chain_fork_tips", "", fs.size()),
        ("chain_fork_blocks", "", ForkStore.size(self.forks)),
        ("chain_fork_bodies", "", forkBodyCount(self)),
        ("chain_fork_longest", "", longest),
        ("chain_fork_highest_tip_height", "", highestTip),
        ("chain_fork_highest_tip_common_height", "", highestTipCommon),
        ("chain_reorg_count", "", nr),
        ("chain_reorg_last_common_height", "", reorgLastCommon),
        ("chain_reorg_max_displaced", "", reorgMaxDisplaced),
      ];
    };
  };

  // ---------------------------------------------------------------------
  // Test helpers.
  // ---------------------------------------------------------------------

  // Small txid-trie root for tests (the wasm test runtime can't allocate the
  // production ~1 GB root region).
  let TEST_TX_ROOT_ARIDITY : Nat = 256;

  // A fresh chain seeded with genesis, full 32-byte keys (synthetic non-PoW
  // headers store without tripping the trailing-zero truncation invariant).
  public func emptyForTest() : State {
    let s = newState(newHeaderTrie(Headers.HASH_SIZE), newTxTrie(TEST_TX_ROOT_ARIDITY));
    initGenesis(s, Sha256.new(#sha256), 0, Principal.fromText("aaaaa-aa"));
    s;
  };

  // A chain anchored at an arbitrary checkpoint header (hex). `keySize` selects
  // the trie key width — pass Headers.KEY_SIZE (28) to exercise the production
  // truncation path with real PoW headers.
  public func fromRootHex(rawHex : Text, keySize : Nat) : State {
    let s = newState(newHeaderTrie(keySize), newTxTrie(TEST_TX_ROOT_ARIDITY));
    initRoot(s, Sha256.new(#sha256), Header.hexToBlob(rawHex), 0, Principal.fromText("aaaaa-aa"));
    s;
  };

};
