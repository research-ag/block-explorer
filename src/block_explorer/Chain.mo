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
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Set "mo:core/Set";

import StableTrie "mo:stable-trie/Enumeration";

import Header "Header";
import HeaderValue "HeaderValue";
import Merkle "Merkle";
import Headers "Headers";
import ForkStore "ForkStore";
import Uploaders "Uploaders";

module {

  // ---------------------------------------------------------------------
  // Public types.
  // ---------------------------------------------------------------------

  // Fork-block types are owned by ForkStore; re-exported for convenience.
  public type ForkBody = ForkStore.ForkBody;
  public type ForkBlock = ForkStore.ForkBlock;

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
    forks : ForkStore.ForkStore;
    uploaders : Uploaders.Uploaders;
    reorgLog : List.List<ReorgEvent>;
    txCountOverride : Map.Map<Nat, Nat>; // BIP30 duplicate-coinbase heights
    var tipWork : Nat; // cumulative work of the canonical tip
    var bodiesNextHeight : Nat; // canonical bodies known for [0, this)
    var initialized : Bool;
  };

  // ---------------------------------------------------------------------
  // Construction.
  // ---------------------------------------------------------------------

  // Production root_aridity for the txid trie (= 4^14). Allocates a ~1 GB
  // flat root region at trie creation (fine on the IC; tests pass a small
  // value to avoid the upfront allocation).
  public let TX_ROOT_ARIDITY : Nat = 268_435_456;

  // Header trie: 28-byte (or 32 for tests) keys -> 76-byte HeaderValue blobs;
  // root_aridity 4^9 (~1 MB root).
  public func newHeaderTrie(keySize : Nat) : StableTrie.Enumeration = StableTrie.empty({
    pointer_size = 4;
    aridity = 4;
    root_aridity = ?262144; // = 4^9
    key_size = keySize;
    value_size = 76;
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
    forks = ForkStore.empty();
    uploaders = Uploaders.empty();
    reorgLog = List.empty<ReorgEvent>();
    txCountOverride = Map.empty<Nat, Nat>();
    var tipWork = 0;
    var bodiesNextHeight = 0;
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

  // Byte at little-endian position `i` (0..3) of a Nat32.
  func le32Byte(v : Nat32, i : Nat) : Nat8 {
    Nat8.fromNat(Nat32.toNat((v >> (Nat32.fromNat(i) * 8)) & 0xff));
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
  func txidAt(hashes : Blob, i : Nat) : Blob {
    let arr = Blob.toArray(hashes);
    let off = i * 32;
    Blob.fromArray(Array.tabulate<Nat8>(32, func(j) = arr[off + j]));
  };

  // ---------------------------------------------------------------------
  // Initialization.
  // ---------------------------------------------------------------------

  public func initGenesis(self : State, firstSeenSecs : Nat32, uploader : Principal) {
    initRoot(self, Header.hexToBlob(Header.GENESIS_HEADER_HEX), firstSeenSecs, uploader);
  };

  // Seed index-0 from an arbitrary 80-byte header (genesis in production; a
  // checkpoint block in tests). Height 0, cumWork = its own block work; its
  // real prev_hash is ignored (height-0 reports a zero prev_hash).
  public func initRoot(self : State, raw : Blob, firstSeenSecs : Nat32, uploader : Principal) {
    if (self.initialized) return;
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
    let idx = Headers.add(self.headerTrie, hash, value);
    assert idx == 0;
    Uploaders.record(self.uploaders, hash, uploader);
    self.tipWork := work;
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
    byHashInternal(self, b.prevHash);
  };

  // Ancestor of `start` at `targetHeight` (<= start.height).
  func ancestorAt(self : State, start : StoredBlock, targetHeight : Nat) : ?StoredBlock {
    if (targetHeight > start.height) return null;
    var cur = start;
    loop {
      if (cur.height == targetHeight) return ?cur;
      if (cur.isCanonical) return ?storedCanonAt(self, targetHeight);
      switch (parentOf(self, cur)) {
        case (?p) cur := p;
        case null return null;
      };
    };
  };

  func lastNTimestamps(self : State, start : StoredBlock, n : Nat) : [Nat32] {
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
          cur := parentOf(self, b);
        };
      };
    };
    List.toArray(buf);
  };

  func expectedBitsFor(self : State, parent : StoredBlock, newHeight : Nat) : Nat32 {
    let parentBits = HeaderValue.bitsOf(parent.value);
    if (newHeight % Header.RETARGET_INTERVAL == 0 and newHeight >= Header.RETARGET_INTERVAL) {
      let firstHeight = newHeight - Header.RETARGET_INTERVAL : Nat;
      switch (ancestorAt(self, parent, firstHeight)) {
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

  // ---------------------------------------------------------------------
  // Internal: reorg.
  // ---------------------------------------------------------------------

  // Switch the canonical chain to the heavier branch ending at `newTipHash`
  // if it outweighs the current tip. Returns the number of canonical blocks
  // displaced (0 if no reorg happened).
  func maybeReorg(self : State, newTipHash : Blob, newWork : Nat, now : Int) : Nat {
    if (newWork <= self.tipWork) return 0;

    // 1. Walk the new branch from its tip down to the common ancestor (the
    //    first canonical block we hit). `branch` is tip-first.
    let branch = List.empty<ForkBlock>();
    var curHash = newTipHash;
    var commonHeight : Nat = 0;
    label findCommon loop {
      let fb = switch (ForkStore.get(self.forks, curHash)) {
        case (?x) x;
        case null Runtime.trap("maybeReorg: branch block missing from fork store");
      };
      List.add(branch, fb);
      switch (Headers.lookup(self.headerTrie, fb.prevHash)) {
        case (?(_, idx)) { commonHeight := idx; break findCommon };
        case null curHash := fb.prevHash;
      };
    };

    let oldTipHeight = tipHeight(self);
    let oldTipHash = switch (Headers.get(self.headerTrie, oldTipHeight)) {
      case (?(h, _)) h;
      case null Runtime.trap("maybeReorg: missing old tip");
    };
    let displaced : Nat = oldTipHeight - commonHeight;

    // Bodies: before removing any header, extract each displaced canonical
    // block's transactions (with its F) from the txid trie so they travel with
    // the block into the fork store, then truncate the trie to the common
    // ancestor.
    let demotedBodies = Map.empty<Nat, ForkBody>();
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
        Map.remove<Nat, Nat>(self.txCountOverride, Nat.compare, h);
        h += 1;
      };
      StableTrie.truncate(self.txTrie, truncPoint);
      self.bodiesNextHeight := commonHeight + 1;
    };

    // 2. Roll back the canonical tip into the fork store, one block at a time.
    while (tipHeight(self) > commonHeight) {
      let h = tipHeight(self);
      let (rmHash, rmValue) = switch (Headers.removeLast(self.headerTrie)) {
        case (?x) x;
        case null Runtime.trap("maybeReorg: removeLast on empty trie");
      };
      let prevH = switch (Headers.get(self.headerTrie, h - 1)) {
        case (?(ph, _)) ph;
        case null Runtime.trap("maybeReorg: missing parent of displaced block");
      };
      ForkStore.add(self.forks, {
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
      ForkStore.removeFork(self.forks, fb.hash, fb.height);
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
      // If the promoted block's body is known, re-index it in chain order.
      switch (fb.body) {
        case (?b) if (fb.height == self.bodiesNextHeight) {
          appendCanonicalBody(self, fb.height, value, b.txids);
          self.bodiesNextHeight += 1;
        };
        case null {};
      };
    };

    self.tipWork := newWork;

    List.add(self.reorgLog, {
      time = now;
      common_height = commonHeight;
      fork_length = List.size(branch);
      displaced;
      old_tip_hash_be_hex = bytesToHexBE(oldTipHash);
      old_tip_height = oldTipHeight;
      new_tip_hash_be_hex = bytesToHexBE(newTipHash);
      new_tip_height = tipHeight(self);
    });

    displaced;
  };

  func storeAndMaybeReorg(
    self : State,
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

    Uploaders.record(self.uploaders, hash, uploader);

    var isCanonical = false;
    var reorgDepth : Nat = 0;

    if (parent.isCanonical and parent.height == tipHeight(self)) {
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
      ignore Headers.add(self.headerTrie, hash, value);
      self.tipWork := cumWork;
      isCanonical := true;
    } else {
      ForkStore.add(self.forks, {
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
      hash_be_hex = bytesToHexBE(hash);
      is_canonical = isCanonical;
      reorg_depth = reorgDepth;
    };
  };

  // ---------------------------------------------------------------------
  // Public mutating API.
  // ---------------------------------------------------------------------

  public func push(self : State, raw : Blob, nowSecs : Int, uploader : Principal) : Result.Result<PushOk, Text> {
    if (raw.size() != 80) return #err("header is not 80 bytes");
    let parsed = switch (Header.parseHeader(raw)) {
      case (?p) p;
      case null return #err("could not parse header");
    };
    let hash = Header.headerHashBlob(raw);
    switch (byHashInternal(self, hash)) {
      case (?_) return #err("duplicate: hash already present");
      case null {};
    };
    let parent = switch (byHashInternal(self, parsed.prev_hash)) {
      case (?p) p;
      case null return #err("unknown previous block hash");
    };
    // Reject headers whose timestamp is more than ONE_YEAR_SECS before the
    // current canonical tip's timestamp.
    let tipTimeNat = Nat32.toNat(HeaderValue.timeOf(tipBlock(self).value));
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
    let stamps = lastNTimestamps(self, parent, if (newHeight < 11) newHeight else 11);
    let mtp = Header.medianTimePast(stamps);

    switch (Header.validateAgainst(raw, expectedBits, parsed.prev_hash, mtp, nowSecs)) {
      case (#err msg) return #err(msg);
      case (#ok()) {};
    };
    let firstSeen = nat32OfNowSecs(nowSecs);
    #ok(storeAndMaybeReorg(self, raw, parsed.bits, hash, parent, firstSeen, uploader, nowSecs));
  };

  public func pushUnchecked(self : State, raw : Blob, nowSecs : Int, uploader : Principal) : Result.Result<PushOk, Text> {
    if (raw.size() != 80) return #err("header is not 80 bytes");
    let parsed = switch (Header.parseHeader(raw)) {
      case (?p) p;
      case null return #err("could not parse header");
    };
    let hash = Header.headerHashBlob(raw);
    switch (byHashInternal(self, hash)) {
      case (?_) return #err("duplicate: hash already present");
      case null {};
    };
    let parent = switch (byHashInternal(self, parsed.prev_hash)) {
      case (?p) p;
      case null return #err("unknown previous block hash");
    };
    #ok(storeAndMaybeReorg(self, raw, parsed.bits, hash, parent, nat32OfNowSecs(nowSecs), uploader, nowSecs));
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
    let stamps = lastNTimestamps(self, b, 11);
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

  // Read txids stored in the canonical trie at indices [lo, hi) into a flat
  // blob (moves a demoted block's body into the fork store).
  func extractTxids(self : State, lo : Nat, hi : Nat) : Blob {
    let keys = Array.tabulate<[Nat8]>(
      hi - lo : Nat,
      func(k) = Blob.toArray(
        switch (StableTrie.get(self.txTrie, lo + k)) {
          case (?(key, _)) key;
          case null Runtime.trap("extractTxids: missing txid " # debug_show(lo + k));
        }
      ),
    );
    Blob.fromArray(Array.tabulate<Nat8>((hi - lo : Nat) * 32, func(j) = keys[j / 32][j % 32]));
  };

  // Append one block's body (flat txid blob) to the tail of the canonical txid
  // trie, setting its F and recording a BIP30 override on cross-block dup txids.
  func appendCanonicalBody(self : State, height : Nat, value : Blob, body : Blob) {
    let f = StableTrie.size(self.txTrie);
    Headers.put(self.headerTrie, height, withFirstTxIndex(value, f));
    let n = body.size() / 32;
    let hv = encodeHeight(height);
    var i = 0;
    while (i < n) { ignore StableTrie.add(self.txTrie, txidAt(body, i), hv); i += 1 };
    if (StableTrie.size(self.txTrie) - f < n) Map.add<Nat, Nat>(self.txCountOverride, Nat.compare, height, n);
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

  // tx_count of a canonical block currently indexed in the trie.
  func trieTxCount(self : State, height : Nat) : Nat {
    switch (Map.get<Nat, Nat>(self.txCountOverride, Nat.compare, height)) {
      case (?n) return n;
      case null {};
    };
    let f = switch (Headers.get(self.headerTrie, height)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return 0 };
    let next = if (height + 1 < self.bodiesNextHeight) {
      switch (Headers.get(self.headerTrie, height + 1)) { case (?(_, v)) HeaderValue.firstTxIndexOf(v); case null return 0 };
    } else StableTrie.size(self.txTrie);
    next - f : Nat;
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
  public func pushBody(self : State, blockHashInternal : Blob, txCount : Nat, hashes : Blob) : Result.Result<PushBodyOk, Text> {
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
    if (Merkle.root(hashes, txCount) != HeaderValue.merkleOf(b.value)) return #err("merkle root mismatch");

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
      ForkStore.updateBlock(self.forks, { fb with body = ?{ txids = hashes; firstTxIndex = f } });
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
    initGenesis(s, 0, Principal.fromText("aaaaa-aa"));
    s;
  };

  // A chain anchored at an arbitrary checkpoint header (hex). `keySize` selects
  // the trie key width — pass Headers.KEY_SIZE (28) to exercise the production
  // truncation path with real PoW headers.
  public func fromRootHex(rawHex : Text, keySize : Nat) : State {
    let s = newState(newHeaderTrie(keySize), newTxTrie(TEST_TX_ROOT_ARIDITY));
    initRoot(s, Header.hexToBlob(rawHex), 0, Principal.fromText("aaaaa-aa"));
    s;
  };

};
