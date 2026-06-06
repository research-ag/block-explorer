// Bitcoin block-header chain with full reorg support.
//
// Layered storage
// ---------------
//   Layer 1 (stable):  HeaderDb         hash -> 76-byte value
//                      via mo:stable-trie Enumeration (assigns dbidx).
//   Layer 2 (stable):  CanonChain       height -> dbidx of canonical
//                      block at that height (Region of Nat32 slots).
//   Layer 3 (heap, EOP-stable):
//     siblings      : Map<Nat,[Nat]> height -> non-canonical dbidxs
//                                   (canonical block at that height
//                                   is excluded).
//     forkTips      : Set<Nat>      non-canonical leaf dbidxs.
//
// The class itself is `transient` in the actor (it owns a HeaderDb
// instance which holds heap-side bookkeeping for the trie); persistence
// goes through `share()`/`unshare()`.
//
// Hash convention
// ---------------
// Internally everything is in Bitcoin "internal" little-endian order.
// Big-endian (display) hex is only used at API boundaries.

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

import CanonChain "CanonChain";
import Header "Header";
import HeaderDb "HeaderDb";
import HeaderValue "HeaderValue";

module {

  // ---------------------------------------------------------------------
  // Public types.
  // ---------------------------------------------------------------------

  // A "stored block" view returned by queries. Built on demand from the
  // HeaderDb entry; not persisted in this shape.
  public type StoredBlock = {
    dbidx : Nat;
    hash : Blob; // internal LE order, 32 bytes
    value : Blob; // 72-byte HeaderValue blob
    height : Nat;
    parentDbidx : Nat; // 0 == "no parent" (only genesis)
    cumWork : Nat;
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

  public type StableData = {
    headerDb : HeaderDb.StableData;
    canonChain : CanonChain.StableData;
    tipWork : Nat;
    siblings : Map.Map<Nat, [Nat]>;
    forkTips : Set.Set<Nat>;
    uploaderPrincipals : List.List<Principal>;
    uploaderOfDbidx : List.List<Nat>;
  };

  // ---------------------------------------------------------------------
  // Helpers (module-local).
  // ---------------------------------------------------------------------

  func bytesToHexBE(b : Blob) : Text {
    Header.bytesToHex(Header.reverse32(b));
  };

  // 32-byte all-zero blob (genesis prev_hash).  Literal form so it
  // qualifies as a static module-level constant.
  let ZERO_HASH_BLOB : Blob = "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00";

  // Clamp an Int seconds-since-epoch into a Nat32 for storage as the
  // `firstSeen` field. Negative values become 0 (only matters in tests
  // where Time.now() can be 0); values past 2106 wrap, but the canister
  // won't be running by then.
  func nat32OfNowSecs(s : Int) : Nat32 {
    if (s <= 0) 0 else Nat32.fromNat(Int.abs(s) % 0x1_0000_0000);
  };

  // One year in seconds (365 days = 31_536_000). Used for the freshness
  // check on newly pushed headers.
  let ONE_YEAR_SECS : Nat = 31_536_000;

  // Extract the byte at little-endian position `i` (0..3) from a Nat32.
  func le32Byte(v : Nat32, i : Nat) : Nat8 {
    Nat8.fromNat(Nat32.toNat((v >> (Nat32.fromNat(i) * 8)) & 0xff));
  };

  // ---------------------------------------------------------------------
  // Chain class.
  // ---------------------------------------------------------------------

  public class Chain() {

    let headerDb : HeaderDb.HeaderDb = HeaderDb.HeaderDb();
    let canonChain : CanonChain.CanonChain = CanonChain.CanonChain();
    var tipWork : Nat = 0;
    var siblings : Map.Map<Nat, [Nat]> = Map.empty<Nat, [Nat]>();
    var forkTips : Set.Set<Nat> = Set.empty<Nat>();
    // Uploader bookkeeping: each principal that has ever pushed a header
    // is recorded once in `uploaderPrincipals`. Its position in that list
    // is the uploader index. `uploaderOfDbidx` is parallel to the
    // HeaderDb: position `dbidx` holds the uploader index for the block
    // stored at that dbidx.
    var uploaderPrincipals : List.List<Principal> = List.empty<Principal>();
    var uploaderOfDbidx : List.List<Nat> = List.empty<Nat>();
    // Heap-only, parallel to `uploaderPrincipals`: position `i` holds
    // a record `{principal; blocks}` where `blocks` is the list of
    // dbidxs uploaded by that principal in chronological (push) order.
    // For the anonymous principal we deliberately keep `blocks` empty
    // (its block list would dominate storage) and count its pushes in
    // `anonymousCount` instead. Both are rebuilt in `unshare` from
    // `uploaderPrincipals` + `uploaderOfDbidx`.
    var uploaders : List.List<{ principal : Principal; blocks : List.List<Nat> }> =
      List.empty<{ principal : Principal; blocks : List.List<Nat> }>();
    var anonymousCount : Nat = 0;
    var initialized : Bool = false;

    // Rebuild `uploaders` and `anonymousCount` from
    // `uploaderPrincipals` + `uploaderOfDbidx`. O(n) on the header-DB
    // size; called from `unshare` so the heap-only views are restored
    // after every upgrade.
    func rebuildUploaders() {
      uploaders := List.empty<{ principal : Principal; blocks : List.List<Nat> }>();
      anonymousCount := 0;
      for (p in List.values<Principal>(uploaderPrincipals)) {
        List.add(uploaders, { principal = p; blocks = List.empty<Nat>() });
      };
      var dbidx : Nat = 0;
      for (uIdx in List.values<Nat>(uploaderOfDbidx)) {
        let e = switch (List.get(uploaders, uIdx)) {
          case (?e) e;
          case null Runtime.trap(
            "rebuildUploaders: dbidx " # debug_show dbidx #
            " references missing uploader index " # debug_show uIdx
          );
        };
        if (Principal.isAnonymous(e.principal)) {
          anonymousCount += 1;
        } else {
          List.add(e.blocks, dbidx);
        };
        dbidx += 1;
      };
    };

    // -----------------------------------------------------------------
    // Initialization / persistence.
    // -----------------------------------------------------------------

    // Insert the Bitcoin mainnet genesis header at dbidx 0.
    // Idempotent: no-op if already initialized. `firstSeenSecs` is the
    // canister's wall-clock time when genesis was inserted (used as the
    // genesis block's `firstSeen`).
    public func initGenesis(firstSeenSecs : Nat32, uploader : Principal) {
      if (initialized) return;
      let raw = Header.hexToBlob(Header.GENESIS_HEADER_HEX);
      let parsed = switch (Header.parseHeader(raw)) {
        case (?p) p;
        case null Runtime.trap("genesis header invalid");
      };
      let hash = Header.headerHashBlob(raw);
      let work = Header.chainWork(parsed.bits);
      let value = HeaderValue.encode({
        version = parsed.version;
        parentDbidx = 0; // genesis is its own "parent"
        merkle = parsed.merkle;
        time = parsed.time;
        bits = parsed.bits;
        nonce = parsed.nonce;
        height = 0;
        cumWork = work;
        firstSeen = firstSeenSecs;
      });
      let dbidx = headerDb.add(hash, value);
      assert dbidx == 0;
      recordUploader(dbidx, uploader);
      canonChain.add(0);
      tipWork := work;
      initialized := true;
    };

    public func share() : StableData = {
      headerDb = headerDb.share();
      canonChain = canonChain.share();
      tipWork;
      siblings;
      forkTips;
      uploaderPrincipals;
      uploaderOfDbidx;
    };

    public func unshare(d : StableData) {
      headerDb.unshare(d.headerDb);
      canonChain.unshare(d.canonChain);
      tipWork := d.tipWork;
      siblings := d.siblings;
      forkTips := d.forkTips;
      uploaderPrincipals := d.uploaderPrincipals;
      uploaderOfDbidx := d.uploaderOfDbidx;
      rebuildUploaders();
      initialized := true;
    };

    // -----------------------------------------------------------------
    // Internal helpers.
    // -----------------------------------------------------------------

    // canonHeight = highest populated slot.
    func canonHeight() : Nat = canonChain.size() - 1 : Nat;

    func readCanonSlot(h : Nat) : Nat = canonChain.at(h);

    // Append the canonical dbidx for the next height (canonHeight+1).
    func appendCanon(dbidx : Nat) = canonChain.add(dbidx);

    // Truncate canonChain to a new top height (inclusive).
    func truncCanon(newTop : Nat) {
      while (canonChain.size() > newTop + 1) {
        canonChain.removeLast();
      };
    };

    func storedAt(dbidx : Nat) : StoredBlock {
      switch (headerDb.get(dbidx)) {
        case (?(hash, value)) {
          {
            dbidx;
            hash;
            value;
            height = HeaderValue.heightOf(value);
            parentDbidx = HeaderValue.parentDbidxOf(value);
            cumWork = HeaderValue.cumWorkOf(value);
          };
        };
        case null Runtime.trap("HeaderDb missing dbidx " # debug_show dbidx);
      };
    };

    // Look up the uploader index for `p`, walking the principals list
    // from the start. Append `p` if not yet present and return its new
    // index. O(n) on the number of distinct uploaders, as requested.
    func findOrAddUploaderIndex(p : Principal) : Nat {
      switch (List.indexOf<Principal>(uploaderPrincipals, Principal.equal, p)) {
        case (?i) i;
        case null {
          let i = List.size(uploaderPrincipals);
          List.add(uploaderPrincipals, p);
          List.add(uploaders, { principal = p; blocks = List.empty<Nat>() });
          i;
        };
      };
    };

    // Record a header push at `dbidx` by `uploader`. Updates the
    // heap-only `uploaders` / `anonymousCount` views in lock-step with
    // the stable `uploaderOfDbidx` so a follow-up `share`/`unshare`
    // cycle reproduces the same state.
    //
    // Invariant: `uploaderOfDbidx` is parallel to the HeaderDb, so the
    // next slot to fill is always at position `List.size(uploaderOfDbidx)`
    // and must equal `dbidx`. Trap if that ever drifts.
    func recordUploader(dbidx : Nat, uploader : Principal) {
      if (List.size(uploaderOfDbidx) != dbidx) {
        Runtime.trap(
          "recordUploader: uploaderOfDbidx size " #
          debug_show List.size(uploaderOfDbidx) #
          " != dbidx " # debug_show dbidx
        );
      };
      let uIdx = findOrAddUploaderIndex(uploader);
      List.add(uploaderOfDbidx, uIdx);
      appendBlockToUploader(uIdx, dbidx);
    };

    // Bump the heap-side bookkeeping for uploader index `uIdx` after
    // it pushed the header at `dbidx`. Anonymous principals only
    // increment `anonymousCount`; everyone else gets `dbidx` appended
    // to their per-uploader block list.
    func appendBlockToUploader(uIdx : Nat, dbidx : Nat) {
      let e = switch (List.get(uploaders, uIdx)) {
        case (?e) e;
        case null Runtime.trap(
          "appendBlockToUploader: missing uploader index " # debug_show uIdx
        );
      };
      if (Principal.isAnonymous(e.principal)) {
        anonymousCount += 1;
      } else {
        List.add(e.blocks, dbidx);
      };
    };

    func ancestorAt(startDbidx : Nat, targetHeight : Nat) : ?Nat {
      var idx = startDbidx;
      loop {
        let value = switch (headerDb.get(idx)) {
          case (?(_, v)) v;
          case null return null;
        };
        let h = HeaderValue.heightOf(value);
        if (h == targetHeight) return ?idx;
        if (h < targetHeight) return null;
        if (h == 0) return null;
        idx := HeaderValue.parentDbidxOf(value);
      };
    };

    func lastNTimestamps(startDbidx : Nat, n : Nat) : [Nat32] {
      let buf = List.empty<Nat32>();
      var idx = startDbidx;
      var i = 0;
      label loop_ loop {
        if (i >= n) break loop_;
        let value = switch (headerDb.get(idx)) {
          case (?(_, v)) v;
          case null break loop_;
        };
        buf.add(HeaderValue.timeOf(value));
        i += 1;
        let h = HeaderValue.heightOf(value);
        if (h == 0) break loop_;
        idx := HeaderValue.parentDbidxOf(value);
      };
      buf.toArray();
    };

    func expectedBitsFor(parentDbidx : Nat, newHeight : Nat) : Nat32 {
      let parent = storedAt(parentDbidx);
      let parentBits = HeaderValue.bitsOf(parent.value);
      if (
        newHeight % Header.RETARGET_INTERVAL == 0 and newHeight >= Header.RETARGET_INTERVAL
      ) {
        let firstHeight = newHeight - Header.RETARGET_INTERVAL : Nat;
        switch (ancestorAt(parentDbidx, firstHeight)) {
          case (?firstIdx) {
            let first = storedAt(firstIdx);
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

    func addSibling(h : Nat, dbidx : Nat) {
      let cur : [Nat] = switch (Map.get<Nat, [Nat]>(siblings, Nat.compare, h)) {
        case (?xs) xs;
        case null [];
      };
      let next = Array.tabulate<Nat>(
        cur.size() + 1,
        func(i) = if (i < cur.size()) cur[i] else dbidx,
      );
      Map.add<Nat, [Nat]>(siblings, Nat.compare, h, next);
    };

    func removeSibling(h : Nat, dbidx : Nat) {
      switch (Map.get<Nat, [Nat]>(siblings, Nat.compare, h)) {
        case null {};
        case (?xs) {
          let kept = Array.filter<Nat>(xs, func(x) = x != dbidx);
          if (kept.size() == 0) {
            Map.remove<Nat, [Nat]>(siblings, Nat.compare, h);
          } else {
            Map.add<Nat, [Nat]>(siblings, Nat.compare, h, kept);
          };
        };
      };
    };

    // Switch canonical chain to `newDbidx` if it has more work.
    // Returns the number of canonical blocks displaced (0 if no reorg).
    func maybeReorg(newDbidx : Nat, newWork : Nat) : Nat {
      if (newWork <= tipWork) return 0;

      let curTip = canonHeight();
      var idx = newDbidx;
      let newBranch = List.empty<Nat>();
      label findCommon loop {
        let s = storedAt(idx);
        if (s.height <= curTip and readCanonSlot(s.height) == idx) {
          break findCommon;
        };
        newBranch.add(idx);
        if (s.height == 0) Runtime.trap("reorg: walked past genesis");
        idx := s.parentDbidx;
      };
      let forkHeight = storedAt(idx).height;
      let oldTipDbidx = readCanonSlot(curTip);
      let droppedCount : Nat = curTip - forkHeight;

      // Demote displaced canonical blocks to siblings.
      var h = forkHeight + 1;
      while (h <= curTip) {
        let demoted = readCanonSlot(h);
        addSibling(h, demoted);
        h += 1;
      };
      truncCanon(forkHeight);

      // Promote new-branch blocks (newBranch is tip-first; replay
      // forwards from common ancestor up to the new tip).
      var k = newBranch.size();
      while (k > 0) {
        k -= 1;
        let promoted = newBranch.at(k);
        appendCanon(promoted);
        removeSibling(canonHeight(), promoted);
      };

      tipWork := newWork;

      Set.add<Nat>(forkTips, Nat.compare, oldTipDbidx);
      Set.remove<Nat>(forkTips, Nat.compare, newDbidx);

      droppedCount;
    };

    func storeAndMaybeReorg(
      raw : Blob,
      bits : Nat32,
      hash : Blob,
      parentDbidx : Nat,
      firstSeenSecs : Nat32,
      uploader : Principal,
    ) : PushOk {
      let parent = storedAt(parentDbidx);
      let newHeight = parent.height + 1;
      let cumWork = parent.cumWork + Header.chainWork(bits);

      let parsed = switch (Header.parseHeader(raw)) {
        case (?p) p;
        case null Runtime.trap("storeAndMaybeReorg: unparseable header");
      };

      let value = HeaderValue.encode({
        version = parsed.version;
        parentDbidx;
        merkle = parsed.merkle;
        time = parsed.time;
        bits = parsed.bits;
        nonce = parsed.nonce;
        height = newHeight;
        cumWork;
        firstSeen = firstSeenSecs;
      });
      let dbidx = headerDb.add(hash, value);
      recordUploader(dbidx, uploader);

      var isCanonical = false;
      var reorgDepth : Nat = 0;

      let curTip = canonHeight();
      let parentIsCanonTip = parent.height == curTip and readCanonSlot(curTip) == parentDbidx;

      if (parentIsCanonTip) {
        appendCanon(dbidx);
        tipWork := cumWork;
        isCanonical := true;
      } else {
        addSibling(newHeight, dbidx);
        Set.add<Nat>(forkTips, Nat.compare, dbidx);
        Set.remove<Nat>(forkTips, Nat.compare, parentDbidx);
        reorgDepth := maybeReorg(dbidx, cumWork);
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
      switch (headerDb.lookup(hash)) {
        case (?_) return #err("duplicate: hash already present");
        case null {};
      };
      let parentDbidx = switch (headerDb.lookup(parsed.prev_hash)) {
        case (?(_, idx)) idx;
        case null return #err("unknown previous block hash");
      };
      // Reject headers whose timestamp is more than ONE_YEAR_SECS
      // before the current canonical tip's timestamp. This blocks
      // "after-the-fact" forks built off ancient history while still
      // accepting genuinely fresh forks observed near the chain tip.
      let tipTimeNat = Nat32.toNat(HeaderValue.timeOf(tipBlock().value));
      let parsedTimeNat = Nat32.toNat(parsed.time);
      if (parsedTimeNat + ONE_YEAR_SECS < tipTimeNat) {
        return #err(
          "header timestamp " # debug_show parsedTimeNat #
          " is more than 1 year before current tip timestamp " #
          debug_show tipTimeNat
        );
      };
      let parent = storedAt(parentDbidx);
      let newHeight = parent.height + 1;

      let expectedBits = expectedBitsFor(parentDbidx, newHeight);
      let stamps = lastNTimestamps(
        parentDbidx,
        if (parent.height + 1 < 11) parent.height + 1 else 11,
      );
      let mtp = Header.medianTimePast(stamps);

      switch (
        Header.validateAgainst(
          raw,
          expectedBits,
          parsed.prev_hash,
          mtp,
          nowSecs,
        )
      ) {
        case (#err msg) return #err(msg);
        case (#ok()) {};
      };
      let firstSeen = nat32OfNowSecs(nowSecs);
      #ok(storeAndMaybeReorg(raw, parsed.bits, hash, parentDbidx, firstSeen, uploader));
    };

    public func pushUnchecked(raw : Blob, nowSecs : Int, uploader : Principal) : Result.Result<PushOk, Text> {
      if (raw.size() != 80) return #err("header is not 80 bytes");
      let parsed = switch (Header.parseHeader(raw)) {
        case (?p) p;
        case null return #err("could not parse header");
      };
      let hash = Header.headerHashBlob(raw);
      switch (headerDb.lookup(hash)) {
        case (?_) return #err("duplicate: hash already present");
        case null {};
      };
      let parentDbidx = switch (headerDb.lookup(parsed.prev_hash)) {
        case (?(_, idx)) idx;
        case null return #err("unknown previous block hash");
      };
      #ok(storeAndMaybeReorg(raw, parsed.bits, hash, parentDbidx, nat32OfNowSecs(nowSecs), uploader));
    };

    // -----------------------------------------------------------------
    // Public queries.
    // -----------------------------------------------------------------

    public func size() : Nat = headerDb.size();

    public func memoryStats() : HeaderDb.MemoryStats = headerDb.memoryStats();

    public func tipHeight() : Nat = canonHeight();

    public func tipBlock() : StoredBlock = storedAt(readCanonSlot(canonHeight()));

    public func canonicalAt(height : Nat) : ?StoredBlock {
      if (height > canonHeight()) null else ?storedAt(readCanonSlot(height));
    };

    public func allAt(height : Nat) : [StoredBlock] {
      let out = List.empty<StoredBlock>();
      if (height <= canonHeight()) {
        out.add(storedAt(readCanonSlot(height)));
      };
      switch (Map.get<Nat, [Nat]>(siblings, Nat.compare, height)) {
        case null {};
        case (?xs) for (i in xs.vals()) out.add(storedAt(i));
      };
      out.toArray();
    };

    public func byHashBE(hex : Text) : ?StoredBlock {
      let bytes = Header.hexToBlob(hex);
      if (bytes.size() != 32) return null;
      let internal = Header.reverse32(bytes);
      switch (headerDb.lookup(internal)) {
        case (?(_, idx)) ?storedAt(idx);
        case null null;
      };
    };

    // Cheap membership check: avoids decoding the 76-byte stored value.
    public func hasHashBE(hex : Text) : Bool {
      let bytes = Header.hexToBlob(hex);
      if (bytes.size() != 32) return false;
      let internal = Header.reverse32(bytes);
      switch (headerDb.lookup(internal)) {
        case (?_) true;
        case null false;
      };
    };

    // Resolve the uploader principal for a stored block (via dbidx).
    // Traps if no entry is recorded for `dbidx` — this should be
    // unreachable since `uploaderOfDbidx` is grown in lockstep with
    // `headerDb.add` (see recordUploader).
    public func uploaderOf(dbidx : Nat) : Principal {
      let uIdx = switch (List.get<Nat>(uploaderOfDbidx, dbidx)) {
        case (?i) i;
        case null Runtime.trap(
          "uploaderOf: no uploader recorded for dbidx " # debug_show dbidx
        );
      };
      switch (List.get<Principal>(uploaderPrincipals, uIdx)) {
        case (?p) p;
        case null Runtime.trap(
          "uploaderOf: uploader index " # debug_show uIdx #
          " out of range (dbidx " # debug_show dbidx # ")"
        );
      };
    };

    // Snapshot of (uploader, headers-pushed) for every distinct
    // uploader the chain has ever seen, in registration order. The
    // caller is responsible for sorting / truncating to a leaderboard.
    // For anonymous, the count comes from `anonymousCount` since we
    // intentionally don't store its block list.
    public func uploaderStats() : [(Principal, Nat)] {
      let arr = List.toArray(uploaders);
      Array.tabulate<(Principal, Nat)>(
        arr.size(),
        func(i) {
          let e = arr[i];
          let count = if (Principal.isAnonymous(e.principal)) {
            anonymousCount;
          } else {
            List.size(e.blocks);
          };
          (e.principal, count);
        },
      );
    };

    // Page through the dbidxs uploaded by `p`, newest first. Returns
    // up to `limit` entries starting at `offset` (0 = newest).
    // Anonymous returns []: we don't track its blocks individually.
    public func blocksByUploader(p : Principal, offset : Nat, limit : Nat) : [Nat] {
      if (Principal.isAnonymous(p) or limit == 0) return [];
      let uIdx = switch (List.indexOf<Principal>(uploaderPrincipals, Principal.equal, p)) {
        case (?i) i;
        case null return [];
      };
      let e = switch (List.get(uploaders, uIdx)) {
        case (?e) e;
        case null return [];
      };
      let n = List.size(e.blocks);
      if (offset >= n) return [];
      let remaining : Nat = n - offset;
      let take = if (limit < remaining) limit else remaining;
      Array.tabulate<Nat>(
        take,
        func(k) {
          let pos : Nat = n - 1 - offset - k;
          switch (List.get(e.blocks, pos)) {
            case (?dbidx) dbidx;
            case null Runtime.trap("blocksByUploader: index out of range");
          };
        },
      );
    };

    public func byHashInternal(hash : Blob) : ?StoredBlock {
      if (hash.size() != 32) return null;
      switch (headerDb.lookup(hash)) {
        case (?(_, idx)) ?storedAt(idx);
        case null null;
      };
    };

    public func byDbidx(dbidx : Nat) : ?StoredBlock {
      switch (headerDb.get(dbidx)) {
        case (?_) ?storedAt(dbidx);
        case null null;
      };
    };

    // Bitcoin-Core "median time past": median of the timestamps of `b`
    // and its 10 ancestors (11 values total, fewer near genesis).
    public func mediantimeOf(b : StoredBlock) : Nat32 {
      let stamps = lastNTimestamps(b.dbidx, 11);
      let sorted = Array.sort<Nat32>(stamps, Nat32.compare);
      sorted[sorted.size() / 2];
    };

    // Reconstruct the canonical 80-byte raw header from stored data.
    // Layout: version | prev_hash (LE) | merkle (LE) | time | bits | nonce.
    public func rawHeaderOf(b : StoredBlock) : Blob {
      let v = b.value;
      let version = HeaderValue.versionOf(v);
      let time = HeaderValue.timeOf(v);
      let bits = HeaderValue.bitsOf(v);
      let nonce = HeaderValue.nonceOf(v);
      let prev = prevHashOf(b);
      let merkle = HeaderValue.merkleOf(v);
      let prevA = Blob.toArray(prev);
      let merkleA = Blob.toArray(merkle);
      let buf = Array.tabulate<Nat8>(
        80,
        func(i) {
          if (i < 4) le32Byte(version, i) else if (i < 36) prevA[i - 4 : Nat] else if (i < 68) merkleA[i - 36 : Nat] else if (i < 72) le32Byte(time, i - 68 : Nat) else if (i < 76) le32Byte(bits, i - 72 : Nat) else le32Byte(nonce, i - 76 : Nat);
        },
      );
      Blob.fromArray(buf);
    };

    // Canonical block at height `h+1`, if any. Used by the Esplora
    // `/block/:hash/status` endpoint as `next_best` for canonical
    // blocks (per spec, this field is only set when in_best_chain).
    public func canonicalChildOf(b : StoredBlock) : ?StoredBlock {
      canonicalAt(b.height + 1);
    };

    public func isOnCanonical(b : StoredBlock) : Bool {
      if (b.height > canonHeight()) return false;
      readCanonSlot(b.height) == b.dbidx;
    };

    public func forks() : [Fork] {
      let out = List.empty<Fork>();
      for (i in Set.values(forkTips)) {
        let tip = storedAt(i);
        var idx = i;
        var length : Nat = 0;
        label walk loop {
          let s = storedAt(idx);
          if (s.height <= canonHeight() and readCanonSlot(s.height) == idx) {
            break walk;
          };
          length += 1;
          if (s.height == 0) Runtime.trap("fork: walked past genesis");
          idx := s.parentDbidx;
        };
        let bp = storedAt(idx);
        out.add({
          tip_height = tip.height;
          tip_hash_be_hex = bytesToHexBE(tip.hash);
          length;
          branch_height = bp.height;
          branch_hash_be_hex = bytesToHexBE(bp.hash);
        });
      };
      out.toArray();
    };

    // Look up the parent's hash (internal LE order). Returns the
    // 32-byte zero hash for genesis (matching the raw header).
    public func prevHashOf(b : StoredBlock) : Blob {
      if (b.height == 0) return ZERO_HASH_BLOB;
      switch (headerDb.get(b.parentDbidx)) {
        case (?(h, _)) h;
        case null Runtime.trap("missing parent for dbidx " # debug_show b.dbidx);
      };
    };
  };

  // ---------------------------------------------------------------------
  // Convenience: fresh chain seeded with genesis.
  // ---------------------------------------------------------------------

  public func empty() : Chain {
    let c = Chain();
    c.initGenesis(0, Principal.fromText("aaaaa-aa"));
    c;
  };

};
