// Pure helpers for Bitcoin block-header parsing and validation.
// This module contains no actor state and is safe to import from tests.

import Blob "mo:core/Blob";
import Char "mo:core/Char";
import Int "mo:core/Int";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";

module {

  // ---------------------------------------------------------------------
  // Bitcoin mainnet consensus constants.
  // ---------------------------------------------------------------------

  public let RETARGET_INTERVAL : Nat = 2016;
  public let TARGET_TIMESPAN : Nat32 = 1_209_600; // 14 * 24 * 60 * 60 (two weeks)
  public let MAX_FUTURE_SECS : Int = 7_200; // 2 * 60 * 60
  public let POW_LIMIT_NBITS : Nat32 = 0x1d00ffff;

  // Genesis header (height 0) on Bitcoin mainnet, raw 80 bytes hex.
  public let GENESIS_HEADER_HEX : Text = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

  // ---------------------------------------------------------------------
  // Hex helpers.
  // ---------------------------------------------------------------------

  func hexCharAt(n : Nat) : Char {
    // n in [0, 16)
    if (n < 10) Char.fromNat32(0x30 + Nat32.fromNat(n)) else Char.fromNat32(0x61 + Nat32.fromNat(n - 10));
  };

  func hexNibble(c : Char) : Nat8 {
    let n = c.toNat32();
    if (n >= 0x30 and n <= 0x39) Nat8.fromNat((n - 0x30).toNat()) else if (n >= 0x61 and n <= 0x66) Nat8.fromNat((n - 0x61 + 10).toNat()) else if (n >= 0x41 and n <= 0x46) Nat8.fromNat((n - 0x41 + 10).toNat()) else Runtime.trap("invalid hex char");
  };

  public func hexToBlob(t : Text) : Blob {
    let size = t.size();
    if (size % 2 != 0) Runtime.trap("odd-length hex");
    let mut = VarArray.repeat<Nat8>(0, size / 2);
    var i = 0;
    var hi : Nat8 = 0;
    var haveHi = false;
    // Stream the chars — materializing them via Iter.toArray costs ~12 KB
    // per 80-byte header.
    for (c in t.chars()) {
      let nib = hexNibble(c);
      if (haveHi) {
        mut[i] := (hi << 4) | nib;
        i += 1;
        haveHi := false;
      } else {
        hi := nib;
        haveHi := true;
      };
    };
    Blob.fromVarArray(mut);
  };

  // Hex-encode a byte sequence (Blob or [Nat8]).  Cold/display path.
  public func bytesToHex(bs : Blob) : Text {
    var out = "";
    for (b in bs.vals()) {
      let n = b.toNat();
      out #= hexCharAt(n / 16).toText();
      out #= hexCharAt(n % 16).toText();
    };
    out;
  };

  public func nat32Hex(v : Nat32) : Text {
    var out = "";
    var i : Nat = 4;
    while (i > 0) {
      i -= 1;
      let shift = Nat32.fromNat(i) * 8;
      let byte = ((v >> shift) & 0xff).toNat();
      out #= hexCharAt(byte / 16).toText();
      out #= hexCharAt(byte % 16).toText();
    };
    out;
  };

  // ---------------------------------------------------------------------
  // Header parsing.
  // ---------------------------------------------------------------------

  public func readLE32(bs : [Nat8], offset : Nat) : Nat32 {
    let b0 = Nat32.fromNat(bs[offset].toNat());
    let b1 = Nat32.fromNat(bs[offset + 1].toNat());
    let b2 = Nat32.fromNat(bs[offset + 2].toNat());
    let b3 = Nat32.fromNat(bs[offset + 3].toNat());
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  };

  // Same as readLE32 but reads directly from a Blob (no toArray copy).
  public func readLE32Blob(b : Blob, offset : Nat) : Nat32 {
    let b0 = Nat32.fromNat(b[offset].toNat());
    let b1 = Nat32.fromNat(b[offset + 1].toNat());
    let b2 = Nat32.fromNat(b[offset + 2].toNat());
    let b3 = Nat32.fromNat(b[offset + 3].toNat());
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  };

  // Copy 32 bytes out of a Blob into a fresh Blob (used to hold
  // prev_hash and merkle as Blob fields in `Parsed`).  Allocates one
  // 32-byte VarArray and converts it to Blob with no extra copy.
  public func slice32BlobOut(b : Blob, offset : Nat) : Blob {
    let mut = VarArray.repeat<Nat8>(0, 32);
    var i = 0;
    while (i < 32) {
      mut[i] := b[offset + i];
      i += 1;
    };
    Blob.fromVarArray(mut);
  };

  // Narrow accessors for hot validation paths: read a single Nat32
  // field straight out of the raw 80-byte header without allocating
  // anything. Caller must pass a 80-byte blob.
  public func versionOf(raw : Blob) : Nat32 = readLE32Blob(raw, 0);
  public func timeOf(raw : Blob) : Nat32 = readLE32Blob(raw, 68);
  public func bitsOf(raw : Blob) : Nat32 = readLE32Blob(raw, 72);
  public func nonceOf(raw : Blob) : Nat32 = readLE32Blob(raw, 76);

  public type Parsed = {
    version : Nat32;
    prev_hash : Blob; // 32 bytes, internal LE order
    merkle : Blob; // 32 bytes, internal LE order
    time : Nat32;
    bits : Nat32;
    nonce : Nat32;
  };

  public func parseHeader(b : Blob) : ?Parsed {
    if (b.size() != 80) return null;
    ?{
      version = readLE32Blob(b, 0);
      prev_hash = slice32BlobOut(b, 4);
      merkle = slice32BlobOut(b, 36);
      time = readLE32Blob(b, 68);
      bits = readLE32Blob(b, 72);
      nonce = readLE32Blob(b, 76);
    };
  };

  // doubleSHA256 of an 80-byte header, in internal LE order. One Digest,
  // reused via reset() for the second round: constructing a Digest costs
  // ~3.3 KB of heap (object + method closures + buffers), while writing and
  // summing on an existing one is ~0.4 KB.
  public func headerHashBlob(b : Blob) : Blob {
    let d = Sha256.Digest(#sha256);
    d.writeBlob(b);
    let first = d.sum();
    d.reset();
    d.writeBlob(first);
    d.sum();
  };

  // Reverse the byte order of a 32-byte Blob (LE <-> BE display).
  public func reverse32(h : Blob) : Blob {
    let mut = VarArray.repeat<Nat8>(0, 32);
    var i = 0;
    while (i < 32) {
      mut[i] := h[31 - i];
      i += 1;
    };
    Blob.fromVarArray(mut);
  };

  // Removed: bytesEq([Nat8],[Nat8]).  Use Blob equality (==) instead.

  // Interpret a little-endian Blob as a Nat. Assembles via Nat64 limbs:
  // per-byte `acc * 256 + b` allocates a fresh, growing bignum every
  // iteration (~7 KB for 32 bytes); limbs cut that to a handful of ops.
  public func leBytesToNat(h : Blob) : Nat {
    let TWO_POW_64 : Nat = 0x1_0000_0000_0000_0000;
    func limbAt(lo : Nat, width : Nat) : Nat64 {
      var limb : Nat64 = 0;
      var j = lo + width;
      while (j > lo) {
        j -= 1;
        limb := (limb << 8) | Nat64.fromNat(h[j].toNat());
      };
      limb;
    };
    var acc : Nat = 0;
    var i : Nat = h.size();
    let rem = i % 8;
    if (rem > 0) {
      // top (most significant) partial limb first
      acc := Nat64.toNat(limbAt(i - rem, rem));
      i -= rem;
    };
    while (i > 0) {
      acc := acc * TWO_POW_64 + Nat64.toNat(limbAt(i - 8, 8));
      i -= 8;
    };
    acc;
  };

  // ---------------------------------------------------------------------
  // nBits <-> target conversion (Bitcoin "compact" format).
  // ---------------------------------------------------------------------

  func pow256(n : Nat) : Nat {
    var acc : Nat = 1;
    var i = 0;
    while (i < n) { acc *= 256; i += 1 };
    acc;
  };

  public func nBitsToTarget(bits : Nat32) : Nat {
    let exp : Nat = (bits >> 24).toNat();
    let mant : Nat = (bits & 0x007fffff).toNat();
    if (exp <= 3) {
      mant / pow256(3 - exp : Nat);
    } else {
      mant * pow256(exp - 3 : Nat);
    };
  };

  // Encode a target as nBits (compact), matching Bitcoin Core semantics.
  public func targetToNBits(target : Nat) : Nat32 {
    if (target == 0) return 0;
    var size : Nat = 0;
    var t = target;
    while (t > 0) { size += 1; t /= 256 };
    var mant : Nat = if (size <= 3) target * pow256(3 - size : Nat) else target / pow256(size - 3 : Nat);
    if (mant >= 0x00800000) {
      mant /= 256;
      size += 1;
    };
    Nat32.fromNat(((size % 256) * 0x01000000) + (mant % 0x00800000));
  };

  // POW_LIMIT_TARGET = nBitsToTarget(0x1d00ffff)
  //                  = 0x00000000_FFFF0000_00000000_00000000_00000000_00000000_00000000_00000000
  public let POW_LIMIT_TARGET : Nat = 0x00000000_FFFF0000_00000000_00000000_00000000_00000000_00000000_00000000;

  // 2^256.  Used to compute per-block "chainwork".
  public let TWO_POW_256 : Nat = 0x1_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000;

  // Per-block chainwork = floor(2^256 / (target + 1)) (Bitcoin Core formula).
  public func chainWork(bits : Nat32) : Nat {
    let t = nBitsToTarget(bits);
    if (t == 0) 0 else TWO_POW_256 / (t + 1);
  };

  // ---------------------------------------------------------------------
  // Validation primitives. Each one is total and pure: pass in the
  // ancestor data the caller has gathered.
  // ---------------------------------------------------------------------

  // Median of the supplied timestamps (1..11 entries).
  // Caller passes the most recent N timestamps (any order, N <= 11, N >= 1).
  public func medianTimePast(timestamps : [Nat32]) : Nat32 {
    let n = timestamps.size();
    assert n > 0;
    let buf = VarArray.repeat<Nat32>(0, n);
    var i = 0;
    while (i < n) { buf[i] := timestamps[i]; i += 1 };
    var k = 1;
    while (k < n) {
      let key = buf[k];
      var j = k;
      while (j > 0 and buf[j - 1] > key) {
        buf[j] := buf[j - 1];
        j -= 1;
      };
      buf[j] := key;
      k += 1;
    };
    buf[n / 2];
  };

  // Recompute nBits at a retarget boundary.
  // `prevTime`/`prevBits` come from the header at height (h - 1).
  // `firstTime` is the timestamp of the header at height
  //   (h - RETARGET_INTERVAL)  [Satoshi off-by-one].
  public func computeRetargetNBits(
    prevTime : Nat32,
    prevBits : Nat32,
    firstTime : Nat32,
  ) : Nat32 {
    var timespan : Nat32 = if (prevTime >= firstTime) prevTime - firstTime else 0;
    let lower = TARGET_TIMESPAN / 4;
    let upper = TARGET_TIMESPAN * 4;
    if (timespan < lower) timespan := lower;
    if (timespan > upper) timespan := upper;
    let oldTarget = nBitsToTarget(prevBits);
    var newTarget = oldTarget * timespan.toNat() / TARGET_TIMESPAN.toNat();
    if (newTarget > POW_LIMIT_TARGET) newTarget := POW_LIMIT_TARGET;
    targetToNBits(newTarget);
  };

  public func checkContinuity(parsed : Parsed, prevHash : Blob) : Result.Result<(), Text> {
    if (parsed.prev_hash == prevHash) #ok() else #err("prev_block_hash mismatch");
  };

  // PoW check against an already-decoded target (callers with a per-period
  // bits -> target memo avoid re-running nBitsToTarget per header).
  public func checkPoWTarget(headerHashLE : Blob, target : Nat) : Result.Result<(), Text> {
    if (target == 0 or target > POW_LIMIT_TARGET) {
      return #err("nBits out of range");
    };
    if (leBytesToNat(headerHashLE) > target) {
      return #err("proof-of-work failed");
    };
    #ok();
  };

  public func checkPoW(headerHashLE : Blob, bits : Nat32) : Result.Result<(), Text> {
    checkPoWTarget(headerHashLE, nBitsToTarget(bits));
  };

  public func checkBits(actualBits : Nat32, expectedBits : Nat32) : Result.Result<(), Text> {
    if (actualBits == expectedBits) #ok() else #err(
      "nBits mismatch: got 0x" # nat32Hex(actualBits) #
      " expected 0x" # nat32Hex(expectedBits)
    );
  };

  public func checkMTP(parsedTime : Nat32, mtp : Nat32) : Result.Result<(), Text> {
    if (parsedTime > mtp) #ok() else #err("timestamp <= median-time-past");
  };

  public func checkFutureDrift(parsedTime : Nat32, nowSecs : Int) : Result.Result<(), Text> {
    if (Int.fromNat(parsedTime.toNat()) <= nowSecs + MAX_FUTURE_SECS) #ok() else #err("timestamp too far in the future");
  };

  // Full per-header validation against a prepared context.  The caller
  // gathers the ancestor data; this function applies all five rules.
  //
  // `expectedBits` is precomputed by the caller (either prev.bits, or
  // computeRetargetNBits at a 2016-boundary). Takes the already-parsed
  // header, its already-computed hash, and the already-decoded target of
  // parsed.bits, so hot callers don't parse, sha256d, or nBitsToTarget the
  // same header twice.
  public func validateParsed(
    parsed : Parsed,
    headerHashLE : Blob,
    target : Nat, // = nBitsToTarget(parsed.bits)
    expectedBits : Nat32,
    prevHashLE : Blob,
    mtp : Nat32,
    nowSecs : Int,
  ) : Result.Result<(), Text> {
    switch (checkContinuity(parsed, prevHashLE)) {
      case (#err msg) return #err(msg);
      case (#ok()) {};
    };
    switch (checkBits(parsed.bits, expectedBits)) {
      case (#err msg) return #err(msg);
      case (#ok()) {};
    };
    switch (checkPoWTarget(headerHashLE, target)) {
      case (#err msg) return #err(msg);
      case (#ok()) {};
    };
    switch (checkMTP(parsed.time, mtp)) {
      case (#err msg) return #err(msg);
      case (#ok()) {};
    };
    switch (checkFutureDrift(parsed.time, nowSecs)) {
      case (#err msg) return #err(msg);
      case (#ok()) {};
    };
    #ok();
  };

  // Convenience wrapper over `validateParsed` for callers holding only the
  // raw header (parses and hashes it first).
  public func validateAgainst(
    header : Blob,
    expectedBits : Nat32,
    prevHashLE : Blob,
    mtp : Nat32,
    nowSecs : Int,
  ) : Result.Result<(), Text> {
    if (header.size() != 80) return #err("header is not 80 bytes");
    let parsed = switch (parseHeader(header)) {
      case (?p) p;
      case null return #err("could not parse header");
    };
    validateParsed(parsed, headerHashBlob(header), nBitsToTarget(parsed.bits), expectedBits, prevHashLE, mtp, nowSecs);
  };

};
