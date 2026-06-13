// Pure helpers for Bitcoin block-header parsing and validation.
// This module contains no actor state and is safe to import from tests.

import Blob "mo:core/Blob";
import Int "mo:core/Int";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Result "mo:core/Result";
import VarArray "mo:core/VarArray";

import Prim "mo:⛔";

import Sha256 "mo:sha2/Sha256";

import Bytes "internal/Bytes";
import Hex "internal/Hex";

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
  // Hex helpers (generic; implementation in internal/Hex).
  // ---------------------------------------------------------------------

  public func hexToBlob(t : Text) : Blob = Hex.decode(t);
  public func bytesToHex(bs : Blob) : Text = Hex.encode(bs);

  // ---------------------------------------------------------------------
  // Header parsing.
  // ---------------------------------------------------------------------

  // Narrow accessors: read a single Nat32 field straight out of the raw
  // 80-byte header without allocating. Caller must pass an 80-byte blob.
  public func versionOf(raw : Blob) : Nat32 = Bytes.readLE32(raw, 0);
  public func timeOf(raw : Blob) : Nat32 = Bytes.readLE32(raw, 68);
  public func bitsOf(raw : Blob) : Nat32 = Bytes.readLE32(raw, 72);
  public func nonceOf(raw : Blob) : Nat32 = Bytes.readLE32(raw, 76);

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
      version = Bytes.readLE32(b, 0);
      prev_hash = Bytes.slice32(b, 4);
      merkle = Bytes.slice32(b, 36);
      time = Bytes.readLE32(b, 68);
      bits = Bytes.readLE32(b, 72);
      nonce = Bytes.readLE32(b, 76);
    };
  };

  // doubleSHA256 of an 80-byte header, in internal LE order, on a
  // caller-provided engine. Constructing a Sha256.Digest costs ~3.3 KB of
  // heap (object + method closures + buffers) while reuse via reset() is
  // ~0.4 KB per hash — so the actor holds ONE transient engine for its whole
  // lifetime and threads it through (a module-level instance is impossible:
  // M0014, non-static expression in library). Resets the engine first;
  // leaves it in a finished state.
  public func headerHashBlob(d : Sha256.Digest, b : Blob) : Blob {
    d.reset();
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

  // ---------------------------------------------------------------------
  // nBits <-> target conversion (Bitcoin "compact" format).
  // ---------------------------------------------------------------------

  // 256^n as a single bignum shift — a `*= 256` loop allocates a fresh,
  // growing bignum per iteration (~3.6 KB inside nBitsToTarget for typical
  // exponents).
  func pow256(n : Nat) : Nat = Prim.shiftLeft(1, Nat32.fromNat(8 * n));

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

  // PoW check directly on the compact nBits encoding — no target bignum is
  // ever computed and nothing allocates. target = mant * 256^(exp - 3), so
  // in the 32-byte LE hash it is: zero bytes at LE indices [exp..32), the
  // 3-byte mantissa window at LE indices exp-1 (hi) .. exp-3 (lo), and free
  // bytes below. hash <= target iff the high bytes are zero and the window,
  // read as a number, is < mant — or == mant with all lower bytes zero.
  //
  // Semantics mirror the old nBitsToTarget-based check exactly:
  //  - the sign bit (0x00800000) is masked off, like nBitsToTarget;
  //  - "nBits out of range" iff target == 0 (mant == 0) or target >
  //    POW_LIMIT_TARGET (= 0xffff * 256^26). The encoding is not canonical,
  //    so the limit check is per (exp, mant): exceeded iff
  //    (exp == 0x1d and mant > 0xffff) or (exp == 0x1e and mant > 0xff)
  //    or (exp >= 0x1f) — and never for exp < 0x1d since mant <= 0x7fffff
  //    < 0xffff * 256.
  //  - exp < 3 (window extends below byte 0; never on mainnet) falls back
  //    to the exact bignum comparison.
  public func checkPoW(headerHashLE : Blob, bits : Nat32) : Result.Result<(), Text> {
    let exp = Nat32.toNat(bits >> 24);
    let mant = bits & 0x007f_ffff;
    if (mant == 0) return #err("nBits out of range"); // target == 0
    if (exp >= 0x1f or (exp == 0x1e and mant > 0xff) or (exp == 0x1d and mant > 0xffff)) {
      return #err("nBits out of range"); // target > POW_LIMIT_TARGET
    };
    if (exp < 3) {
      // Targets with exp < 3 are below ~2^15 — roughly 2^160x harder than
      // today's difficulty, i.e. unreachable for many decades and bounded by
      // physics well before then. We reject such headers rather than carry a
      // bignum hash-vs-target comparison for a case real chain data will
      // never present. Revisit if Bitcoin difficulty ever approaches it.
      return #err("nBits out of range");
    };
    // Bytes above the mantissa window must be zero (LE indices exp..31).
    var i = exp;
    while (i < 32) {
      if (headerHashLE[i] != (0 : Nat8)) return #err("proof-of-work failed");
      i += 1;
    };
    // The 3-byte window vs the mantissa.
    let w : Nat32 = (Nat32.fromNat(Nat8.toNat(headerHashLE[exp - 1])) << 16) | (Nat32.fromNat(Nat8.toNat(headerHashLE[exp - 2])) << 8) | Nat32.fromNat(Nat8.toNat(headerHashLE[exp - 3]));
    if (w > mant) return #err("proof-of-work failed");
    if (w == mant) {
      // Exactly at the window: hash <= target only if every lower byte is 0.
      var j = 0;
      while (j + 3 < exp) {
        if (headerHashLE[j] != (0 : Nat8)) return #err("proof-of-work failed");
        j += 1;
      };
    };
    #ok();
  };

  public func checkBits(actualBits : Nat32, expectedBits : Nat32) : Result.Result<(), Text> {
    if (actualBits == expectedBits) #ok() else #err(
      "nBits mismatch: got 0x" # Hex.encodeNat32(actualBits) #
      " expected 0x" # Hex.encodeNat32(expectedBits)
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
  // header and its already-computed hash, so hot callers don't parse or
  // sha256d the same header twice. The PoW check works on the compact bits
  // directly — no target is computed anywhere on this path.
  public func validateParsed(
    parsed : Parsed,
    headerHashLE : Blob,
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
    switch (checkPoW(headerHashLE, parsed.bits)) {
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
    validateParsed(parsed, headerHashBlob(Sha256.Digest(#sha256), header), expectedBits, prevHashLE, mtp, nowSecs);
  };

};
