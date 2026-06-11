// 76-byte value blob stored in the canonical header trie.
//
// Layout (all integers little-endian):
//
//   off | bytes | field
//  -----+-------+-----------------------------------------------
//     0 |     4 | version          (Nat32)
//     4 |     4 | firstTxIndex (F) (Nat32)
//     8 |    32 | merkle root      (raw, internal LE order)
//    40 |     4 | time             (Nat32)
//    44 |     4 | bits             (Nat32)
//    48 |     4 | nonce            (Nat32)
//    52 |     4 | height           (Nat32)
//    56 |    16 | cumWork          (Nat128, LE)
//    72 |     4 | first seen       (Nat32, unix seconds; wraps in 2106)
//  -----+-------+
//    76 total
//
// No prev_hash / parent pointer is stored: the trie holds ONLY the
// canonical chain, so the parent of the block at trie index `i` is the
// block at index `i - 1` and prev_hash is that block's key.
//
// firstTxIndex (F) is the 0-based index of this block's first transaction
// in the canonical-chain-wide transaction ordering:
//   F(0) = 0  (genesis)
//   F(h) = F(h-1) + N(h-1)   where N is the block's transaction count.
// It is populated only once the bodies of all preceding blocks are known
// (a later feature). Until then it is the SENTINEL value 0, meaning
// "first-transaction number not yet known" — for any block except genesis,
// whose F is genuinely 0.

import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";

import Prim "mo:⛔";

module {

  public let SIZE : Nat = 76;

  public type Fields = {
    version : Nat32;
    firstTxIndex : Nat; // F; 0 == sentinel "unknown" (except genesis)
    merkle : Blob; // 32 bytes, internal LE order
    time : Nat32;
    bits : Nat32;
    nonce : Nat32;
    height : Nat;
    cumWork : Nat; // fits in 128 bits
    firstSeen : Nat32; // unix seconds when first added to DB
  };

  // ---------------------------------------------------------------------
  // Blob writers (used only at encode time; reads use direct b[i]).
  // ---------------------------------------------------------------------

  func writeLE32(buf : [var Nat8], off : Nat, v : Nat32) {
    buf[off] := Nat8.fromNat((v & 0xff).toNat());
    buf[off + 1] := Nat8.fromNat(((v >> 8) & 0xff).toNat());
    buf[off + 2] := Nat8.fromNat(((v >> 16) & 0xff).toNat());
    buf[off + 3] := Nat8.fromNat(((v >> 24) & 0xff).toNat());
  };

  // Split into two Nat64 limbs WITHOUT bignum division: Nat64.fromIntWrap
  // takes the value mod 2^64 (= the low limb, exact for Nat) and
  // Prim.shiftRight(v, 64) yields the high limb — bignum % and / by 2^64
  // allocate ~0.8 KB of internal temporaries for a 96-bit cumWork, the
  // wrap+shift split doesn't. Then explode each limb into its 8 bytes in
  // one prim call (most-significant byte first); byte extraction is free
  // either way (Nat64 locals are unboxed). Avoid: per-byte `% 256` on a
  // Nat (fresh bignum per iteration, ~12 KB) and Nat32 quarters (measured
  // worse).
  func writeLE128(buf : [var Nat8], off : Nat, v : Nat) {
    let (l7, l6, l5, l4, l3, l2, l1, l0) = Prim.explodeNat64(Nat64.fromIntWrap(v));
    let (h7, h6, h5, h4, h3, h2, h1, h0) = Prim.explodeNat64(Nat64.fromIntWrap(Prim.shiftRight(v, 64)));
    buf[off] := l0; buf[off + 1] := l1; buf[off + 2] := l2; buf[off + 3] := l3;
    buf[off + 4] := l4; buf[off + 5] := l5; buf[off + 6] := l6; buf[off + 7] := l7;
    buf[off + 8] := h0; buf[off + 9] := h1; buf[off + 10] := h2; buf[off + 11] := h3;
    buf[off + 12] := h4; buf[off + 13] := h5; buf[off + 14] := h6; buf[off + 15] := h7;
  };

  func writeBlob32(buf : [var Nat8], off : Nat, b : Blob) {
    var i = 0;
    while (i < 32) {
      buf[off + i] := b[i];
      i += 1;
    };
  };

  // ---------------------------------------------------------------------
  // Blob readers (direct, no toArray).
  // ---------------------------------------------------------------------

  func readLE32(b : Blob, off : Nat) : Nat32 {
    let b0 = Nat32.fromNat(b[off].toNat());
    let b1 = Nat32.fromNat(b[off + 1].toNat());
    let b2 = Nat32.fromNat(b[off + 2].toNat());
    let b3 = Nat32.fromNat(b[off + 3].toNat());
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  };

  // Assemble via two Nat64 limbs (3 bignum ops total) — per-byte
  // `acc * 256 + b` allocates a fresh, growing bignum every iteration.
  func readLE128(b : Blob, off : Nat) : Nat {
    var lo : Nat64 = 0;
    var hi : Nat64 = 0;
    var i = 8;
    while (i > 0) {
      i -= 1;
      lo := (lo << 8) | Nat64.fromNat(b[off + i].toNat());
      hi := (hi << 8) | Nat64.fromNat(b[off + 8 + i].toNat());
    };
    Prim.shiftLeft(Nat64.toNat(hi), 64) + Nat64.toNat(lo);
  };

  // ---------------------------------------------------------------------
  // Encode / decode.
  // ---------------------------------------------------------------------

  public func encode(f : Fields) : Blob {
    let mut = VarArray.repeat<Nat8>(0, SIZE);
    writeLE32(mut, 0, f.version);
    writeLE32(mut, 4, Nat32.fromNat(f.firstTxIndex));
    writeBlob32(mut, 8, f.merkle);
    writeLE32(mut, 40, f.time);
    writeLE32(mut, 44, f.bits);
    writeLE32(mut, 48, f.nonce);
    writeLE32(mut, 52, Nat32.fromNat(f.height));
    writeLE128(mut, 56, f.cumWork);
    writeLE32(mut, 72, f.firstSeen);
    Blob.fromVarArray(mut);
  };

  // Encode straight from the raw 80-byte header: version (raw[0..4)) and
  // the contiguous merkle|time|bits|nonce run (raw[36..80)) are copied as
  // bytes — no parse, no Nat32 round trips. Only the computed fields
  // (firstTxIndex, height, cumWork, firstSeen) are serialized. The value
  // layout was chosen to make these two copies possible.
  public func encodeFromRaw(raw : Blob, firstTxIndex : Nat, height : Nat, cumWork : Nat, firstSeen : Nat32) : Blob {
    let mut = VarArray.repeat<Nat8>(0, SIZE);
    var i = 0;
    while (i < 4) { mut[i] := raw[i]; i += 1 }; // version
    writeLE32(mut, 4, Nat32.fromNat(firstTxIndex));
    var j = 0;
    while (j < 44) { mut[8 + j] := raw[36 + j]; j += 1 }; // merkle|time|bits|nonce
    writeLE32(mut, 52, Nat32.fromNat(height));
    writeLE128(mut, 56, cumWork);
    writeLE32(mut, 72, firstSeen);
    Blob.fromVarArray(mut);
  };

  // Copy of `b` with only firstTxIndex (bytes 4..8) replaced — a byte-level
  // patch, not a decode/re-encode of all nine fields.
  public func withFirstTxIndex(b : Blob, f : Nat) : Blob {
    let mut = VarArray.repeat<Nat8>(0, SIZE);
    var i = 0;
    while (i < SIZE) { mut[i] := b[i]; i += 1 };
    writeLE32(mut, 4, Nat32.fromNat(f));
    Blob.fromVarArray(mut);
  };

  // Slice 32 bytes out of a Blob into a fresh Blob without going via [Nat8].
  func sliceBlob32(b : Blob, off : Nat) : Blob {
    let mut = VarArray.repeat<Nat8>(0, 32);
    var i = 0;
    while (i < 32) {
      mut[i] := b[off + i];
      i += 1;
    };
    Blob.fromVarArray(mut);
  };

  public func decode(b : Blob) : Fields {
    {
      version = readLE32(b, 0);
      firstTxIndex = readLE32(b, 4).toNat();
      merkle = sliceBlob32(b, 8);
      time = readLE32(b, 40);
      bits = readLE32(b, 44);
      nonce = readLE32(b, 48);
      height = readLE32(b, 52).toNat();
      cumWork = readLE128(b, 56);
      firstSeen = readLE32(b, 72);
    };
  };

  // ---------------------------------------------------------------------
  // Narrow accessors — read a single field straight from the value Blob
  // without allocating. Caller must pass a 76-byte blob (SIZE).
  // ---------------------------------------------------------------------

  public func versionOf(b : Blob) : Nat32 = readLE32(b, 0);
  public func firstTxIndexOf(b : Blob) : Nat = readLE32(b, 4).toNat();
  public func timeOf(b : Blob) : Nat32 = readLE32(b, 40);
  public func bitsOf(b : Blob) : Nat32 = readLE32(b, 44);
  public func nonceOf(b : Blob) : Nat32 = readLE32(b, 48);
  public func heightOf(b : Blob) : Nat = readLE32(b, 52).toNat();
  public func cumWorkOf(b : Blob) : Nat = readLE128(b, 56);
  public func firstSeenOf(b : Blob) : Nat32 = readLE32(b, 72);

  // 32-byte merkle root copy (small allocation, only used by /metrics
  // and BlockInfo construction).
  public func merkleOf(b : Blob) : Blob = sliceBlob32(b, 8);

};
