// Generic byte / little-endian helpers — nothing Bitcoin-specific.
// Internal to the `btc` package; not part of its public API.

import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";

import Prim "mo:⛔";

module {

  // Read a little-endian uint32 directly from a Blob at `offset` (no copy).
  public func readLE32(b : Blob, offset : Nat) : Nat32 {
    let b0 = Nat32.fromNat(b[offset].toNat());
    let b1 = Nat32.fromNat(b[offset + 1].toNat());
    let b2 = Nat32.fromNat(b[offset + 2].toNat());
    let b3 = Nat32.fromNat(b[offset + 3].toNat());
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  };

  // Copy 32 bytes out of a Blob at `offset` into a fresh Blob (one VarArray,
  // converted with no extra copy).
  public func slice32(b : Blob, offset : Nat) : Blob {
    let mut = VarArray.repeat<Nat8>(0, 32);
    var i = 0;
    while (i < 32) { mut[i] := b[offset + i]; i += 1 };
    Blob.fromVarArray(mut);
  };

  // Interpret a little-endian Blob as a Nat. Assembles via Nat64 limbs:
  // per-byte `acc * 256 + b` allocates a fresh, growing bignum every
  // iteration (~7 KB for 32 bytes); limbs cut that to a handful of ops.
  // (Nat32 limbs measured WORSE: full-range Nat32 values are heap-boxed
  // just like Nat64 — compact scalars are 31-bit — and halving the limb
  // width doubles the bignum combines.)
  public func leToNat(h : Blob) : Nat {
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
      acc := Prim.shiftLeft(acc, 64) + Nat64.toNat(limbAt(i - 8, 8));
      i -= 8;
    };
    acc;
  };

};
