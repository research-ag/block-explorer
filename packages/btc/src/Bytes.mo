// Generic byte / little-endian helpers — nothing Bitcoin-specific, but a
// public part of the `btc` package API: consumers that mirror raw headers in
// their own storage (e.g. a block-explorer's value layout) reuse these.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";

module {

  // Read a little-endian uint32 directly from a Blob at `offset` (no copy).
  // Widen each byte Nat8 -> Nat16 -> Nat32 explicitly: both hops are `let`
  // Prim aliases (nat8ToNat16 / nat16ToNat32), so this lowers to two raw prim
  // conversions with no wrapper call — unlike `Nat8.toNat32`, a `func` that
  // wraps the same two hops, or `Nat32.fromNat`, which detours through Nat.
  public func readLE32(b : Blob, offset : Nat) : Nat32 {
    b[offset].toNat16().toNat32() | b[offset + 1].toNat16().toNat32() << 8 | b[offset + 2].toNat16().toNat32() << 16 | b[offset + 3].toNat16().toNat32() << 24;
  };

  // Write a little-endian uint32 into `buf` at `offset` (4 bytes). Narrow each
  // byte Nat32 -> Nat16 -> Nat8 via `let` Prim aliases (no Nat detour, no
  // non-inlined Nat32.toNat8 wrapper); the masked value always fits in Nat8.
  public func writeLE32(buf : [var Nat8], offset : Nat, v : Nat32) {
    buf[offset] := (v & 0xff).toNat16().toNat8();
    buf[offset + 1] := ((v >> 8) & 0xff).toNat16().toNat8();
    buf[offset + 2] := ((v >> 16) & 0xff).toNat16().toNat8();
    buf[offset + 3] := (v >> 24).toNat16().toNat8();
  };

  // Copy 32 bytes out of a Blob at `offset` into a fresh Blob.
  public func slice32(b : Blob, offset : Nat) : Blob {
    Blob.fromArray(Array.tabulate<Nat8>(32, func(i) = b[offset + i]));
  };

};
