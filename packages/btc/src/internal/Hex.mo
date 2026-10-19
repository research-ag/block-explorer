// Generic hex encode/decode — nothing Bitcoin-specific.
// Internal to the `btc` package; not part of its public API.

import Blob "mo:core/Blob";
import Char "mo:core/Char";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import VarArray "mo:core/VarArray";

module {

  // Lowercase hex alphabet as ASCII bytes — hex Text is built as a byte
  // buffer and decoded once (per-char Char.toText + `#=` measured ~5 KB
  // per 32-byte hash; this is ~0.3 KB).
  let CHARS : Blob = "0123456789abcdef";

  // Reverse table for decode: ASCII byte -> hex nibble, 0xff for any non-hex
  // byte. Indexed directly by the char code (`c.toNat32().toNat()`), so it is
  // sparse — bytes 0x00..0x2f are 0xff filler, the price of an offset-free
  // index. Codes above 'f' (0x66) run off the end and trap as out-of-range.
  // A `Blob` (1 byte/entry, indexed like the table it is) rather than a
  // 103-element `[Nat8]` (4 bytes/entry, and the formatter splits it one
  // element per line). Layout: 48x ff, '0'-'9' = 00..09, 7x ff, 'A'-'F' =
  // 0a..0f, 26x ff, 'a'-'f' = 0a..0f.
  let NIBBLE : Blob = "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\00\01\02\03\04\05\06\07\08\09\ff\ff\ff\ff\ff\ff\ff\0a\0b\0c\0d\0e\0f\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\0a\0b\0c\0d\0e\0f";

  // Decode a hex string to bytes. Traps on odd length or non-hex chars.
  // Streams the chars (materializing them via Iter.toArray costs ~12 KB per
  // 80-byte header), so this stays a sequential fill rather than a tabulate.
  // The per-char nibble is a direct table lookup (inlined — one caller).
  public func decode(t : Text) : Blob {
    let size = t.size();
    if (size % 2 != 0) Runtime.trap("odd-length hex");
    let mut = VarArray.repeat<Nat8>(0, size / 2);
    var i = 0;
    var hi : Nat8 = 0;
    var haveHi = false;
    for (c in t.chars()) {
      let nib = NIBBLE[c.toNat32().toNat()];
      if (nib == 0xff) Runtime.trap("invalid hex char");
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

  // Lowercase-hex encode a byte sequence: emit ASCII into one buffer, decode
  // once. Each output nibble is a Nat8 shift/mask of the source byte indexing
  // CHARS — no Nat div/mod. A byte-streaming fill (not a tabulate): with two
  // outputs per input, tabulating over output positions would reintroduce a
  // per-element j/2, j%2 Nat div/mod that costs more than the saved zero-init.
  public func encode(bs : Blob) : Text {
    let mut = VarArray.repeat<Nat8>(0, bs.size() * 2);
    var i = 0;
    for (b in bs.vals()) {
      mut[i] := CHARS[(b >> 4).toNat()];
      mut[i + 1] := CHARS[(b & 0x0f).toNat()];
      i += 2;
    };
    switch (Text.decodeUtf8(Blob.fromVarArray(mut))) {
      case (?t) t;
      case null Runtime.trap("Hex.encode: unreachable (pure ASCII)");
    };
  };

  // 8-char big-endian hex of a Nat32. Emit the most-significant nibble each
  // step, then shift it out — a running shift register avoids recomputing a
  // `28 - j*4` shift amount (and masking) per iteration. A loop, not a
  // tabulate: a closure capturing `v` would add per-call GC for no gain.
  public func encodeNat32(v : Nat32) : Text {
    let mut = VarArray.repeat<Nat8>(0, 8);
    var x = v;
    var j = 0;
    while (j < 8) {
      mut[j] := CHARS[(x >> 28).toNat()]; // top nibble (already 0..15)
      x <<= 4;
      j += 1;
    };
    switch (Text.decodeUtf8(Blob.fromVarArray(mut))) {
      case (?t) t;
      case null Runtime.trap("Hex.encodeNat32: unreachable (pure ASCII)");
    };
  };

};
