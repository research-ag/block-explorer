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
  let CHARS : [Nat8] = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66];

  func nibble(c : Char) : Nat8 {
    let n = c.toNat32();
    if (n >= 0x30 and n <= 0x39) Nat8.fromNat((n - 0x30).toNat()) else if (n >= 0x61 and n <= 0x66) Nat8.fromNat((n - 0x61 + 10).toNat()) else if (n >= 0x41 and n <= 0x46) Nat8.fromNat((n - 0x41 + 10).toNat()) else Runtime.trap("invalid hex char");
  };

  // Decode a hex string to bytes. Traps on odd length or non-hex chars.
  public func decode(t : Text) : Blob {
    let size = t.size();
    if (size % 2 != 0) Runtime.trap("odd-length hex");
    let mut = VarArray.repeat<Nat8>(0, size / 2);
    var i = 0;
    var hi : Nat8 = 0;
    var haveHi = false;
    // Stream the chars — materializing them via Iter.toArray costs ~12 KB
    // per 80-byte header.
    for (c in t.chars()) {
      let nib = nibble(c);
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

  // Lowercase-hex encode a byte sequence: emit ASCII into one buffer,
  // decode once.
  public func encode(bs : Blob) : Text {
    let mut = VarArray.repeat<Nat8>(0, bs.size() * 2);
    var i = 0;
    for (b in bs.vals()) {
      let n = b.toNat();
      mut[i] := CHARS[n / 16];
      mut[i + 1] := CHARS[n % 16];
      i += 2;
    };
    switch (Text.decodeUtf8(Blob.fromVarArray(mut))) {
      case (?t) t;
      case null Runtime.trap("Hex.encode: unreachable (pure ASCII)");
    };
  };

  // 8-char big-endian hex of a Nat32.
  public func encodeNat32(v : Nat32) : Text {
    let mut = VarArray.repeat<Nat8>(0, 8);
    var i : Nat = 0;
    while (i < 4) {
      let shift = Nat32.fromNat(3 - i) * 8;
      let byte = ((v >> shift) & 0xff).toNat();
      mut[2 * i] := CHARS[byte / 16];
      mut[2 * i + 1] := CHARS[byte % 16];
      i += 1;
    };
    switch (Text.decodeUtf8(Blob.fromVarArray(mut))) {
      case (?t) t;
      case null Runtime.trap("Hex.encodeNat32: unreachable (pure ASCII)");
    };
  };

};
