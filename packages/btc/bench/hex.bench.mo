// Benchmarks for the internal hex helpers (src/internal/Hex).
//
// Rows are operations; columns are batch sizes. decode parses a 64-char hex
// string into a 32-byte blob, encode does the inverse, encodeNat32 formats a
// 4-byte value as its 8-char hex (used by the difficulty display path).

import Array "mo:core/Array";
import Bench "mo:bench-helper";

import Hex "../src/internal/Hex";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "Internal hex helpers";
      description = "decode, encode and encodeNat32 over a 32-byte value, batched";
      rows = ["decode", "encode", "encodeNat32"];
      cols = ["1", "100"];
    };

    let hexText : Text = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";
    let blob : Blob = Hex.decode(hexText);
    let nbits : Nat32 = 0x1d00ffff;
    let counts : [Nat] = [1, 100];

    func runDecode(n : Nat) {
      var i = 0;
      while (i < n) { ignore Hex.decode(hexText); i += 1 };
    };
    func runEncode(n : Nat) {
      var i = 0;
      while (i < n) { ignore Hex.encode(blob); i += 1 };
    };
    func runEncodeNat32(n : Nat) {
      var i = 0;
      while (i < n) { ignore Hex.encodeNat32(nbits); i += 1 };
    };

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      schema.rows.size(),
      func(ri) {
        Array.tabulate<() -> ()>(
          schema.cols.size(),
          func(ci) {
            let n = counts[ci];
            switch (ri) {
              case 0 (func() = runDecode(n));
              case 1 (func() = runEncode(n));
              case _ (func() = runEncodeNat32(n));
            };
          },
        );
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
