// Benchmarks for the internal byte/little-endian helpers (src/internal/Bytes).
//
// Rows are operations; columns are batch sizes. Inputs come from a real
// 80-byte header blob: readLE32 pulls the 4-byte timestamp, slice32 carves a
// 32-byte window, leToNat assembles a full 256-bit little-endian integer.

import Array "mo:core/Array";
import Bench "mo:bench-helper";

import Header "../src/Header";
import Bytes "../src/internal/Bytes";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "Internal byte helpers";
      description = "readLE32, slice32 and leToNat over a header blob, batched";
      rows = ["readLE32", "slice32", "leToNat"];
      cols = ["1", "100"];
    };

    let header : Blob = Header.hexToBlob(Header.GENESIS_HEADER_HEX);
    let hash : Blob = Bytes.slice32(header, 36); // 32-byte merkle field
    let counts : [Nat] = [1, 100];

    func runReadLE32(n : Nat) {
      var i = 0;
      while (i < n) { ignore Bytes.readLE32(header, 68); i += 1 };
    };
    func runSlice32(n : Nat) {
      var i = 0;
      while (i < n) { ignore Bytes.slice32(header, 36); i += 1 };
    };
    func runLeToNat(n : Nat) {
      var i = 0;
      while (i < n) { ignore Bytes.leToNat(hash); i += 1 };
    };

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      schema.rows.size(),
      func(ri) {
        Array.tabulate<() -> ()>(
          schema.cols.size(),
          func(ci) {
            let n = counts[ci];
            switch (ri) {
              case 0 (func() = runReadLE32(n));
              case 1 (func() = runSlice32(n));
              case _ (func() = runLeToNat(n));
            };
          },
        );
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
