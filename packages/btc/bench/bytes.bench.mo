// Benchmarks for the byte helpers (src/Bytes).
//
// Rows are operations; columns are batch sizes. Inputs come from a real
// 80-byte header blob: readLE32 pulls the 4-byte timestamp, slice32 carves a
// 32-byte window out of it.

import Array "mo:core/Array";
import Bench "mo:bench-helper";

import Header "../src/Header";
import Bytes "../src/Bytes";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "Byte helpers";
      description = "readLE32 and slice32 over a header blob, batched";
      rows = ["readLE32", "slice32"];
      cols = ["1", "100"];
    };

    let header : Blob = Header.hexToBlob(Header.GENESIS_HEADER_HEX);
    let counts : [Nat] = [1, 100];

    func runReadLE32(n : Nat) {
      var i = 0;
      while (i < n) { ignore Bytes.readLE32(header, 68); i += 1 };
    };
    func runSlice32(n : Nat) {
      var i = 0;
      while (i < n) { ignore Bytes.slice32(header, 36); i += 1 };
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
              case _ (func() = runSlice32(n));
            };
          },
        );
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
