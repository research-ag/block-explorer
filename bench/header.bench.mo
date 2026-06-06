// Benchmarks for raw block-header parsing and related primitives.
//
// Rows are operations; columns are batch sizes (how many headers we
// run the operation on per measured call).

import Array "mo:core/Array";
import Bench "mo:bench-helper";

import Header "../src/block_explorer/Header";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "Block-header parsing";
      description = "parseHeader, headerHash, and combined cost on the genesis header replicated N times";
      rows = ["parse", "hash", "parse+hash", "parse+hash+powCheck"];
      cols = ["1", "10", "100"];
    };

    // Single 80-byte input (Bitcoin genesis) reused by every routine.
    let header : Blob = Header.hexToBlob(Header.GENESIS_HEADER_HEX);
    let counts : [Nat] = [1, 10, 100];

    func runParse(n : Nat) {
      var i = 0;
      while (i < n) {
        ignore Header.parseHeader(header);
        i += 1;
      };
    };

    func runHash(n : Nat) {
      var i = 0;
      while (i < n) {
        ignore Header.headerHashBlob(header);
        i += 1;
      };
    };

    func runParseHash(n : Nat) {
      var i = 0;
      while (i < n) {
        ignore Header.parseHeader(header);
        ignore Header.headerHashBlob(header);
        i += 1;
      };
    };

    func runFull(n : Nat) {
      var i = 0;
      while (i < n) {
        switch (Header.parseHeader(header)) {
          case (?p) {
            let h = Header.headerHashBlob(header);
            ignore Header.checkPoW(h, p.bits);
          };
          case null {};
        };
        i += 1;
      };
    };

    // routines[row][col]
    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      schema.rows.size(),
      func(ri) {
        Array.tabulate<() -> ()>(
          schema.cols.size(),
          func(ci) {
            let n = counts[ci];
            switch (ri) {
              case 0 (func() = runParse(n));
              case 1 (func() = runHash(n));
              case 2 (func() = runParseHash(n));
              case _ (func() = runFull(n));
            };
          },
        );
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
