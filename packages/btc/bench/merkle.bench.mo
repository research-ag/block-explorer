// Benchmark for merkle-root construction.
//
// One row (root); columns are tx counts. Each column feeds Merkle.root
// `count` distinct 32-byte leaves, so the per-call cost tracks the O(n)
// hashing work as the block fills up.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Bench "mo:bench-helper";

import Merkle "../src/Merkle";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "Merkle root";
      description = "Merkle.root over 1, 16, 256 and 2048 distinct 32-byte leaves";
      rows = ["root"];
      cols = ["1", "16", "256", "2048"];
    };

    let counts : [Nat] = [1, 16, 256, 2048];

    // txids[ci]: `counts[ci]` distinct 32-byte leaves. Each byte derived
    // from a global index so no two leaves within a column collide.
    let txids : [[Blob]] = Array.map<Nat, [Blob]>(
      counts,
      func(n) = Array.tabulate<Blob>(
        n,
        func(i) = Blob.fromArray(
          Array.tabulate<Nat8>(32, func(j) = Nat8.fromIntWrap(i * 32 + j))
        ),
      ),
    );

    let routines : [() -> ()] = Array.tabulate<() -> ()>(
      schema.cols.size(),
      func(ci) = func() = ignore Merkle.root(txids[ci]),
    );

    Bench.V1(schema, func(_ri : Nat, ci : Nat) = routines[ci]());
  };
};
