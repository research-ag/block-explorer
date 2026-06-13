// Benchmark for merkle-root construction.
//
// One row (root); columns are tx counts. Each column feeds Merkle.root a
// concatenated blob of `count` distinct 32-byte leaves, so the per-call cost
// tracks the O(n) hashing work as the block fills up.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Bench "mo:bench-helper";
import Sha256 "mo:sha2/Sha256";

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
    let sha = Sha256.Digest(#sha256);

    // hashes[ci]: `counts[ci]` leaves concatenated; each leaf byte derived from
    // its index so no two leaves collide.
    let hashes : [Blob] = Array.map<Nat, Blob>(
      counts,
      func(n) = Blob.fromArray(Array.tabulate<Nat8>(n * 32, func(i) = Nat8.fromIntWrap(i))),
    );

    let routines : [() -> ()] = Array.tabulate<() -> ()>(
      schema.cols.size(),
      func(ci) = func() = ignore Merkle.root(sha, hashes[ci], counts[ci]),
    );

    Bench.V1(schema, func(_ri : Nat, ci : Nat) = routines[ci]());
  };
};
