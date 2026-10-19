// Benchmarks for the compact-difficulty arithmetic.
//
// Rows are operations; columns are difficulty regimes — genesis (easy,
// small-magnitude target) vs a modern mainnet header (hard, large target).
// The bignum work scales with target magnitude, so the two columns expose how
// the cost moves with difficulty.

import Array "mo:core/Array";
import Bench "mo:bench-helper";

import Header "../src/Header";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "Compact-difficulty math";
      description = "nBitsToTarget, targetToNBits, chainWork and retarget on an easy vs a hard nBits";
      rows = ["nBitsToTarget", "targetToNBits", "chainWork", "computeRetarget"];
      cols = ["genesis", "modern"];
    };

    // Compact targets: genesis (0x1d00ffff) and a 2024-era mainnet block.
    let bits : [Nat32] = [0x1d00ffff, 0x17034219];
    let targets : [Nat] = [Header.nBitsToTarget(bits[0]), Header.nBitsToTarget(bits[1])];
    // Retarget inputs: a full 2016-block span at the lower difficulty bound.
    let prevTime : [Nat32] = [1_296_688_602, 1_700_000_000];
    let firstTime : [Nat32] = [1_295_478_795, 1_698_790_000];

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      schema.rows.size(),
      func(ri) {
        Array.tabulate<() -> ()>(
          schema.cols.size(),
          func(ci) {
            switch (ri) {
              case 0 (func() = ignore Header.nBitsToTarget(bits[ci]));
              case 1 (func() = ignore Header.targetToNBits(targets[ci]));
              case 2 (func() = ignore Header.chainWork(bits[ci]));
              case _ (func() = ignore Header.computeRetargetNBits(prevTime[ci], bits[ci], firstTime[ci]));
            };
          },
        );
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
