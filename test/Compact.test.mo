// nBits <-> target round-trip, against well-known historical values.

import { test; suite } "mo:test";
import Header "../src/block_explorer/Header";

suite(
  "Compact (nBits) format",
  func() {
    test(
      "nBitsToTarget(0x1d00ffff) is the mainnet POW limit",
      func() {
        let t = Header.nBitsToTarget(0x1d00ffff);
        // 0x00000000FFFF0000_00000000_00000000_00000000_00000000_00000000_00000000
        assert t == 0x00000000_FFFF0000_00000000_00000000_00000000_00000000_00000000_00000000;
        assert t == Header.POW_LIMIT_TARGET;
      },
    );

    test(
      "targetToNBits round-trips known values",
      func() {
        let bits = [
          0x1d00ffff : Nat32,
          0x1c0d3142 : Nat32,
          0x1b04864c : Nat32, // block 100000
          0x1b0404cb : Nat32,
          0x180696bf : Nat32,
        ];
        for (b in bits.vals()) {
          let t = Header.nBitsToTarget(b);
          let b2 = Header.targetToNBits(t);
          assert b == b2;
        };
      },
    );

    test(
      "targetToNBits(0) == 0",
      func() {
        assert Header.targetToNBits(0) == 0;
      },
    );

    test(
      "mantissa-overflow normalization",
      func() {
        // Choose a target that, when expressed at exponent N, has a top byte
        // >= 0x80; targetToNBits must shift right and bump the exponent.
        // target = 0x008000_00 (24-bit value with top bit set after shift)
        // Actually use: 2^23 = 0x800000.  nBits = 0x04008000 (exp=4, mant=0x008000)
        // because mantissa would be 0x800000 which has the sign bit; normalize.
        let t : Nat = 0x800000;
        let bits = Header.targetToNBits(t);
        let t2 = Header.nBitsToTarget(bits);
        assert t == t2;
      },
    );
  },
);
