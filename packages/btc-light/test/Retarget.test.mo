// Tests for difficulty retarget computation.

import { test; suite } "mo:test";
import Header "../src/Header";
import F "fixtures/Fixtures";

func parsed(hex : Text) : Header.Parsed {
  switch (Header.parseHeader(Header.hexToBlob(hex))) {
    case (?p) p;
    case null { assert false; loop {} };
  };
};

suite(
  "computeRetargetNBits",
  func() {
    test(
      "first mainnet retarget at height 2016 yields parent's bits",
      func() {
        // The first 2016 blocks all use 0x1d00ffff and the retarget at 2016
        // produced the same bits (mining was slow enough that the difficulty
        // stayed at the minimum).  This exercises the retarget code path
        // including the [1/4, 4] clamp logic without changing the result.
        let prev = parsed(F.H_2015);
        let first = parsed(F.H_0);
        let actualAt2016 = parsed(F.H_2016).bits;
        let computed = Header.computeRetargetNBits(prev.time, prev.bits, first.time);
        assert computed == actualAt2016;
      },
    );

    test(
      "upper clamp: huge timespan still respects POW limit cap",
      func() {
        // Synthesize: prev.time - first.time = 10 years (way beyond 4x clamp).
        // Old target = POW limit. After clamp+cap we should land on POW limit again.
        assert Header.computeRetargetNBits(
          1_000_000_000,
          Header.POW_LIMIT_NBITS,
          0,
        ) == Header.POW_LIMIT_NBITS;
      },
    );

    test(
      "lower clamp: zero timespan -> target shrinks 4x",
      func() {
        // Use a non-POW-limit bits so the cap doesn't hide the result.
        let bits : Nat32 = 0x1c0d3142;
        let oldTarget = Header.nBitsToTarget(bits);
        let newBits = Header.computeRetargetNBits(0, bits, 0);
        let newTarget = Header.nBitsToTarget(newBits);
        // newTarget should be ~ oldTarget / 4 (allowing for compact-format
        // round-trip loss in the low bits).
        assert newTarget * 4 <= oldTarget;
        assert newTarget * 4 + oldTarget / 1000 >= oldTarget;
      },
    );
  },
);
