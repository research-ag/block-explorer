// Tests for medianTimePast.

import { test; suite } "mo:test";
import Header "../src/Header";

suite(
  "medianTimePast",
  func() {
    test(
      "single timestamp",
      func() {
        assert Header.medianTimePast([100 : Nat32]) == 100;
      },
    );

    test(
      "three timestamps unsorted",
      func() {
        assert Header.medianTimePast([100 : Nat32, 110, 105]) == 105;
      },
    );

    test(
      "11 timestamps returns 6th smallest",
      func() {
        // {1..11} shuffled -> median (6th smallest) = 6
        let ts : [Nat32] = [7, 3, 11, 1, 9, 5, 6, 8, 2, 10, 4];
        assert Header.medianTimePast(ts) == 6;
      },
    );

    test(
      "4 timestamps -- core picks index n/2 = 2 (3rd smallest)",
      func() {
        // sorted: [10, 20, 30, 40]; index 2 -> 30 (matches Bitcoin Core behavior
        // for small windows: it indexes the upper-middle on even sizes).
        assert Header.medianTimePast([20 : Nat32, 40, 30, 10]) == 30;
      },
    );
  },
);
