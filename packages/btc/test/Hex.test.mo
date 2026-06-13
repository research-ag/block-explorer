// Round-trip and edge-case tests for hex helpers.

import { test; suite } "mo:test";
import Header "../src/Header";
import Hex "../src/internal/Hex";

suite(
  "Hex helpers",
  func() {
    test(
      "hexToBlob round-trips bytesToHex",
      func() {
        let samples = [
          "",
          "00",
          "ff",
          "deadbeef",
          "0123456789abcdef",
        ];
        for (s in samples.vals()) {
          let blob = Header.hexToBlob(s);
          let back = Header.bytesToHex(blob);
          assert back == s;
        };
      },
    );

    test(
      "hexToBlob accepts uppercase",
      func() {
        let lower = Header.hexToBlob("deadbeef");
        let upper = Header.hexToBlob("DEADBEEF");
        assert lower == upper;
      },
    );

    test(
      "nat32Hex pads to 8 chars",
      func() {
        assert Hex.encodeNat32(0) == "00000000";
        assert Hex.encodeNat32(0x1d00ffff) == "1d00ffff";
        assert Hex.encodeNat32(0xffffffff) == "ffffffff";
        assert Hex.encodeNat32(0x1) == "00000001";
      },
    );
  },
);
