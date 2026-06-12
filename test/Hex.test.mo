// Round-trip and edge-case tests for hex helpers.

import { test; suite } "mo:test";
import Header "../src/block_explorer/Header";

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
        assert Header.nat32Hex(0) == "00000000";
        assert Header.nat32Hex(0x1d00ffff) == "1d00ffff";
        assert Header.nat32Hex(0xffffffff) == "ffffffff";
        assert Header.nat32Hex(0x1) == "00000001";
      },
    );
  },
);
