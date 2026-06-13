// Tests for the double-SHA256 of a header.

import { test; suite } "mo:test";
import Sha256 "mo:sha2/Sha256";
import Header "../src/Header";
import F "fixtures/Fixtures";

let SHA = Sha256.Digest(#sha256);

func hashBE(hex : Text) : Text {
  Header.bytesToHex(Header.reverse32(Header.headerHashBlob(SHA, Header.hexToBlob(hex))));
};

suite(
  "headerHash",
  func() {
    test(
      "genesis hash matches well-known value",
      func() {
        let expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        assert hashBE(F.H_0) == expected;
      },
    );

    test(
      "block 1 hash",
      func() {
        let expected = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
        assert hashBE(F.H_1) == expected;
      },
    );

    test(
      "block 100000 hash",
      func() {
        let expected = "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506";
        assert hashBE(F.H_100000) == expected;
      },
    );
  },
);
