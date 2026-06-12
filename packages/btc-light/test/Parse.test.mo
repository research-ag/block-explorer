// Tests for Header.parseHeader and headerHash on the genesis block and
// the first few mainnet headers.

import { test; suite } "mo:test";
import Header "../src/Header";
import F "fixtures/Fixtures";

suite(
  "parseHeader",
  func() {
    test(
      "rejects wrong-size blobs",
      func() {
        assert Header.parseHeader(Header.hexToBlob("")) == null;
        let short = Header.hexToBlob(
          "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b"
        );
        assert Header.parseHeader(short) == null;
        let long = Header.hexToBlob(
          "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c00"
        );
        assert Header.parseHeader(long) == null;
      },
    );

    test(
      "parses genesis header",
      func() {
        let p = switch (Header.parseHeader(Header.hexToBlob(F.H_0))) {
          case (?p) p;
          case null { assert false; return };
        };
        assert p.version == 1;
        // genesis prev_hash is all zeros
        var i = 0;
        while (i < 32) { assert p.prev_hash[i] == 0; i += 1 };
        // bits and timestamp are well known
        assert p.bits == 0x1d00ffff;
        assert p.time == 0x495fab29;
        assert p.nonce == 0x7c2bac1d;
      },
    );

    test(
      "parses header at height 100000",
      func() {
        let p = switch (Header.parseHeader(Header.hexToBlob(F.H_100000))) {
          case (?p) p;
          case null { assert false; return };
        };
        assert p.bits == 0x1b04864c;
        assert p.time == 1293623863;
      },
    );
  },
);
