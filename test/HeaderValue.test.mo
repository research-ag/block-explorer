import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";

import HeaderValue "../src/block_explorer/HeaderValue";

func mkMerkle(byte : Nat8) : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func _ = byte));

suite(
  "HeaderValue: round-trip encode/decode",
  func() {

    test(
      "genesis-like fields round-trip",
      func() {
        let f : HeaderValue.Fields = {
          version = 1;
          firstTxIndex = 0;
          merkle = mkMerkle(0xab);
          time = 1_231_006_505;
          bits = 0x1d00ffff;
          nonce = 2_083_236_893;
          height = 0;
          cumWork = 4_295_032_833;
          firstSeen = 1_700_000_000;
        };
        let blob = HeaderValue.encode(f);
        assert blob.size() == HeaderValue.SIZE;
        let g = HeaderValue.decode(blob);
        assert g.version == f.version;
        assert g.firstTxIndex == f.firstTxIndex;
        assert g.merkle == f.merkle;
        assert g.time == f.time;
        assert g.bits == f.bits;
        assert g.nonce == f.nonce;
        assert g.height == f.height;
        assert g.cumWork == f.cumWork;
        assert g.firstSeen == f.firstSeen;
      },
    );

    test(
      "large 128-bit cumWork round-trips",
      func() {
        // 2^120 + 12345
        let big : Nat = 1329227995784915872903807060280344576 + 12345;
        let f : HeaderValue.Fields = {
          version = 0x20000000;
          firstTxIndex = 4_294_967_294; // near Nat32 max
          merkle = mkMerkle(0xff);
          time = 0xffff_fffe;
          bits = 0x1d00ffff;
          nonce = 0x12345678;
          height = 999_999;
          cumWork = big;
          firstSeen = 0xffff_ffff;
        };
        let blob = HeaderValue.encode(f);
        let g = HeaderValue.decode(blob);
        assert g.cumWork == big;
        assert g.firstTxIndex == f.firstTxIndex;
        assert g.height == f.height;
      },
    );
  },
);

suite(
  "HeaderValue: narrow accessors",
  func() {

    test(
      "read fields directly without decode",
      func() {
        let f : HeaderValue.Fields = {
          version = 0xdeadbeef;
          firstTxIndex = 42;
          merkle = mkMerkle(0x77);
          time = 1_700_000_000;
          bits = 0x1c0f_ffff;
          nonce = 0xcafebabe;
          height = 850_000;
          cumWork = 0x123456789abcdef;
          firstSeen = 1_762_000_123;
        };
        let blob = HeaderValue.encode(f);
        assert HeaderValue.versionOf(blob) == f.version;
        assert HeaderValue.firstTxIndexOf(blob) == f.firstTxIndex;
        assert HeaderValue.timeOf(blob) == f.time;
        assert HeaderValue.bitsOf(blob) == f.bits;
        assert HeaderValue.nonceOf(blob) == f.nonce;
        assert HeaderValue.heightOf(blob) == f.height;
        assert HeaderValue.cumWorkOf(blob) == f.cumWork;
        assert HeaderValue.merkleOf(blob) == f.merkle;
        assert HeaderValue.firstSeenOf(blob) == f.firstSeen;
      },
    );
  },
);
