// Tests for proof-of-work check.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Result "mo:core/Result";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";
import Header "../src/Header";
import Bytes "../src/internal/Bytes";
import F "fixtures/Fixtures";

let SHA = Sha256.Digest(#sha256);

func isOk<E>(r : Result.Result<(), E>) : Bool {
  switch r { case (#ok()) true; case (#err _) false };
};

suite(
  "checkPoW",
  func() {
    test(
      "genesis header passes",
      func() {
        let blob = Header.hexToBlob(F.H_0);
        let p = switch (Header.parseHeader(blob)) {
          case (?p) p;
          case null { assert false; return };
        };
        let h = Header.headerHashBlob(SHA, blob);
        assert isOk(Header.checkPoW(h, p.bits));
      },
    );

    test(
      "block 100000 passes",
      func() {
        let blob = Header.hexToBlob(F.H_100000);
        let p = switch (Header.parseHeader(blob)) {
          case (?p) p;
          case null { assert false; return };
        };
        let h = Header.headerHashBlob(SHA, blob);
        assert isOk(Header.checkPoW(h, p.bits));
      },
    );

    test(
      "mutated nonce fails",
      func() {
        let bs = Header.hexToBlob(F.H_0).toArray();
        // Flip last byte (high byte of nonce).
        let mutated = Array.tabulate<Nat8>(
          80,
          func(i) {
            if (i == 79) bs[i] ^ 0xff else bs[i];
          },
        );
        let mblob = Blob.fromArray(mutated);
        let p = switch (Header.parseHeader(mblob)) {
          case (?p) p;
          case null { assert false; return };
        };
        let h = Header.headerHashBlob(SHA, mblob);
        assert not isOk(Header.checkPoW(h, p.bits));
      },
    );

    test(
      "nBits = 0 is rejected",
      func() {
        // Hash itself doesn't matter; target=0 path triggers immediately.
        let zeros = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = 0));
        assert not isOk(Header.checkPoW(zeros, 0));
      },
    );
  },
);

// Equivalence of the bits-direct checkPoW against the Nat-based reference.
suite(
  "checkPoW bits-direct equivalence",
  func() {
    func refCheck(h : Blob, bits : Nat32) : Bool {
      let t = Header.nBitsToTarget(bits);
      if (t == 0 or t > Header.POW_LIMIT_TARGET) return false;
      Bytes.leToNat(h) <= t;
    };
    func mkHash(bytes : [(Nat, Nat8)]) : Blob {
      let mut = VarArray.repeat<Nat8>(0, 32);
      for ((i, v) in bytes.vals()) { mut[i] := v };
      Blob.fromVarArray(mut);
    };
    func agree(h : Blob, bits : Nat32) {
      let got = switch (Header.checkPoW(h, bits)) {
        case (#ok()) true;
        case _ false;
      };
      assert got == refCheck(h, bits);
    };
    test(
      "window and boundary vectors agree with Nat reference",
      func() {
        let exp : Nat = 0x18; // window at LE indices 21..23
        let bits : Nat32 = 0x1800_1234 | 0x0000_5600; // exp 0x18, mant 0x125656? build explicitly below
        let b : Nat32 = 0x1812_3456; // exp 0x18, mant 0x123456
        // window == mant, low bytes zero -> pass (hash == target)
        agree(mkHash([(23, 0x12), (22, 0x34), (21, 0x56)]), b);
        // window == mant, a nonzero LOW byte -> fail (hash > target)
        agree(mkHash([(23, 0x12), (22, 0x34), (21, 0x56), (0, 1)]), b);
        // window < mant, junk low bytes -> pass
        agree(mkHash([(23, 0x12), (22, 0x34), (21, 0x55), (5, 0xff), (0, 0xff)]), b);
        // window > mant -> fail
        agree(mkHash([(23, 0x12), (22, 0x34), (21, 0x57)]), b);
        // nonzero byte ABOVE the window -> fail
        agree(mkHash([(24, 1), (23, 0x12)]), b);
        agree(mkHash([(31, 1)]), b);
        // all-zero hash -> pass
        agree(mkHash([]), b);
        ignore bits;
        ignore exp;
      },
    );
    test(
      "range-check vectors agree (canonical and non-canonical encodings)",
      func() {
        let zero = mkHash([]);
        agree(zero, 0x1d00_ffff); // exactly the PoW limit
        agree(zero, 0x1d01_0000); // exp 0x1d, mant > 0xffff -> out of range
        agree(zero, 0x1e00_00ff); // non-canonical, == limit-ish, IN range
        agree(zero, 0x1e00_0100); // exp 0x1e, mant > 0xff -> out of range
        agree(zero, 0x1f00_0001); // exp 0x1f -> out of range
        agree(zero, 0x1800_0000); // mant == 0 -> target 0 -> out of range
        agree(zero, 0x1880_0001); // sign bit set: masked like nBitsToTarget
        agree(mkHash([(20, 1)]), 0x1880_0001);
      },
    );
    test(
      "exp < 3 fallback agrees",
      func() {
        agree(mkHash([]), 0x0200_ffff); // tiny target, zero hash
        agree(mkHash([(0, 1)]), 0x0200_ffff);
        agree(mkHash([(1, 0xff), (0, 0xff)]), 0x0200_ffff);
      },
    );
  },
);
