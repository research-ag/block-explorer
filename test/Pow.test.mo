// Tests for proof-of-work check.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Result "mo:core/Result";

import Sha256 "mo:sha2/Sha256";
import Header "../src/block_explorer/Header";
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
