// End-to-end validation tests on the pure validateAgainst.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Result "mo:core/Result";

import Sha256 "mo:sha2/Sha256";
import Header "../src/Header";
import F "fixtures/Fixtures";

let SHA = Sha256.new(#sha256);

ignore Nat8.toNat;

let FUTURE_NOW : Int = 9_999_999_999; // year ~2286, well past any fixture

func parsedAt(hex : Text) : Header.Parsed {
  switch (Header.parseHeader(Header.hexToBlob(hex))) {
    case (?p) p;
    case null { assert false; loop {} };
  };
};

func isOk(r : Result.Result<(), Text>) : Bool {
  switch r { case (#ok()) true; case (#err _) false };
};

let chainHex : [Text] = [
  F.H_0,
  F.H_1,
  F.H_2,
  F.H_3,
  F.H_4,
  F.H_5,
  F.H_6,
  F.H_7,
  F.H_8,
  F.H_9,
  F.H_10,
];

suite(
  "validateAgainst",
  func() {
    test(
      "first 10 mainnet headers all validate",
      func() {
        var height = 1;
        while (height < chainHex.size()) {
          let prevP = parsedAt(chainHex[height - 1]);
          let prevHash = Header.headerHashBlob(SHA, Header.hexToBlob(chainHex[height - 1]));
          // collect last up-to-11 timestamps before `height`
          let n : Nat = if (height < 11) height else 11;
          let buf = Array.tabulate<Nat32>(
            n,
            func(i) {
              parsedAt(chainHex[height - 1 - i]).time;
            },
          );
          let mtp = Header.medianTimePast(buf);
          let r = Header.validateAgainst(
            Header.hexToBlob(chainHex[height]),
            prevP.bits, // no retargets in first 10 blocks
            prevHash,
            mtp,
            FUTURE_NOW,
          );
          assert isOk(r);
          height += 1;
        };
      },
    );

    test(
      "mutated nonce fails proof-of-work",
      func() {
        let bs = Blob.toArray(Header.hexToBlob(F.H_5));
        let mutated = Array.tabulate<Nat8>(
          80,
          func(i) {
            if (i == 79) bs[i] ^ 0xff else bs[i];
          },
        );
        let prevP = parsedAt(F.H_4);
        let prevHash = Header.headerHashBlob(SHA, Header.hexToBlob(F.H_4));
        let r = Header.validateAgainst(
          Blob.fromArray(mutated),
          prevP.bits,
          prevHash,
          0,
          FUTURE_NOW,
        );
        assert not isOk(r);
      },
    );

    test(
      "wrong prev_hash fails continuity",
      func() {
        let prevP = parsedAt(F.H_4);
        let bogusHash = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = 0xaa));
        let r = Header.validateAgainst(
          Header.hexToBlob(F.H_5),
          prevP.bits,
          bogusHash,
          0,
          FUTURE_NOW,
        );
        assert not isOk(r);
      },
    );

    test(
      "future-drift rejection",
      func() {
        let prevP = parsedAt(F.H_0);
        let prevHash = Header.headerHashBlob(SHA, Header.hexToBlob(F.H_0));
        // Block 1's timestamp is in 2009.  If "now" is in 2008 (well before
        // block 1's time + 2h drift window), future-drift must reject.
        let r = Header.validateAgainst(
          Header.hexToBlob(F.H_1),
          prevP.bits,
          prevHash,
          0, // mtp
          1_200_000_000, // nowSecs ~ 2008
        );
        assert not isOk(r);
      },
    );

    test(
      "MTP rejection (header time <= mtp)",
      func() {
        let prevP = parsedAt(F.H_4);
        let prevHash = Header.headerHashBlob(SHA, Header.hexToBlob(F.H_4));
        let h5 = parsedAt(F.H_5);
        let r = Header.validateAgainst(
          Header.hexToBlob(F.H_5),
          prevP.bits,
          prevHash,
          h5.time, // mtp == header.time -> rejected (must be strictly >)
          FUTURE_NOW,
        );
        assert not isOk(r);
      },
    );
  },
);
