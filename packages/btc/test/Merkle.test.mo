// Tests for Bitcoin merkle-root computation against well-known
// mainnet vectors. All hashes here are written in BIG-endian order
// (the way block explorers display them) and reversed to internal
// little-endian before being passed to `Merkle.root`, which operates
// on the on-the-wire byte order.

import { test; suite } "mo:test";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import VarArray "mo:core/VarArray";

import Header "../src/Header";
import Sha256 "mo:sha2/Sha256";
import Merkle "../src/Merkle";

let SHA = Sha256.Digest(#sha256);

// Pack BE-hex hashes into a single flat LE-byte hashes blob, the
// shape that `Merkle.root` consumes.
func leBlob(beHexes : [Text]) : Blob {
  let n = beHexes.size();
  let out = VarArray.repeat<Nat8>(0, n * 32);
  var i = 0;
  while (i < n) {
    let le = Header.reverse32(Header.hexToBlob(beHexes[i]));
    var j = 0;
    while (j < 32) { out[i * 32 + j] := le[j]; j += 1 };
    i += 1;
  };
  Blob.fromVarArray(out);
};

// Run Merkle.root and compare its output (LE) to the expected
// big-endian hex.
func rootBE(beHexes : [Text]) : Text {
  let r = Merkle.root(SHA, leBlob(beHexes), beHexes.size());
  Header.bytesToHex(Header.reverse32(r));
};

suite(
  "Merkle.root",
  func() {

    test(
      "1-tx block (genesis): root == coinbase txid",
      func() {
        // Genesis block has a single transaction; its txid IS the
        // merkle root.
        let coinbaseBE = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        assert rootBE([coinbaseBE]) == coinbaseBE;
      },
    );

    test(
      "2-tx block 170 (first ever non-coinbase tx)",
      func() {
        let txids = [
          "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082", // coinbase
          "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
        ];
        let expected = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff";
        assert rootBE(txids) == expected;
      },
    );

    test(
      "3-tx synthetic (odd-count duplicate-last rule)",
      func() {
        // Synthetic vector: three identical leaves H = 0x00..00.
        // With Bitcoin's "duplicate the last node on odd levels"
        // rule the tree collapses to:
        //   L1 = [ sha256d(H||H), sha256d(H||H) ]
        //   root = sha256d(L1[0] || L1[1])
        // i.e. it must equal Merkle.root(SHA, [H,H,H,H], 4) for the same
        // four-leaf tree of all-zero hashes. This exercises the
        // odd-count code path.
        let zero96 = Blob.fromVarArray(VarArray.repeat<Nat8>(0, 96));
        let zero128 = Blob.fromVarArray(VarArray.repeat<Nat8>(0, 128));
        assert Merkle.root(SHA, zero96, 3) == Merkle.root(SHA, zero128, 4);
      },
    );
  },
);
