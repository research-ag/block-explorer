// The Bitcoin Merkle root the explorer computes with the mmr package
// (`Bitcoin.merkleRoot`, and `Bitcoin.mutated` for CVE-2012-2459), against
// well-known mainnet vectors. All hashes here are written in BIG-endian
// order (the way block explorers display them) and reversed to internal
// little-endian before being passed to `Bitcoin.merkleRoot`, which operates
// on the on-the-wire byte order.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";

import Header "mo:btc/Header";
import Bitcoin "mo:mmr/Bitcoin";

// Decode BE-hex hashes to the internal-LE `[Blob]` shape `Bitcoin.merkleRoot` consumes.
func leTxids(beHexes : [Text]) : [Blob] =
  Array.map<Text, Blob>(beHexes, func(h) = Header.reverse32(Header.hexToBlob(h)));

// Distinct synthetic 32-byte leaf: every byte is `k`.
func leaf(k : Nat) : Blob = Blob.fromVarArray(VarArray.repeat<Nat8>(Nat8.fromNat(k % 256), 32));

func leaves(ks : [Nat]) : [Blob] = Array.map<Nat, Blob>(ks, leaf);

func cat(a : Blob, b : Blob) : Blob {
  let x = a.toArray();
  let y = b.toArray();
  Blob.fromArray(Array.tabulate<Nat8>(x.size() + y.size(), func(i) = if (i < x.size()) x[i] else y[i - x.size()]));
};

func dSha(b : Blob) : Blob {
  let d = Sha256.new(#sha256);
  d.writeBlob(b);
  d.sumDouble();
};

// Root via the incremental API, which (unlike Bitcoin.merkleRoot) does not
// run the mutation check, so it can show that a mutated list shares the real
// root.
func uncheckedRoot(txids : [Blob]) : Blob {
  let tree = Bitcoin.new(txids.size());
  for (t in txids.values()) tree.add(t);
  tree.root();
};

// Run Bitcoin.merkleRoot and compare its output (LE) to the expected
// big-endian hex.
func rootBE(beHexes : [Text]) : Text {
  let r = Bitcoin.merkleRoot(leTxids(beHexes));
  Header.bytesToHex(Header.reverse32(r));
};

suite(
  "Bitcoin.merkleRoot",
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
        // Three distinct leaves A, B, C. Bitcoin pairs the odd last node
        // with itself: root = dSHA(dSHA(A||B) || dSHA(C||C)). (Identical
        // leaves no longer work here: Bitcoin.merkleRoot traps on them as a
        // mutated list.)
        let a = leaf(1);
        let b = leaf(2);
        let c = leaf(3);
        assert Bitcoin.merkleRoot([a, b, c]) == dSha(cat(dSha(cat(a, b)), dSha(cat(c, c))));
      },
    );
  },
);

suite(
  "Bitcoin.mutated (CVE-2012-2459)",
  func() {

    test(
      "genuine lists of distinct txids pass, 1 to 40 leaves",
      func() {
        var n = 1;
        while (n <= 40) {
          assert not Bitcoin.mutated(leaves(Array.tabulate<Nat>(n, func(i) = i + 1)));
          n += 1;
        };
      },
    );

    test(
      "duplicated tails share the real root and are flagged",
      func() {
        // (real, mutated) pairs: the mutated list
        // ends with a second copy, complete or cut off, of the subtree
        // before it on some level.
        let cases : [([Nat], [Nat])] = [
          ([1, 2, 3], [1, 2, 3, 3]),
          ([1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 6, 5, 6]),
          ([1, 2, 3, 4, 5], [1, 2, 3, 4, 5, 5, 5]),
          ([1, 2, 3, 4, 5], [1, 2, 3, 4, 5, 5]),
        ];
        for ((real, mut) in cases.values()) {
          assert uncheckedRoot(leaves(mut)) == uncheckedRoot(leaves(real));
          assert Bitcoin.merkleRoot(leaves(real)) == uncheckedRoot(leaves(real));
          assert not Bitcoin.mutated(leaves(real));
          assert Bitcoin.mutated(leaves(mut));
        };
      },
    );
  },
);
