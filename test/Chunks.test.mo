// Tests for the chunk verifier of push_body_chunk as the explorer sets it up:
// mmr's Chunks on one tree kept across blocks, without a backup
// (Chunks.onTree(root, tree, null, #copy, true)). Valid chunkings verify and
// complete; a wrong proof, a wrong leaf, a premature last chunk and mutated
// blocks (CVE-2012-2459) are rejected; a chunk rejected after its leaves went
// in breaks the verifier, which is why the canister traps on it; a chunk
// refused before that leaves the verifier usable. Proofs come from mmr's
// Prove.rightPeaks.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Nat "mo:core/Nat";

import Sha256 "mo:sha2/Sha256";

import Bitcoin "mo:mmr/Bitcoin";
import Chunks "mo:mmr/Chunks";
import Peaks "mo:mmr/Peaks";
import Prove "mo:mmr/Prove";

let MAX_DEPTH = 20;

// Distinct leaves: SHA-256 of the index as 4 little-endian bytes.
func txid(i : Nat) : Blob {
  let d = Sha256.new(#sha256);
  d.writeBlob(Array.toBlob([Nat.toNat8(i % 256), Nat.toNat8((i / 256) % 256), 0, 0]));
  d.sum();
};

func txids(n : Nat) : [Blob] = Array.tabulate<Blob>(n, txid);

func slice(a : [Blob], lo : Nat, hi : Nat) : [Blob] = Array.tabulate<Blob>(hi - lo : Nat, func(i) = a[lo + i]);

// The proof for a chunk of `t` that ends at leaf m.
func proofFor(t : [Blob], m : Nat) : [Blob] = Prove.rightPeaks(Bitcoin.levels(t), m);

// The explorer's verifier for the block with root `root`, on `tree`.
func onTree(root : Blob, tree : Peaks.Peaks) : Chunks.Verifier = Chunks.onTree(root, tree, null, #copy, true);

func newTree() : Peaks.Peaks = Peaks.withDepth(MAX_DEPTH, true);

func fresh(root : Blob) : Chunks.Verifier = onTree(root, newTree());

// A verifier for the real list `t`, with the chunks [0, b1), [b1, b2), ...
// accepted. True if they all verified.
func verifierAfter(t : [Blob], bounds : [Nat]) : (Chunks.Verifier, Bool) {
  let v = fresh(Bitcoin.merkleRoot(t));
  var lo = 0;
  for (hi in bounds.values()) {
    if (not v.verifyChunk(slice(t, lo, hi), proofFor(t, hi))) return (v, false);
    lo := hi;
  };
  (v, true);
};

suite(
  "Chunks (onTree, no backup)",
  func() {

    test(
      "a verifier is on maxDepth + 2 hashers, with no backup",
      func() {
        let v = fresh(txid(0));
        assert v.tree.hasher.size() == MAX_DEPTH + 2;
        switch (v.backup) {
          case null {};
          case (?_) assert false;
        };
        assert not v.broken() and v.count() == 0;
      },
    );

    test(
      "one tree serves block after block, whatever it holds",
      func() {
        let tree = newTree();
        // Block A (13 txids) in chunks of 4.
        let a = txids(13);
        let va = onTree(Bitcoin.merkleRoot(a), tree);
        var lo = 0;
        for (hi in [4, 8, 12, 13].values()) {
          assert va.verifyChunk(slice(a, lo, hi), proofFor(a, hi));
          lo := hi;
        };
        assert va.complete();
        // Block B: a rejected chunk leaves the tree half-updated ...
        let b = Array.tabulate<Blob>(9, func(i) = txid(100 + i));
        let bad = onTree(Bitcoin.merkleRoot(b), tree);
        assert bad.verifyChunk(slice(b, 0, 3), proofFor(b, 3));
        assert not bad.verifyChunk(slice(b, 3, 6), proofFor(b, 3));
        assert bad.broken();
        // ... and a new verifier on the same tree still verifies B.
        let vb = onTree(Bitcoin.merkleRoot(b), tree);
        assert vb.count() == 0;
        assert vb.verifyChunk(slice(b, 0, 5), proofFor(b, 5));
        assert vb.verifyChunk(slice(b, 5, 9), []);
        assert vb.complete();
        // Block C (a single txid) in one chunk, and A again.
        let c = [txid(200)];
        assert onTree(Bitcoin.merkleRoot(c), tree).verifyChunk(c, []);
        assert onTree(Bitcoin.merkleRoot(a), tree).verifyChunk(a, []);
      },
    );

    test(
      "every chunking of every list verifies and completes",
      func() {
        for (n in [1, 2, 3, 5, 6, 7, 8, 9, 13, 16, 17, 33].values()) {
          let t = txids(n);
          for (size in [1, 2, 3, 4, 7, n].values()) {
            var bounds : [Nat] = [];
            var hi = size;
            while (hi < n) { bounds := bounds.concat([hi]); hi += size };
            bounds := bounds.concat([n]);
            let (v, ok) = verifierAfter(t, bounds);
            assert ok;
            assert v.complete() and v.count() == n.toNat64();
          };
        };
      },
    );

    test(
      "a wrong proof is rejected",
      func() {
        let t = txids(7);
        let first = slice(t, 0, 3);
        let start = func() : Chunks.Verifier = fresh(Bitcoin.merkleRoot(t));
        // The proof for another boundary.
        assert not start().verifyChunk(first, proofFor(t, 4));
        // An empty proof: a premature last chunk.
        assert not start().verifyChunk(first, []);
        // A proof with its last peak missing, and one with an extra peak.
        let p3 = proofFor(t, 3);
        assert not start().verifyChunk(first, slice(p3, 0, p3.size() - 1 : Nat));
        assert not start().verifyChunk(first, p3.concat([txid(99)]));
        // A later chunk, after a valid prefix.
        let (v, ok) = verifierAfter(t, [3]);
        assert ok;
        assert not v.verifyChunk(slice(t, 3, 5), p3);
      },
    );

    test(
      "a wrong leaf is rejected",
      func() {
        let t = txids(7);
        let p3 = proofFor(t, 3);
        let v = fresh(Bitcoin.merkleRoot(t));
        assert not v.verifyChunk([t[0], txid(40), t[2]], p3);
        let (w, ok) = verifierAfter(t, [3]);
        assert ok;
        assert not w.verifyChunk([txid(40), txid(41)], proofFor(t, 5));
      },
    );

    test(
      "a last chunk must end at the last leaf",
      func() {
        let t = txids(7);
        let (v, ok) = verifierAfter(t, [5]);
        assert ok;
        assert not v.verifyChunk(slice(t, 5, 6), []);
      },
    );

    test(
      "mutated blocks (CVE-2012-2459) are rejected on equal siblings",
      func() {
        // [a, b, c] and [a, b, c, c] share their root.
        let t3 = txids(3);
        let m3 : [Blob] = [t3[0], t3[1], t3[2], t3[2]];
        assert not fresh(Bitcoin.merkleRoot(t3)).verifyChunk(m3, []);
        // The duplicate tail in a last chunk, after a genuine prefix.
        let (v, ok) = verifierAfter(t3, [2]);
        assert ok;
        assert not v.verifyChunk([t3[2], t3[2]], []);
        // A duplicated pair one level up: [a..f] and [a..f, e, f].
        let t6 = txids(6);
        let m6 = t6.concat([t6[4], t6[5]]);
        assert not fresh(Bitcoin.merkleRoot(t6)).verifyChunk(m6, []);
        // A repeated txid elsewhere: [a, a] has no valid root to match, and
        // its equal siblings are caught first.
        let ta : [Blob] = [txid(1), txid(1)];
        assert not fresh(txid(0)).verifyChunk(ta, []);
        // At an odd offset the chunk's first txid is added alone and the
        // rest in pairs. A repeat of the txid before the chunk meets it as
        // the lone txid; the mutated tail [c, c] of [a, b, c] meets itself
        // inside a pair.
        let (w, okw) = verifierAfter(t3, [1]);
        assert okw;
        assert not w.verifyChunk([t3[0], t3[1], t3[2]], []);
        let (x, okx) = verifierAfter(t3, [1]);
        assert okx;
        assert not x.verifyChunk([t3[1], t3[2], t3[2]], []);
      },
    );

    test(
      "a chunk rejected after its leaves went in breaks the verifier: the caller must trap",
      func() {
        let t = txids(7);
        let (v, ok) = verifierAfter(t, [3]);
        assert ok and not v.broken();
        // The wrong proof is rejected after the chunk's leaves went in ...
        assert not v.verifyChunk(slice(t, 3, 5), proofFor(t, 3));
        assert v.broken() and v.count() == 5;
        // ... so the verifier accepts nothing more, the right chunk included.
        assert not v.verifyChunk(slice(t, 3, 5), proofFor(t, 5));
      },
    );

    test(
      "a chunk refused before any leaf is added leaves the verifier usable",
      func() {
        let t = txids(7);
        let (v, ok) = verifierAfter(t, [3]);
        assert ok;
        // An empty chunk, a malformed txid, a malformed proof, and a proof
        // longer than the tree has levels.
        assert not v.verifyChunk([], proofFor(t, 3));
        assert not v.verifyChunk([t[3], "\00"], proofFor(t, 5));
        assert not v.verifyChunk(slice(t, 3, 5), ["\00"]);
        assert not v.verifyChunk(slice(t, 3, 5), Array.tabulate<Blob>(MAX_DEPTH + 1, txid));
        assert not v.broken() and v.count() == 3;
        // The upload goes on.
        assert v.verifyChunk(slice(t, 3, 7), []);
        assert v.complete() and v.count() == 7;
      },
    );

    test(
      "a complete verifier accepts nothing more",
      func() {
        let t = txids(5);
        let (v, ok) = verifierAfter(t, [5]);
        assert ok and v.complete();
        assert not v.verifyChunk([txid(9)], []);
      },
    );
  },
);
