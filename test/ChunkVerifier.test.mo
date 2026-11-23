// Tests for the chunk verifier of push_body_chunk (ChunkVerifier: mmr's
// chunk verification on its Peaks, without the backup, on one pool): valid
// chunkings verify and complete; a wrong proof, a wrong leaf, a premature
// last chunk and mutated blocks (CVE-2012-2459) are rejected; and a
// rejected chunk leaves the verifier half-updated, which is why the canister
// traps on it. Proofs come from mmr's Prove.rightPeaks.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";

import Sha256 "mo:sha2/Sha256";

import Bitcoin "mo:mmr/Bitcoin";
import Prove "mo:mmr/Prove";

import ChunkVerifier "../src/block_explorer/ChunkVerifier";

let MAX_DEPTH = 20;

// Distinct leaves: SHA-256 of the index as 4 little-endian bytes.
func txid(i : Nat) : Blob {
  let d = Sha256.new(#sha256);
  d.writeBlob(Blob.fromArray([Nat8.fromNat(i % 256), Nat8.fromNat((i / 256) % 256), 0, 0]));
  d.sum();
};

func txids(n : Nat) : [Blob] = Array.tabulate<Blob>(n, txid);

func slice(a : [Blob], lo : Nat, hi : Nat) : [Blob] = Array.tabulate<Blob>(hi - lo : Nat, func(i) = a[lo + i]);

// The proof for a chunk of `t` that ends at leaf m.
func proofFor(t : [Blob], m : Nat) : [Blob] = Prove.rightPeaks(Bitcoin.levels(t), m);

func fresh(root : Blob) : ChunkVerifier.Verifier = ChunkVerifier.new(root, ChunkVerifier.pool(MAX_DEPTH));

// A verifier for the real list `t`, with the chunks [0, b1), [b1, b2), ...
// accepted. True if they all verified.
func verifierAfter(t : [Blob], bounds : [Nat]) : (ChunkVerifier.Verifier, Bool) {
  let v = fresh(Bitcoin.merkleRoot(t));
  var lo = 0;
  for (hi in bounds.values()) {
    if (not v.verifyChunk(slice(t, lo, hi), proofFor(t, hi))) return (v, false);
    lo := hi;
  };
  (v, true);
};

suite(
  "ChunkVerifier",
  func() {

    test(
      "a verifier holds maxDepth + 2 hashers, and no backup",
      func() {
        let v = fresh(txid(0));
        assert v.hasher.size() == MAX_DEPTH + 2;
        assert ChunkVerifier.pool(MAX_DEPTH).size() == MAX_DEPTH + 2;
      },
    );

    test(
      "one pool of hashers serves block after block, whatever it holds",
      func() {
        let pool = ChunkVerifier.pool(MAX_DEPTH);
        // Block A (13 txids) in chunks of 4.
        let a = txids(13);
        let va = ChunkVerifier.new(Bitcoin.merkleRoot(a), pool);
        var lo = 0;
        for (hi in [4, 8, 12, 13].values()) {
          assert va.verifyChunk(slice(a, lo, hi), proofFor(a, hi));
          lo := hi;
        };
        assert va.complete();
        // Block B: a rejected chunk leaves the pool half-updated ...
        let b = Array.tabulate<Blob>(9, func(i) = txid(100 + i));
        let bad = ChunkVerifier.new(Bitcoin.merkleRoot(b), pool);
        assert bad.verifyChunk(slice(b, 0, 3), proofFor(b, 3));
        assert not bad.verifyChunk(slice(b, 3, 6), proofFor(b, 3));
        // ... and a new verifier on the same pool still verifies B.
        let vb = ChunkVerifier.new(Bitcoin.merkleRoot(b), pool);
        assert vb.verifyChunk(slice(b, 0, 5), proofFor(b, 5));
        assert vb.verifyChunk(slice(b, 5, 9), []);
        assert vb.complete();
        // Block C (a single txid) in one chunk, and A again.
        let c = [txid(200)];
        assert ChunkVerifier.new(Bitcoin.merkleRoot(c), pool).verifyChunk(c, []);
        assert ChunkVerifier.new(Bitcoin.merkleRoot(a), pool).verifyChunk(a, []);
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
            while (hi < n) { bounds := Array.concat(bounds, [hi]); hi += size };
            bounds := Array.concat(bounds, [n]);
            let (v, ok) = verifierAfter(t, bounds);
            assert ok;
            assert v.complete() and v.count == Nat64.fromNat(n);
          };
        };
      },
    );

    test(
      "a wrong proof is rejected",
      func() {
        let t = txids(7);
        let first = slice(t, 0, 3);
        let start = func() : ChunkVerifier.Verifier = fresh(Bitcoin.merkleRoot(t));
        // The proof for another boundary.
        assert not start().verifyChunk(first, proofFor(t, 4));
        // An empty proof: a premature last chunk.
        assert not start().verifyChunk(first, []);
        // A proof with its last peak missing, and one with an extra peak.
        let p3 = proofFor(t, 3);
        assert not start().verifyChunk(first, slice(p3, 0, p3.size() - 1 : Nat));
        assert not start().verifyChunk(first, Array.concat(p3, [txid(99)]));
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
        let m6 = Array.concat(t6, [t6[4], t6[5]]);
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
      "a rejected chunk leaves the verifier half-updated: the caller must trap",
      func() {
        let t = txids(7);
        let (v, ok) = verifierAfter(t, [3]);
        assert ok;
        // The wrong proof is rejected after the chunk's leaves went in ...
        assert not v.verifyChunk(slice(t, 3, 5), proofFor(t, 3));
        assert v.count == 5;
        // ... so the right chunk no longer verifies on this verifier.
        assert not v.verifyChunk(slice(t, 3, 5), proofFor(t, 5));
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
