/// The chunk verifier of push_body_chunk, on the core of the mmr package
/// (`mo:mmr/Peaks`).
///
/// It is mmr's `Chunks.verifyChunk` for a Bitcoin tree (double SHA-256, the
/// last node of an odd level paired with itself, equal siblings rejected),
/// with two differences that `Chunks` does not offer:
///
///   - NO BACKUP. `Chunks` copies the peaks aside before every chunk and back
///     when the chunk is rejected, which takes a second pool of hashers. Here
///     a rejected chunk leaves the verifier HALF-UPDATED and the caller TRAPS,
///     which rolls the call back (in inspect: rejects the message).
///   - ONE POOL OF HASHERS for block after block (`pool`, `new`), allocated
///     once by the canister. `Chunks.new` allocates two pools per verifier.
///
/// The `Verifier` record is what Chain keeps in stable memory
/// (State.bodyChunks), unchanged from the verifier this replaces, so the
/// switch needs no migration. mmr's `Peaks` record has a `double` flag
/// besides the hashers and the count, so `verifyChunk` puts a `Peaks` record
/// on the same hashers and count for the duration of the call: one small
/// record per chunk, nothing per txid.
///
/// The proof of a chunk ending at txid m is `Prove.rightPeaks(levels, m)`
/// (mo:mmr/Prove, with `Bitcoin.levels`): the peaks to the right of txid
/// m - 1, lowest first; empty for the last chunk. Txids, proofs and the root
/// are in Bitcoin's internal byte order.

import Nat "mo:core/Nat";

import Hasher "mo:sha2/Hasher/Sha256";
import Peaks "mo:mmr/Peaks";

module {
  /// The verifier's state. Slot k of `hasher` holds the peak of height k of
  /// the tree over the txids accepted so far exactly when bit k of `count` is
  /// set, and the last slot is the spare: the layout of mmr's `Peaks`.
  public type Verifier = {
    /// The block's Merkle root.
    root : Blob;
    /// The pool the tree lives in (see `pool`).
    hasher : [var Hasher.Hasher];
    /// The number of txids accepted so far.
    var count : Nat64;
    /// Whether the last chunk, the one with an empty proof, was accepted.
    var done : Bool;
  };

  /// A pool of hashers for blocks of at most 2^maxDepth txids: maxDepth + 2
  /// of them, the slots 0 to maxDepth and the spare (`Peaks.withDepth`).
  public func pool(maxDepth : Nat) : [var Hasher.Hasher] = Peaks.withDepth(maxDepth, true).hasher;

  /// A verifier for the block with Merkle root `root` on `pool`. Whatever the
  /// pool holds does not matter: a txid is loaded into the spare before it is
  /// used, and a slot is only read while `count` has a 1-bit there, that is
  /// after a node came to rest in it. Only one verifier may use a pool at a
  /// time: verifying swaps the pool's hashers around.
  public func new(root : Blob, pool : [var Hasher.Hasher]) : Verifier {
    assert root.size() == 32 and pool.size() >= 2 and pool.size() <= 63;
    { root; hasher = pool; var count = 0; var done = false };
  };

  /// Whether the upload is complete: the last accepted chunk came with an
  /// empty proof, so no txid can follow, and `count` is the block's
  /// transaction count.
  public func complete(self : Verifier) : Bool = self.done;

  func wellFormed(hashes : [Blob]) : Bool {
    var i = 0;
    while (i < hashes.size()) {
      if (hashes[i].size() != 32) return false;
      i += 1;
    };
    true;
  };

  /// Verify the next chunk of txids with the uploader's proof `next` for the
  /// txids after it, and accept it if it checks out: `true`, and the verifier
  /// advances. Otherwise `false`, and the verifier is HALF-UPDATED and must
  /// not be used again: the caller traps. An empty `next` claims that the
  /// chunk is the last one. Allocates the `Peaks` record and nothing else.
  public func verifyChunk(self : Verifier, txids : [Blob], next : [Blob]) : Bool {
    if (self.done or txids.size() == 0 or not wellFormed(txids) or not wellFormed(next)) return false;
    let tree : Peaks.Peaks = { hasher = self.hasher; double = true; var count = self.count };
    // A tree of 2^maxDepth txids is the most there is room for (as in
    // `Chunks.verifyChunk`).
    let maxLeaves = (tree.capacity() + 1) / 2;
    if (txids.size().toNat64() > maxLeaves - tree.count) return false;
    // 1. Add the chunk, rejecting equal siblings: in pairs, fused straight
    // from their Blobs (`addPairChecked` compares the two txids as well), and
    // a txid alone first if the count is odd, and last if one is left over.
    let n = txids.size();
    var j = 0;
    var ok = true;
    if ((tree.count & 1) == 1) {
      ok := tree.addChecked(txids[0]);
      j := 1;
    };
    while (ok and j + 1 < n) {
      ok := tree.addPairChecked(txids[j], txids[j + 1]);
      j += 2;
    };
    if (ok and j < n) ok := tree.addChecked(txids[j]);
    self.count := tree.count;
    if (not ok) return false;
    // 2. and 3. Close the tree with the proof, rejecting equal siblings, and
    // compare with the root.
    if (not tree.close(next, #copy, true) or not tree.spare().equalsBlob32(self.root)) return false;
    // 4. Keep the grown tree.
    self.done := next.size() == 0;
    true;
  };
};
