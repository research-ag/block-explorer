// Bitcoin merkle root from a flat blob of transaction hashes.
//
// Input: a Blob of length `tx_count * 32` containing the txids in
// block order, each 32 bytes in INTERNAL little-endian order (the
// same byte order Bitcoin uses on the wire and that we use for
// `prev_hash`, `merkle_root`, and stored block hashes).
//
// Algorithm: Bitcoin's per-level "duplicate the last node if odd"
// rule, hashing concatenated 32-byte pairs with double-SHA256.

import Blob "mo:core/Blob";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";

import Bytes "Bytes";

module {

  // Bitcoin sha256d of the concatenation `left || right` on a reused
  // engine. Streaming the two halves avoids a 64-byte concat buffer, and
  // reusing one Digest across the whole tree avoids the ~3.3 KB Digest
  // construction per hash — at 2 fresh Digests per inner node, a 4000-tx
  // block would otherwise allocate ~26 MB just building its merkle root.
  func sha256dPair(d : Sha256.Digest, left : Blob, right : Blob) : Blob {
    d.reset();
    d.writeBlob(left);
    d.writeBlob(right);
    let first = d.sum();
    d.reset();
    d.writeBlob(first);
    d.sum();
  };

  // Compute the Bitcoin merkle root for `txCount` leaves stored
  // contiguously in `hashes` at stride 32, using the caller's hash engine
  // (reset between hashes; left in a finished state). Returns the root in
  // internal LE order. Traps if `hashes.size() != txCount * 32` or
  // `txCount == 0` (no block has zero txs — coinbase is mandatory).
  public func root(d : Sha256.Digest, hashes : Blob, txCount : Nat) : Blob {
    if (txCount == 0) {
      // Caller should have validated; treat as programmer error.
      assert false;
    };
    if (hashes.size() != txCount * 32) {
      assert false;
    };

    // Materialise level 0 as a mutable array of 32-byte Blobs.
    var level = VarArray.tabulate<Blob>(txCount, func(i) = Bytes.slice32(hashes, i * 32));
    var n = txCount;

    while (n > 1) {
      let nextN = (n + 1) / 2; // ceil(n/2)
      let next = VarArray.repeat<Blob>("" : Blob, nextN);
      var i = 0;
      while (i < nextN) {
        let leftIdx = i * 2;
        let rightIdx = if (leftIdx + 1 < n) leftIdx + 1 else leftIdx; // dup last on odd
        next[i] := sha256dPair(d, level[leftIdx], level[rightIdx]);
        i += 1;
      };
      level := next;
      n := nextN;
    };

    level[0];
  };

};
