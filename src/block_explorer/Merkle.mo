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
import Nat8 "mo:core/Nat8";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";

module {

  // Bitcoin sha256d of the concatenation `left || right`, computed
  // via a streaming Digest so we don't allocate a 64-byte
  // intermediate buffer per inner node.
  func sha256dPair(left : Blob, right : Blob) : Blob {
    let d = Sha256.Digest(#sha256);
    d.writeBlob(left);
    d.writeBlob(right);
    Sha256.fromBlob(#sha256, d.sum());
  };

  // Slice a 32-byte hash out of a flat hashes blob at index `i`.
  func leafAt(hashes : Blob, i : Nat) : Blob {
    let mut = VarArray.repeat<Nat8>(0, 32);
    let off = i * 32;
    var j = 0;
    while (j < 32) { mut[j] := hashes[off + j]; j += 1 };
    Blob.fromVarArray(mut);
  };

  // Compute the Bitcoin merkle root for `txCount` leaves stored
  // contiguously in `hashes` at stride 32. Returns the root in
  // internal LE order. Traps if `hashes.size() != txCount * 32` or
  // `txCount == 0` (no block has zero txs — coinbase is mandatory).
  public func root(hashes : Blob, txCount : Nat) : Blob {
    if (txCount == 0) {
      // Caller should have validated; treat as programmer error.
      assert false;
    };
    if (hashes.size() != txCount * 32) {
      assert false;
    };

    // Materialise level 0 as a mutable array of 32-byte Blobs.
    var level = VarArray.tabulate<Blob>(txCount, func(i) = leafAt(hashes, i));
    var n = txCount;

    while (n > 1) {
      let nextN = (n + 1) / 2; // ceil(n/2)
      let next = VarArray.repeat<Blob>("" : Blob, nextN);
      var i = 0;
      while (i < nextN) {
        let leftIdx = i * 2;
        let rightIdx = if (leftIdx + 1 < n) leftIdx + 1 else leftIdx; // dup last on odd
        next[i] := sha256dPair(level[leftIdx], level[rightIdx]);
        i += 1;
      };
      level := next;
      n := nextN;
    };

    level[0];
  };

};
