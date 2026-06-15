// Bitcoin merkle root from a flat blob of transaction hashes.
//
// Input: a Blob of length `tx_count * 32` containing the txids in block order,
// each 32 bytes in INTERNAL little-endian order (the same byte order Bitcoin
// uses on the wire and that we use for `prev_hash`, `merkle_root`, and stored
// block hashes).
//
// Algorithm: Bitcoin's per-level "duplicate the last node if odd" rule,
// hashing concatenated 32-byte pairs with double-SHA256. Implemented as a
// streaming tree with ONE sha-256 engine per level (height N => N digests).
// A node's result never leaves the engine as a Blob or array: the left child
// is finalized in place and reloaded into the engine's message buffer
// (`closeDouble` + `loadStateToMsg`, the latter folded into the next combine),
// the right child is appended straight from its engine's state (`writeSum`),
// and the parent is double-hashed in place (`closeDouble`). Only the leaves
// (read from the input blob) and the final root cross the byte boundary.

import Array "mo:core/Array";
import Blob "mo:core/Blob";

import Sha256 "mo:sha2/Sha256";

module {

  // Compute the Bitcoin merkle root for `txCount` leaves stored contiguously in
  // `hashes` at stride 32. Returns the root in internal LE order. Traps if
  // `hashes.size() != txCount * 32` or `txCount == 0` (no block has zero txs —
  // coinbase is mandatory). The caller's engine `d` is reused as level 1; the
  // remaining N-1 engines are created here (amortized over the whole tree).
  public func root(d : Sha256.Digest, hashes : Blob, txCount : Nat) : Blob {
    if (txCount == 0) {
      assert false;
    };
    if (hashes.size() != txCount * 32) {
      assert false;
    };
    // 1-tx block: the root IS the single txid (no tree, no hashing).
    if (txCount == 1) return hashes;

    // Tree height N: the smallest N with 2^N >= txCount; p = 2^N.
    var n = 0;
    var p = 1;
    while (p < txCount) { p *= 2; n += 1 };

    // One engine per level (1..N), reusing the caller's as level 1.
    let digests = Array.tabulate<Sha256.Digest>(n, func(i) = if (i == 0) d else Sha256.new(#sha256));

    // Height-h subtree covering virtual leaves [lo, lo + 2^h) -> digests[h-1]
    // (closed; state = node hash). `half` = 2^(h-1). Leaves at or beyond
    // txCount don't exist; Bitcoin fills them by duplicating the last present
    // node at that level, which here is "duplicate the left when the right half
    // is entirely missing".
    func subtree(h : Nat, lo : Nat, half : Nat) {
      let dig = digests[h - 1];
      if (h == 1) {
        let r = if (lo + 1 < txCount) lo + 1 else lo; // dup last leaf if odd
        dig.reset();
        dig.writeBlob32(hashes, lo * 32);
        dig.writeBlob32(hashes, r * 32);
        dig.closeDouble();
      } else {
        subtree(h - 1, lo, half / 2); // left -> digests[h-2].state
        dig.reset();
        dig.writeSum(digests[h - 2]); // load the left as the message prefix
        if (lo + half < txCount) {
          subtree(h - 1, lo + half, half / 2); // right -> digests[h-2].state
          dig.writeSum(digests[h - 2]); // append the right
        } else {
          dig.writeSum(digests[h - 2]); // right half missing: duplicate the left
        };
        dig.closeDouble();
      };
    };

    subtree(n, 0, p / 2);
    digests[n - 1].readSum();
  };

};
