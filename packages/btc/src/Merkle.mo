// Bitcoin merkle root from a flat blob of transaction hashes.
//
// Input: a Blob of length `txCount * 32` containing the txids in block order,
// each 32 bytes in INTERNAL little-endian order (the same byte order Bitcoin
// uses on the wire and that we use for `prev_hash`, `merkle_root`, and stored
// block hashes).
//
// Algorithm: Bitcoin's per-level "duplicate the last node if odd" rule,
// double-SHA256 per node, computed as a Merkle mountain range (MMR) over the
// stream of leaves. Follows the `BitcoinMerkle.mo` + `CounterBase.mo` examples
// of the sha2 package verbatim (binary-counter organization, slot k holds the
// height-k peak, slot 0 is the free accumulator used by the Bitcoin collapse);
// the only project-specific adaptation is reading the leaves out of a flat
// hashes blob at stride 32 instead of taking them as `[Blob]`.
//
// Allocation: no per-node allocations — peaks live in a pre-sized `Hasher`
// pool of `floor(log2 txCount) + 1` 16-word state arrays, and `combineState` /
// `hashState` fold them in place. Each leaf costs one small 32-byte `Blob`
// slice (the Hasher API's inputs are 32-byte `Blob`s); the only other heap
// output is the final root `Blob`.

import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";

import Hasher "mo:sha2/Hasher/Sha256";

import Bytes "Bytes";

module {

  // Compute the Bitcoin merkle root for `txCount` leaves stored contiguously in
  // `hashes` at stride 32. Returns the root in internal LE order. Traps if
  // `hashes.size() != txCount * 32` or `txCount == 0` (no block has zero txs —
  // coinbase is mandatory).
  public func root(hashes : Blob, txCount : Nat) : Blob {
    assert txCount > 0;
    assert hashes.size() == txCount * 32;
    // 1-tx block: the root IS the single txid (no tree, no hashing).
    if (txCount == 1) return hashes;

    // Pool size = bit length of `txCount` = floor(log2 txCount) + 1. Slot k
    // holds the height-k peak when bit k of the leaf count is set; slot 0
    // stays free (the height-0 leaf waits as `pending`) and is the Bitcoin-
    // collapse accumulator.
    var l = 0;
    var pow = 1;
    while (pow * 2 <= txCount) { pow *= 2; l += 1 };
    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) = Hasher.new());
    var count : Nat64 = 0;
    var pending : ?Blob = null;

    // Add each txid to the MMR (double-SHA per node — the Bitcoin leaf/node
    // combiner from `CounterBase.mo` with `double = true`).
    var i = 0;
    while (i < txCount) {
      let leaf = Bytes.slice32(hashes, i * 32);
      switch (pending) {
        case null { pending := ?leaf }; // hold until the partner arrives
        case (?leaf0) {
          pending := null;
          // Fuse the pair straight from the two 32-byte Blobs — no loadBlob32.
          // The height-1 node is built in slot 0, free since bit 0 just cleared.
          hasher[0].combineBlob32(leaf0, leaf);
          hasher[0].hashState(hasher[0]); // -> double SHA
          // Carry: the rising node climbs the slots — height-(k+1) is built in
          // slot k by merging the peak there with the node from below.
          var k : Nat64 = 1;
          while (((count >> k) & 1) == 1) {
            let kk = k.toNat();
            hasher[kk].combineState(hasher[kk], hasher[kk - 1]);
            hasher[kk].hashState(hasher[kk]); // -> double SHA
            k += 1;
          };
          // Carry stopped at a clear bit: slot k is free; swap the finished
          // height-k node up from one below.
          let kk = k.toNat();
          let tmp = hasher[kk];
          hasher[kk] := hasher[kk - 1];
          hasher[kk - 1] := tmp;
        };
      };
      count += 1;
      i += 1;
    };

    // Bitcoin collapse: walk the bits of `count` from the lowest set bit
    // upward, accumulator in slot 0 (free, thanks to the pending height-0
    // leaf). At every level above the lowest the node count has parity
    // ((count >> k) + 1): SET bit — pair acc with the waiting peak; CLEAR bit
    // — the level is odd again, pair acc with itself (Bitcoin's duplicate).
    let acc = hasher[0];
    var k : Nat64 = 1;
    switch (pending) {
      case (?b) {
        // Odd leaf count: the pending txid is the lowest component — the
        // level-0 odd node. Load it into the accumulator and pair it with
        // itself.
        acc.loadBlob32(b);
        acc.combineState(acc, acc);
      };
      case null {
        // Even count: start the collapse at the lowest set peak.
        while (((count >> k) & 1) == 0) { k += 1 };
        if (Nat64.bitcountNonZero(count) == 1) {
          // Single peak (power-of-two count): the root is that peak outright.
          return hasher[k.toNat()].readSum();
        };
        // The lowest peak is paired with itself — its level's node count
        // (count >> k) is odd.
        let k0 = k.toNat();
        acc.combineState(hasher[k0], hasher[k0]);
        k += 1;
      };
    };
    acc.hashState(acc); // -> double SHA, completing the doubling
    while ((count >> k) > 0) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[k.toNat()], acc); // dSHA(peak ++ acc)
      } else {
        acc.combineState(acc, acc); // duplicate: dSHA(acc ++ acc)
      };
      acc.hashState(acc); // -> double SHA
      k += 1;
    };
    acc.readSum();
  };

};
