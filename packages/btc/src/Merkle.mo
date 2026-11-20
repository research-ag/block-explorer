// Bitcoin merkle root over a list of 32-byte txids.
//
// Input: `txids : [Blob]` in block order, each exactly 32 bytes in INTERNAL
// little-endian order (the same byte order Bitcoin uses on the wire and that
// we use for `prev_hash`, `merkle_root`, and stored block hashes). Returns
// the merkle root in internal LE order; empty / mis-sized leaves trap.
//
// Thin re-export of `BitcoinMerkle.bitcoinMerkleRoot` and
// `BitcoinMutation.mutated` — the Example 5 files of the sha2 package (0.3.3)
// copied verbatim into this crate alongside `CounterBase.mo` (Example 3's
// base). The algorithm is the MMR with a binary-counter organization,
// double-SHA per node, and Bitcoin's "duplicate the last node on odd levels"
// collapse; no per-node heap allocation.
//
// Mutated blocks (CVE-2012-2459): because of the duplication rule, a txid
// list that writes out a duplicated tail (e.g. `[1,2,3,3]` for `[1,2,3]`) has
// the same root as the real block. `root` runs `mutated` up front and TRAPS
// on a flagged list. `mutated` is also exported on its own so callers can
// run the check without the tree (log2(n) Blob comparisons, no hashing).

import BitcoinMerkle "BitcoinMerkle";
import BitcoinMutation "BitcoinMutation";

module {
  public let root : (txids : [Blob]) -> Blob = BitcoinMerkle.bitcoinMerkleRoot;
  public let mutated : (txids : [Blob]) -> Bool = BitcoinMutation.mutated;
};
