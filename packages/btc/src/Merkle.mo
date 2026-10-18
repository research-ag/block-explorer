// Bitcoin merkle root over a list of 32-byte txids.
//
// Input: `txids : [Blob]` in block order, each exactly 32 bytes in INTERNAL
// little-endian order (the same byte order Bitcoin uses on the wire and that
// we use for `prev_hash`, `merkle_root`, and stored block hashes). Returns
// the merkle root in internal LE order; empty / mis-sized leaves trap.
//
// Thin re-export of `BitcoinMerkle.bitcoinMerkleRoot` — the Example 5 file
// of the sha2 package copied verbatim into this crate alongside
// `CounterBase.mo` (Example 3's base). The algorithm is the MMR with a
// binary-counter organization, double-SHA per node, and Bitcoin's "duplicate
// the last node on odd levels" collapse; no per-node heap allocation.

import BitcoinMerkle "BitcoinMerkle";

module {
  public let root : (txids : [Blob]) -> Blob = BitcoinMerkle.bitcoinMerkleRoot;
};
