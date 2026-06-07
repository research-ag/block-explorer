// Stable hash → header value store for the CANONICAL chain only.
//
// Backed by `mo:stable-trie` `Enumeration` (v0.1.x, module-level
// functional API). The trie holds exactly the canonical chain in height
// order, so its enumeration index equals the canonical height:
//
//   index 0           = genesis
//   index h           = canonical block at height h
//   size()            = tipHeight + 1
//
// We append with `add`, and on a reorg we retract the tip with
// `removeLast` (or `truncate`). Non-canonical blocks never enter this
// trie — they live in the heap-side fork store (see Chain.mo).
//
// Key truncation
// --------------
// Bitcoin proof-of-work caps every block hash at the consensus max
// target 0x1d00ffff, whose value
//   0x00000000_FFFF0000_00000000_..._00000000 (big-endian, 32 bytes)
// has its top 4 bytes equal to zero. In our INTERNAL little-endian
// order (natural sha-256d output order) those become the last 4 bytes —
// so bytes [28..32) of any valid header hash are always 0x00. We drop
// them: the trie stores 28-byte keys and we re-pad with 4 zero bytes
// when handing hashes back out. Callers always see 32-byte Blobs.
//
// Constructor parameters
// ----------------------
//   key_size     = 28           (sha-256d truncated; see above)
//   value_size   = 76           (HeaderValue blob, see HeaderValue.mo)
//   aridity      = 4            (recommended for uniform keys)
//   root_aridity = 262144       (= 4^9; replaces the top 9 levels with
//                                a single ~1 MB root region)
//   pointer_size = 4            (cap of 2^31 entries; ~2.1 B)

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";

import Enumeration "mo:stable-trie/Enumeration";

module {

  // The whole stable-trie state is itself a stable record, so the
  // enclosing Chain can carry it directly in its StableData.
  public type StableData = Enumeration.Enumeration;
  public type MemoryStats = Enumeration.MemoryStats;

  public let HASH_SIZE : Nat = 32; // full sha-256d output
  public let KEY_SIZE : Nat = 28; // truncated key stored in the trie (production)

  // Hold the trie behind a class so the enclosing Chain can share/unshare
  // it across upgrades. `keySize` is the trie key width: production uses
  // KEY_SIZE (28, the PoW-truncated form); tests may use HASH_SIZE (32,
  // full keys, no truncation) so synthetic non-PoW headers can be stored.
  public class HeaderDb(keySize : Nat) {

    var trie : Enumeration.Enumeration = Enumeration.empty({
      pointer_size = 4;
      aridity = 4;
      root_aridity = ?262144; // = 4^9
      key_size = keySize;
      value_size = 76;
    });

    // Truncate a 32-byte header hash to its `keySize` leading internal-LE
    // bytes. Traps if the hash is the wrong size or if any dropped byte is
    // non-zero (which would imply a hash above max consensus target). When
    // keySize == HASH_SIZE this is the identity (no bytes dropped).
    func truncateKey(hash : Blob) : Blob {
      if (hash.size() != HASH_SIZE) {
        Runtime.trap("HeaderDb: hash size " # debug_show hash.size() # " != 32");
      };
      let arr = hash.toArray();
      var i = keySize;
      while (i < HASH_SIZE) {
        if (arr[i] != (0 : Nat8)) {
          Runtime.trap("HeaderDb: hash trailing byte " # debug_show i # " not zero (PoW invariant violated)");
        };
        i += 1;
      };
      Blob.fromArray(Array.tabulate<Nat8>(keySize, func(j) = arr[j]));
    };

    // Re-pad a stored key back to a 32-byte hash by appending zero bytes
    // (their consensus-guaranteed value).
    func expand(key : Blob) : Blob {
      let arr = key.toArray();
      Blob.fromArray(
        Array.tabulate<Nat8>(
          HASH_SIZE,
          func(i) = if (i < keySize) arr[i] else (0 : Nat8),
        )
      );
    };

    // Append a (hash, value) pair at the next index (== its height).
    // Returns the assigned index.
    public func add(hash : Blob, value : Blob) : Nat = Enumeration.add(trie, truncateKey(hash), value);

    // Look up by hash. Returns (value, index) or null.
    public func lookup(hash : Blob) : ?(Blob, Nat) = Enumeration.lookup(trie, truncateKey(hash));

    // Read the (hash, value) at an index.
    public func get(index : Nat) : ?(Blob, Blob) {
      switch (Enumeration.get(trie, index)) {
        case null null;
        case (?(k, v)) ?(expand(k), v);
      };
    };

    // Overwrite the value at an index in place (key unchanged). Used to
    // backfill firstTxIndex once a block's body is known. Traps on OOB.
    public func put(index : Nat, value : Blob) = Enumeration.put(trie, index, value);

    // Retract the tip (highest index). Returns the removed (hash, value)
    // so the caller can move it into the fork store, or null if empty.
    public func removeLast() : ?(Blob, Blob) {
      switch (Enumeration.removeLast(trie)) {
        case null null;
        case (?(k, v)) ?(expand(k), v);
      };
    };

    // Drop all entries from `newSize` onwards (keeps indices 0..newSize-1).
    public func truncate(newSize : Nat) = Enumeration.truncate(trie, newSize);

    public func size() : Nat = Enumeration.size(trie);

    public func memoryStats() : MemoryStats = Enumeration.memoryStats(trie);

    // Promtracker Value exposing this trie's memoryStats (stable_trie_*
    // families). Feed to a renderer, optionally wrapped in PT.bundle to
    // add a distinguishing label.
    public func toValue() : { read : () -> [(Text, Text, Nat)] } = Enumeration.toValue(trie);

    // Persistence hooks: called from the enclosing Chain's share/unshare.
    public func share() : StableData = trie;
    public func unshare(d : StableData) { trie := d };
  };

};
