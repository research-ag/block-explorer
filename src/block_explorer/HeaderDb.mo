// Stable hash → header value store.
//
// Backed by `mo:stable-trie` `Enumeration`, which gives us:
//   - O(1) `lookupByHash(hash) -> ?(value, dbidx)`
//   - O(1) `getByDbidx(dbidx) -> ?(hash, value)`
//   - dbidx assigned monotonically from 0 in insertion order.
//
// Key truncation
// --------------
// Bitcoin proof-of-work caps every block hash at the consensus max
// target 0x1d00ffff, whose value
//   0x00000000_FFFF0000_00000000_..._00000000 (big-endian, 32 bytes)
// has its top 4 bytes equal to zero. In our INTERNAL little-endian
// order those become the last 4 bytes — so bytes [28..32) of any valid
// header hash are always 0x00. We drop them: the trie stores 28-byte
// keys, and we re-pad with 4 zero bytes when handing hashes back out.
// External callers continue to see 32-byte Blobs; truncation is hidden
// behind the HeaderDb boundary.
//
// Constructor parameters
// ----------------------
//   key_size     = 28           (sha-256d truncated; see above)
//   value_size   = 76           (HeaderValue blob, see HeaderValue.mo)
//   aridity      = 4            (recommended for uniform keys)
//   root_aridity = 262144       (= 4^9; replaces the top 9 levels with
//                                a single ~1 MB root region)
//   pointer_size = 4            (cap of 2^31 entries; ~2.1 B)
//
// Memory cost (per leaf, with these params):
//   leaf       = key_size + value_size       = 28 + 76       = 104 B
//   internal   ~ aridity*pointer_size/(a-1)  = 16/3          ~  5 B
//   root amort = root_aridity*ptr_size / N   = 1 MB / 900 K  ~  1 B
//   total                                                    ~110 B / block

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";

import StableTrie "mo:stable-trie/Enumeration";

module {

  public type StableData = StableTrie.StableData;
  public type MemoryStats = StableTrie.MemoryStats;

  public let HASH_SIZE : Nat = 32; // full sha-256d output
  public let KEY_SIZE : Nat = 28; // truncated key stored in the trie

  // Truncate a 32-byte header hash to its 28 leading internal-LE bytes.
  // Traps if the hash is the wrong size or its trailing bytes aren't
  // zero (which would imply a hash above max consensus target).
  func truncate(hash : Blob) : Blob {
    if (hash.size() != HASH_SIZE) {
      Runtime.trap("HeaderDb: hash size " # debug_show hash.size() # " != 32");
    };
    let arr = hash.toArray();
    var i = KEY_SIZE;
    while (i < HASH_SIZE) {
      if (arr[i] != (0 : Nat8)) {
        Runtime.trap("HeaderDb: hash trailing byte " # debug_show i # " not zero (PoW invariant violated)");
      };
      i += 1;
    };
    Blob.fromArray(Array.tabulate<Nat8>(KEY_SIZE, func(j) = arr[j]));
  };

  // Re-pad a 28-byte stored key back to a 32-byte hash by appending
  // zero bytes (their consensus-guaranteed value).
  func expand(key : Blob) : Blob {
    let arr = key.toArray();
    Blob.fromArray(
      Array.tabulate<Nat8>(
        HASH_SIZE,
        func(i) = if (i < KEY_SIZE) arr[i] else (0 : Nat8),
      )
    );
  };

  // Hold the trie behind a class so we can do share/unshare in the
  // actor's pre/post-upgrade hooks.
  public class HeaderDb() {

    let trie = StableTrie.Enumeration({
      pointer_size = 4;
      aridity = 4;
      root_aridity = ?262144; // = 4^9
      key_size = KEY_SIZE;
      value_size = 76;
    });

    // Add a (hash, value) pair. Returns the assigned dbidx, or the
    // existing dbidx if the hash was already present (in which case
    // the stored value is overwritten by the new one).
    public func add(hash : Blob, value : Blob) : Nat = trie.add(truncate(hash), value);

    public func lookup(hash : Blob) : ?(Blob, Nat) {
      switch (trie.lookup(truncate(hash))) {
        case null null;
        case (?(k, idx)) ?(expand(k), idx);
      };
    };

    public func get(dbidx : Nat) : ?(Blob, Blob) {
      switch (trie.get(dbidx)) {
        case null null;
        case (?(k, v)) ?(expand(k), v);
      };
    };

    public func size() : Nat = trie.size();

    public func memoryStats() : MemoryStats = trie.memoryStats();

    // Persistence hooks: must be called from the enclosing actor's
    // pre/post-upgrade. `unshare` MUST be the first call after
    // construction (per stable-trie docs).
    public func share() : StableData = trie.share();
    public func unshare(d : StableData) = trie.unshare(d);
  };

};
