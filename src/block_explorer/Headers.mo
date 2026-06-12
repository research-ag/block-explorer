// Canonical-chain header store: helpers over a bare `mo:stable-trie`
// Enumeration that holds ONLY the canonical chain in height order, so the
// enumeration index equals the canonical height (index 0 = genesis,
// size() = tipHeight + 1). Append with `add`; retract the tip with
// `removeLast` / `truncate` on a reorg.
//
// Unlike the old HeaderDb class, there is no wrapper record and no `keySize`
// constructor seam: the key width is read from the trie itself
// (`trie.key_size`). Production tries are built with key_size = 28; tests may
// use 32 (full keys, no truncation). These functions take the trie directly,
// e.g. `Headers.add(headerTrie, hash, value)`.
//
// Key truncation: a valid PoW hash has its top 4 big-endian bytes zero, which
// in internal little-endian order are bytes [key_size..32). We drop them
// (stored key = key_size bytes) and re-pad with zeros on the way out, so
// callers always see 32-byte hashes. When key_size == 32 this is the identity.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";

import Enumeration "mo:stable-trie/Enumeration";

module {

  public let HASH_SIZE : Nat = 32; // full sha-256d output
  public let KEY_SIZE : Nat = 28; // PoW-truncated key (production)

  public type MemoryStats = Enumeration.MemoryStats;

  // Truncate a 32-byte hash to the trie's key width, trapping if a dropped
  // byte is non-zero (PoW invariant violated). Identity when key_size == 32.
  func truncateKey(trie : Enumeration.Enumeration, hash : Blob) : Blob {
    let keySize = trie.key_size;
    if (hash.size() != HASH_SIZE) {
      Runtime.trap("Headers: hash size " # debug_show hash.size() # " != 32");
    };
    if (keySize == HASH_SIZE) return hash; // identity mode: no copy
    var i = keySize;
    while (i < HASH_SIZE) {
      if (hash[i] != (0 : Nat8)) {
        Runtime.trap("Headers: hash trailing byte " # debug_show i # " not zero (PoW invariant violated)");
      };
      i += 1;
    };
    Blob.fromArray(Array.tabulate<Nat8>(keySize, func(j) = hash[j]));
  };

  // Re-pad a stored key back to a 32-byte hash with zero bytes.
  func expand(trie : Enumeration.Enumeration, key : Blob) : Blob {
    let keySize = trie.key_size;
    if (keySize == HASH_SIZE) return key; // identity mode: no copy
    Blob.fromArray(
      Array.tabulate<Nat8>(HASH_SIZE, func(i) = if (i < keySize) key[i] else (0 : Nat8))
    );
  };

  // Append a (hash, value) pair at the next index (== its height); returns it.
  public func add(trie : Enumeration.Enumeration, hash : Blob, value : Blob) : Nat =
    Enumeration.add(trie, truncateKey(trie, hash), value);

  // Look up by hash. Returns (value, index) or null.
  public func lookup(trie : Enumeration.Enumeration, hash : Blob) : ?(Blob, Nat) =
    Enumeration.lookup(trie, truncateKey(trie, hash));

  // Read the (hash, value) at an index (hash re-expanded to 32 bytes).
  public func get(trie : Enumeration.Enumeration, index : Nat) : ?(Blob, Blob) {
    switch (Enumeration.get(trie, index)) {
      case null null;
      case (?(k, v)) ?(expand(trie, k), v);
    };
  };

  // Read only the value at an index — skips the key re-expansion. Use for
  // narrow field reads (e.g. a single timestamp via HeaderValue.timeOf).
  public func valueAt(trie : Enumeration.Enumeration, index : Nat) : ?Blob {
    switch (Enumeration.get(trie, index)) {
      case null null;
      case (?(_, v)) ?v;
    };
  };

  // Overwrite the value at an index in place (key unchanged). Traps on OOB.
  public func put(trie : Enumeration.Enumeration, index : Nat, value : Blob) =
    Enumeration.put(trie, index, value);

  // Retract the tip (highest index); returns the removed (hash, value) or null.
  public func removeLast(trie : Enumeration.Enumeration) : ?(Blob, Blob) {
    switch (Enumeration.removeLast(trie)) {
      case null null;
      case (?(k, v)) ?(expand(trie, k), v);
    };
  };

  // Drop all entries from `newSize` onwards (keeps indices 0..newSize-1).
  public func truncate(trie : Enumeration.Enumeration, newSize : Nat) =
    Enumeration.truncate(trie, newSize);

  public func size(trie : Enumeration.Enumeration) : Nat = Enumeration.size(trie);

  public func memoryStats(trie : Enumeration.Enumeration) : MemoryStats =
    Enumeration.memoryStats(trie);

  public func toValue(trie : Enumeration.Enumeration) : { read : () -> [(Text, Text, Nat)] } =
    Enumeration.toValue(trie);

};
