// Heap-side store of all NON-canonical blocks (forks), stored in full.
//
// Two cooperating maps, bundled in a `ForkStore` record so the functions
// below can be called with dot-notation (`forks.add(fb)` ==
// `ForkStore.add(forks, fb)`):
//   byHash   : hash   -> ForkBlock   (lookup / attach / dedup)
//   byHeight : height -> [hash]       (siblings at a height)
//
// Fork tips are derived on demand (a fork block is a tip iff no other fork
// block names it as parent) — that walk needs canonical context, so it lives
// in Chain, not here. This module only owns the raw two-map bookkeeping.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";
import Map "mo:core/Map";
import Nat "mo:core/Nat";

module {

  // The transaction list of a fork block plus its first-tx serial number F
  // in the would-be canonical ordering. Present only once all of the block's
  // ancestors' bodies are known (so F is determined) — see Chain.pushBody.
  public type ForkBody = {
    txids : Blob; // flat 32-byte txids, block order
    firstTxIndex : Nat; // F
  };

  // A non-canonical block, stored in full (including prev_hash).
  public type ForkBlock = {
    hash : Blob; // internal LE order, 32 bytes
    prevHash : Blob; // internal LE order, 32 bytes
    version : Nat32;
    merkle : Blob; // internal LE order, 32 bytes
    time : Nat32;
    bits : Nat32;
    nonce : Nat32;
    height : Nat;
    cumWork : Nat;
    firstSeen : Nat32;
    body : ?ForkBody;
  };

  public type ForkStore = {
    byHash : Map.Map<Blob, ForkBlock>;
    byHeight : Map.Map<Nat, [Blob]>;
  };

  public func empty() : ForkStore = {
    byHash = Map.empty<Blob, ForkBlock>();
    byHeight = Map.empty<Nat, [Blob]>();
  };

  // Fork-block hashes at `height` (siblings), or [].
  public func at(self : ForkStore, height : Nat) : [Blob] {
    switch (Map.get<Nat, [Blob]>(self.byHeight, Nat.compare, height)) {
      case (?xs) xs;
      case null [];
    };
  };

  // Insert a brand-new fork block (updates both maps).
  public func add(self : ForkStore, fb : ForkBlock) {
    Map.add<Blob, ForkBlock>(self.byHash, Blob.compare, fb.hash, fb);
    let cur = at(self, fb.height);
    let next = Array.tabulate<Blob>(
      cur.size() + 1,
      func(i) = if (i < cur.size()) cur[i] else fb.hash,
    );
    Map.add<Nat, [Blob]>(self.byHeight, Nat.compare, fb.height, next);
  };

  // Overwrite an EXISTING fork block in place (same hash/height) — e.g. to
  // attach a body. Only the byHash entry changes; byHeight is unaffected.
  public func updateBlock(self : ForkStore, fb : ForkBlock) {
    Map.add<Blob, ForkBlock>(self.byHash, Blob.compare, fb.hash, fb);
  };

  // Remove a fork block (updates both maps).
  public func removeFork(self : ForkStore, hash : Blob, height : Nat) {
    Map.remove<Blob, ForkBlock>(self.byHash, Blob.compare, hash);
    switch (Map.get<Nat, [Blob]>(self.byHeight, Nat.compare, height)) {
      case null {};
      case (?xs) {
        let kept = Array.filter<Blob>(xs, func(x) = x != hash);
        if (kept.size() == 0) {
          Map.remove<Nat, [Blob]>(self.byHeight, Nat.compare, height);
        } else {
          Map.add<Nat, [Blob]>(self.byHeight, Nat.compare, height, kept);
        };
      };
    };
  };

  public func get(self : ForkStore, hash : Blob) : ?ForkBlock =
    Map.get<Blob, ForkBlock>(self.byHash, Blob.compare, hash);

  public func contains(self : ForkStore, hash : Blob) : Bool =
    Map.containsKey<Blob, ForkBlock>(self.byHash, Blob.compare, hash);

  // Number of fork blocks tracked.
  public func size(self : ForkStore) : Nat = Map.size(self.byHash);

  // Iterate all (hash, block) pairs.
  public func entries(self : ForkStore) : Iter.Iter<(Blob, ForkBlock)> =
    Map.entries(self.byHash);

};
