// Generic store of NON-canonical blocks (forks) for a heaviest-chain
// protocol. Blocks are identified by Blob ids (hashes); the block type `B`
// is fully opaque — callers pass id and height explicitly, so the store
// needs no accessors and the record is plain stable data.
//
// Two cooperating maps:
//   byId     : id -> B          (lookup / attach / dedup)
//   byHeight : height -> [Blob] (siblings at a height)

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";
import Map "mo:core/Map";
import Nat "mo:core/Nat";

module {

  public type ForkStore<B> = {
    byId : Map.Map<Blob, B>;
    byHeight : Map.Map<Nat, [Blob]>;
  };

  public func empty<B>() : ForkStore<B> = {
    byId = Map.empty<Blob, B>();
    byHeight = Map.empty<Nat, [Blob]>();
  };

  // Fork-block ids at `height` (siblings), or [].
  public func at<B>(self : ForkStore<B>, height : Nat) : [Blob] {
    switch (Map.get<Nat, [Blob]>(self.byHeight, Nat.compare, height)) {
      case (?xs) xs;
      case null [];
    };
  };

  // Insert a brand-new fork block (updates both maps).
  public func add<B>(self : ForkStore<B>, id : Blob, height : Nat, b : B) {
    Map.add<Blob, B>(self.byId, Blob.compare, id, b);
    let cur = at(self, height);
    let next = Array.tabulate<Blob>(
      cur.size() + 1,
      func(i) = if (i < cur.size()) cur[i] else id,
    );
    Map.add<Nat, [Blob]>(self.byHeight, Nat.compare, height, next);
  };

  // Overwrite an EXISTING fork block in place (same id/height) — e.g. to
  // attach a payload. Only the byId entry changes.
  public func update<B>(self : ForkStore<B>, id : Blob, b : B) {
    Map.add<Blob, B>(self.byId, Blob.compare, id, b);
  };

  // Remove a fork block (updates both maps).
  public func remove<B>(self : ForkStore<B>, id : Blob, height : Nat) {
    Map.remove<Blob, B>(self.byId, Blob.compare, id);
    switch (Map.get<Nat, [Blob]>(self.byHeight, Nat.compare, height)) {
      case null {};
      case (?xs) {
        let kept = Array.filter<Blob>(xs, func(x) = x != id);
        if (kept.size() == 0) {
          Map.remove<Nat, [Blob]>(self.byHeight, Nat.compare, height);
        } else {
          Map.add<Nat, [Blob]>(self.byHeight, Nat.compare, height, kept);
        };
      };
    };
  };

  public func get<B>(self : ForkStore<B>, id : Blob) : ?B =
    Map.get<Blob, B>(self.byId, Blob.compare, id);

  public func contains<B>(self : ForkStore<B>, id : Blob) : Bool =
    Map.containsKey<Blob, B>(self.byId, Blob.compare, id);

  // Number of fork blocks tracked.
  public func size<B>(self : ForkStore<B>) : Nat = Map.size(self.byId);

  // Iterate all (id, block) pairs.
  public func entries<B>(self : ForkStore<B>) : Iter.Iter<(Blob, B)> =
    Map.entries(self.byId);

};
