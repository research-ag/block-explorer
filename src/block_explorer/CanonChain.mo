// Stable-memory canonical-chain index.
//
// Maps height -> dbidx of the canonical block at that height, packed
// densely into a Region as little-endian Nat32 slots (4 bytes each).
//
// At ~900K blocks: 4 bytes * 900K = ~3.5 MB stable, ~zero heap.
//
// dbidxs come from `mo:stable-trie` with `pointer_size = 4`, which caps
// the number of leaves at 2^31 ~ 2.1 B; that comfortably fits in Nat32.
// We assert this on every append.
//
// The Region itself is a Motoko stable type — the enclosing class can
// be embedded into a `persistent actor`'s stable record via share/unshare
// (see Chain.mo).

import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";

module {

  // 4 bytes per slot, dense layout.
  let SLOT_SIZE : Nat64 = 4;
  let PAGE_SIZE : Nat64 = 65536;
  let MAX_DBIDX : Nat = 0xFFFF_FFFF; // Nat32 max

  public type StableData = {
    region : Region.Region;
    len : Nat;
  };

  public class CanonChain() {

    var region_ : Region.Region = Region.new();
    var len_ : Nat = 0;

    // -----------------------------------------------------------------
    // Stable persistence (share / unshare from the enclosing chain).
    // -----------------------------------------------------------------

    public func share() : StableData = { region = region_; len = len_ };

    public func unshare(d : StableData) {
      region_ := d.region;
      len_ := d.len;
    };

    // -----------------------------------------------------------------
    // Capacity management.
    // -----------------------------------------------------------------

    // Ensure the region has enough pages to hold `len_+1` slots.
    func ensureCapacity() {
      let neededBytes : Nat64 = (Nat64.fromNat(len_) + 1) * SLOT_SIZE;
      let neededPages : Nat64 = (neededBytes + PAGE_SIZE - 1) / PAGE_SIZE;
      let havePages : Nat64 = Region.size(region_);
      if (neededPages > havePages) {
        let grew = Region.grow(region_, neededPages - havePages);
        if (grew == (0xffff_ffff_ffff_ffff : Nat64)) {
          Runtime.trap("CanonChain: Region.grow failed");
        };
      };
    };

    // -----------------------------------------------------------------
    // Public API.
    // -----------------------------------------------------------------

    public func size() : Nat = len_;

    public func at(height : Nat) : Nat {
      if (height >= len_) {
        Runtime.trap(
          "CanonChain: index " # debug_show height
          # " out of bounds (len " # debug_show len_ # ")"
        );
      };
      let off : Nat64 = Nat64.fromNat(height) * SLOT_SIZE;
      Region.loadNat32(region_, off).toNat();
    };

    public func add(dbidx : Nat) {
      if (dbidx > MAX_DBIDX) {
        Runtime.trap(
          "CanonChain: dbidx " # debug_show dbidx
          # " exceeds Nat32 range"
        );
      };
      ensureCapacity();
      let off : Nat64 = Nat64.fromNat(len_) * SLOT_SIZE;
      Region.storeNat32(region_, off, Nat32.fromNat(dbidx));
      len_ += 1;
    };

    // Logically remove the last slot (does not shrink the Region).
    public func removeLast() {
      if (len_ == 0) Runtime.trap("CanonChain: removeLast on empty");
      len_ -= 1;
    };
  };

};
