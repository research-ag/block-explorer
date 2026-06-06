// Single-region storage for Bitcoin block-body summaries, indexed by
// the `block_explorer` canister's `dbidx`.
//
// Layout
// ------
// Region: one fixed 8-byte slot per dbidx (dense, padded for any
// unset dbidx). Slot encoding (little-endian Nat64):
//
//     bits  0..23  : tx_count           (24 bits, max 16_777_215)
//     bits 24..63  : first_txdbidx      (40 bits, max ~1 T)
//
// `tx_count == 0` means the slot is unset (every real Bitcoin block
// has at least the coinbase transaction).
//
// Why this is enough
// ------------------
// On upload we insert all of a block's txids into the txid trie in
// block order, in one synchronous batch. The trie's enumeration
// assigns consecutive `txdbidx`s. So the body is fully described by
// `(first_txdbidx, tx_count)`: the txid at position `i` of block
// `dbidx` lives at `txdbidx = first_txdbidx + i`.

import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";

module {

  let META_SLOT : Nat64 = 8;
  let PAGE_SIZE : Nat64 = 65536;

  let MAX_TX_COUNT : Nat = 0xFF_FFFF; // 24 bits
  let MAX_TXDBIDX : Nat = 0xFF_FFFF_FFFF; // 40 bits

  public type StableData = {
    metaRegion : Region.Region;
  };

  public type Body = { tx_count : Nat; first_txdbidx : Nat };

  public class BlockBodyStore() {

    var metaRegion_ : Region.Region = Region.new();

    public func share() : StableData = { metaRegion = metaRegion_ };

    public func unshare(d : StableData) {
      metaRegion_ := d.metaRegion;
    };

    func ensureCapacityFor(dbidx : Nat) {
      let neededBytes : Nat64 = (Nat64.fromNat(dbidx) + 1) * META_SLOT;
      let neededPages : Nat64 = (neededBytes + PAGE_SIZE - 1) / PAGE_SIZE;
      let havePages : Nat64 = Region.size(metaRegion_);
      if (neededPages > havePages) {
        let grew = Region.grow(metaRegion_, neededPages - havePages);
        if (grew == (0xffff_ffff_ffff_ffff : Nat64)) {
          Runtime.trap("BlockBodyStore: Region.grow failed");
        };
      };
    };

    func packSlot(txCount : Nat, firstTxdbidx : Nat) : Nat64 {
      Nat64.fromNat(txCount) | (Nat64.fromNat(firstTxdbidx) << 24);
    };

    func unpackSlot(slot : Nat64) : Body {
      {
        tx_count = Nat64.toNat(slot & 0xFF_FFFF);
        first_txdbidx = Nat64.toNat(slot >> 24);
      };
    };

    func slotInRange(dbidx : Nat) : Bool {
      let slotOff : Nat64 = Nat64.fromNat(dbidx) * META_SLOT;
      slotOff + META_SLOT <= Region.size(metaRegion_) * PAGE_SIZE;
    };

    public func get(dbidx : Nat) : ?Body {
      if (not slotInRange(dbidx)) return null;
      let slotOff : Nat64 = Nat64.fromNat(dbidx) * META_SLOT;
      let slot = Region.loadNat64(metaRegion_, slotOff);
      let body = unpackSlot(slot);
      if (body.tx_count == 0) null else ?body;
    };

    public func txCountOf(dbidx : Nat) : ?Nat {
      switch (get(dbidx)) {
        case null null;
        case (?b) ?b.tx_count;
      };
    };

    // Record (txCount, firstTxdbidx) at slot `dbidx`. Traps if a
    // body is already stored, or on bound violations.
    public func put(dbidx : Nat, txCount : Nat, firstTxdbidx : Nat) {
      if (txCount == 0) Runtime.trap("BlockBodyStore: tx_count == 0");
      if (txCount > MAX_TX_COUNT) Runtime.trap("BlockBodyStore: tx_count overflow");
      if (firstTxdbidx > MAX_TXDBIDX) Runtime.trap("BlockBodyStore: first_txdbidx overflow");

      ensureCapacityFor(dbidx);
      let slotOff : Nat64 = Nat64.fromNat(dbidx) * META_SLOT;
      let existing = Region.loadNat64(metaRegion_, slotOff);
      if ((existing & 0xFF_FFFF) != 0) {
        Runtime.trap("BlockBodyStore: dbidx " # debug_show dbidx # " already populated");
      };
      Region.storeNat64(metaRegion_, slotOff, packSlot(txCount, firstTxdbidx));
    };

    public func capacityBlocks() : Nat {
      Nat64.toNat(Region.size(metaRegion_) * PAGE_SIZE / META_SLOT);
    };

    // Bytes of stable memory currently allocated to the body region.
    public func byteSize() : Nat {
      Nat64.toNat(Region.size(metaRegion_) * PAGE_SIZE);
    };

  };

};
