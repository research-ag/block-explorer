// Inline actor migration to enumeration 0.3.x.
//
// enumeration 0.3.0 changed the stable type of its tree: a node stores its
// index and its color in one Nat32 (`index << 1 | red`) instead of a color
// variant and a Nat, so `Tree` went from `?({#R; #B}, Tree, Nat, Tree)` to
// `?(Tree, Nat32, Tree)` (see "Upgrading from 0.2.x" in its README). The
// explorer keeps one enumeration, `chain.uploaders.enum` (uploader principal
// <-> id). Its key array and size pass through as they are, so every
// uploader keeps its id; only the tree is converted, node by node, to the
// same shape and colors.
//
// Everything else (the two StableTrie regions, the fork store, the rest of
// the uploaders record, the reorg log, the coinbase region, the chunk tree
// and all the `var` scalars) passes through by reference. The whole `chain`
// record must be rebuilt because it is a single bundled stable variable: a
// field left out here would be lost.
//
// Delete this file and the `(with migration = ...)` clause in main.mo once
// the upgrade has run on mainnet.

import List "mo:core/List";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Runtime "mo:core/Runtime";

import Enum "mo:enumeration";
import ForkStore "mo:heaviest-chain/ForkStore";
import Peaks "mo:mmr/Peaks";
import StableTrie "mo:stable-trie/Enumeration";

import Chain "Chain";
import Coinbases "Coinbases";
import Uploaders "Uploaders";

module {

  // --- OLD stable shape (inline, so this module stays self-contained) ---

  // The tree of enumeration 0.2.x.
  public type OldTree = ?({ #R; #B }, OldTree, Nat, OldTree);

  public type OldBlobEnumeration = {
    var array : [var Blob];
    var size_ : Nat;
    var tree : OldTree;
  };

  public type OldUploaders = {
    enum : OldBlobEnumeration;
    blocks : List.List<List.List<Blob>>;
    ofHash : Map.Map<Blob, Nat>;
    var anonymousCount : Nat;
  };

  public type OldState = {
    headerTrie : StableTrie.Enumeration;
    txTrie : StableTrie.Enumeration;
    forks : ForkStore.ForkStore<Chain.ForkBlock>;
    uploaders : OldUploaders;
    reorgLog : List.List<Chain.ReorgEvent>;
    coinbasesRegion : Coinbases.Store;
    var coinbasesRegionSize : Nat64;
    var coinbaseBackfillCursor : Nat;
    var tipWork : Nat;
    var bodiesNextHeight : Nat;
    var bodyChunks : ?Chain.BodyChunks;
    chunkTree : Peaks.Peaks;
    var recentTimes : [Nat32];
    var workMemo : Chain.WorkMemo;
    var initialized : Bool;
  };

  // The same tree in 0.3.x's node layout: index << 1, plus 1 if red.
  public func convertTree(t : OldTree) : Enum.Tree = switch t {
    case null null;
    case (?(#R, l, i, r)) ?(convertTree(l), i.toNat32() << 1 | 1, convertTree(r));
    case (?(#B, l, i, r)) ?(convertTree(l), i.toNat32() << 1, convertTree(r));
  };

  public func enumeration(old : OldBlobEnumeration) : Enum.BlobEnumeration.BlobEnumeration {
    // 0.3.x holds at most 2 ** 31 keys (0.2.x: 3 * 2 ** 30). A larger index
    // would not fit into the node field, so refuse to migrate: the trap
    // rejects the upgrade and keeps the old state.
    if (old.size_ >= 2 ** 31) Runtime.trap("Migration: more than 2 ** 31 uploaders, cannot convert the enumeration");
    {
      var array = old.array;
      var size_ = old.size_;
      var tree = convertTree(old.tree);
    };
  };

  public func uploaders(old : OldUploaders) : Uploaders.Uploaders = {
    enum = enumeration(old.enum);
    blocks = old.blocks;
    ofHash = old.ofHash;
    var anonymousCount = old.anonymousCount;
  };

  public func run(old : { chain : OldState }) : { chain : Chain.State } {
    let o = old.chain;
    {
      chain : Chain.State = {
        headerTrie = o.headerTrie;
        txTrie = o.txTrie;
        forks = o.forks;
        uploaders = uploaders(o.uploaders);
        reorgLog = o.reorgLog;
        coinbasesRegion = o.coinbasesRegion;
        var coinbasesRegionSize = o.coinbasesRegionSize;
        var coinbaseBackfillCursor = o.coinbaseBackfillCursor;
        var tipWork = o.tipWork;
        var bodiesNextHeight = o.bodiesNextHeight;
        var bodyChunks = o.bodyChunks;
        chunkTree = o.chunkTree;
        var recentTimes = o.recentTimes;
        var workMemo = o.workMemo;
        var initialized = o.initialized;
      };
    };
  };

};
