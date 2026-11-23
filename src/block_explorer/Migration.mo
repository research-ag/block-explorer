// Inline actor migration to mmr's Chunks verifier on a caller-owned tree
// (Chunks.onTree, without a backup).
//
// Two State changes:
//
//   - `chunkHashers`, the pool every block's verifier was put on, becomes
//     `chunkTree`, a `Peaks` record on the same hashers (double SHA-256).
//   - The verifier of a chunked upload in progress (`bodyChunks`) becomes a
//     `Chunks.Verifier`: the same root and done flag, its peaks and count as
//     the tree (which IS `chunkTree`, the same record), no backup, Bitcoin's
//     fill (#copy) and equal-sibling checks, not broken. `bodyChunks` is a
//     `var` field, so its type has to match exactly, and it is rebuilt here.
//     An upload in progress survives the upgrade and goes on on the tree.
//
// Everything else (the two StableTrie regions, the fork store, uploaders,
// the reorg log, the coinbase region and all the `var` scalars) passes
// through by reference. The whole `chain` record must be rebuilt because it
// is a single bundled stable variable: a field left out here would be lost.
//
// Delete this file and the `(with migration = ...)` clause in main.mo once
// the upgrade has run on mainnet.

import List "mo:core/List";

import Hasher "mo:sha2/Hasher/Sha256";
import ForkStore "mo:heaviest-chain/ForkStore";
import Peaks "mo:mmr/Peaks";
import StableTrie "mo:stable-trie/Enumeration";

import Chain "Chain";
import Coinbases "Coinbases";
import Uploaders "Uploaders";

module {

  // --- OLD stable shape (inline, so this module stays self-contained) ---

  public type OldVerifier = {
    root : Blob;
    hasher : [var Hasher.Hasher];
    var count : Nat64;
    var done : Bool;
  };

  public type OldBodyChunks = {
    hash : Blob;
    height : Nat;
    firstTxIndex : Nat;
    coinbase : Blob;
    verifier : OldVerifier;
  };

  public type OldState = {
    headerTrie : StableTrie.Enumeration;
    txTrie : StableTrie.Enumeration;
    forks : ForkStore.ForkStore<Chain.ForkBlock>;
    uploaders : Uploaders.Uploaders;
    reorgLog : List.List<Chain.ReorgEvent>;
    coinbasesRegion : Coinbases.Store;
    var coinbasesRegionSize : Nat64;
    var coinbaseBackfillCursor : Nat;
    var tipWork : Nat;
    var bodiesNextHeight : Nat;
    var bodyChunks : ?OldBodyChunks;
    chunkHashers : [var Hasher.Hasher];
    var recentTimes : [Nat32];
    var workMemo : Chain.WorkMemo;
    var initialized : Bool;
  };

  public func run(old : { chain : OldState }) : { chain : Chain.State } {
    let o = old.chain;
    // The tree, on the hashers that hold the peaks of the upload in
    // progress, if any (they are the pool's: every verifier was put on it).
    let tree : Peaks.Peaks = switch (o.bodyChunks) {
      case (?p) ({ hasher = p.verifier.hasher; double = true; var count = p.verifier.count });
      case null ({ hasher = o.chunkHashers; double = true; var count = 0 });
    };
    let bodyChunks : ?Chain.BodyChunks = switch (o.bodyChunks) {
      case null null;
      case (?p) ?{
        hash = p.hash;
        height = p.height;
        firstTxIndex = p.firstTxIndex;
        coinbase = p.coinbase;
        verifier = {
          root = p.verifier.root;
          tree;
          backup = null;
          fill = #copy;
          checked = true;
          var done = p.verifier.done;
          var failed = false;
        };
      };
    };
    {
      chain : Chain.State = {
        headerTrie = o.headerTrie;
        txTrie = o.txTrie;
        forks = o.forks;
        uploaders = o.uploaders;
        reorgLog = o.reorgLog;
        coinbasesRegion = o.coinbasesRegion;
        var coinbasesRegionSize = o.coinbasesRegionSize;
        var coinbaseBackfillCursor = o.coinbaseBackfillCursor;
        var tipWork = o.tipWork;
        var bodiesNextHeight = o.bodiesNextHeight;
        var bodyChunks;
        chunkTree = tree;
        var recentTimes = o.recentTimes;
        var workMemo = o.workMemo;
        var initialized = o.initialized;
      };
    };
  };

};
