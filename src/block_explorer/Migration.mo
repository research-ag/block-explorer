// Inline actor migration for chunked body uploads (push_body_chunk).
//
// One State addition: `bodyChunks : ?Chain.BodyChunks`, the chunked upload
// in progress, which starts out as none.
//
// Everything else (the two StableTrie regions, the fork store, uploaders,
// the reorg log, the coinbase region and all the `var` scalars) passes
// through by reference. The whole `chain` record must be rebuilt because it
// is a single bundled stable variable: a field left out here would be lost.
//
// Delete this file and the `(with migration = ...)` clause in main.mo once
// the upgrade has run on mainnet.

import List "mo:core/List";

import ForkStore "mo:heaviest-chain/ForkStore";
import StableTrie "mo:stable-trie/Enumeration";

import Chain "Chain";
import Coinbases "Coinbases";
import Uploaders "Uploaders";

module {

  // --- OLD stable shape (inline, so this module stays self-contained) ---

  type OldState = {
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
    var recentTimes : [Nat32];
    var workMemo : Chain.WorkMemo;
    var initialized : Bool;
  };

  public func run(old : { chain : OldState }) : { chain : Chain.State } {
    let o = old.chain;
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
        var bodyChunks = null;
        var recentTimes = o.recentTimes;
        var workMemo = o.workMemo;
        var initialized = o.initialized;
      };
    };
  };

};
