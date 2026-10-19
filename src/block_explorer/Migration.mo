// Inline actor migration for the coinbase-storage change.
//
// Three State additions that need defaulting from the pre-change shape:
//   * `coinbasesRegion : Region` — fresh empty region
//   * `coinbasesRegionSize : Nat64` — 0
//   * `coinbaseBackfillCursor : Nat` — 0 (backfill starts from genesis)
//
// And one ForkBody field: `coinbase : ?Blob` — null for every existing
// fork body (none were received with a coinbase before this change).
//
// Everything else — the two StableTrie regions, forks store maps (apart
// from the ForkBody rewrite), uploaders, reorg log, and all the `var`
// scalars — passes through by reference. Fork bodies are rare in
// practice, so this migration touches very few entries in a real
// deployment.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";

import ForkStore "mo:heaviest-chain/ForkStore";
import StableTrie "mo:stable-trie/Enumeration";

import Chain "Chain";
import Uploaders "Uploaders";

module {

  // --- OLD stable shape --- (inline, so this module stays self-contained)

  type OldForkBody = {
    txids : [Blob];
    firstTxIndex : Nat;
  };

  type OldForkBlock = {
    hash : Blob;
    prevHash : Blob;
    version : Nat32;
    merkle : Blob;
    time : Nat32;
    bits : Nat32;
    nonce : Nat32;
    height : Nat;
    cumWork : Nat;
    firstSeen : Nat32;
    body : ?OldForkBody;
  };

  type OldState = {
    headerTrie : StableTrie.Enumeration;
    txTrie : StableTrie.Enumeration;
    forks : ForkStore.ForkStore<OldForkBlock>;
    uploaders : Uploaders.Uploaders;
    reorgLog : List.List<Chain.ReorgEvent>;
    var tipWork : Nat;
    var bodiesNextHeight : Nat;
    var recentTimes : [Nat32];
    var workMemo : Chain.WorkMemo;
    var initialized : Bool;
  };

  func convertBody(old : OldForkBody) : Chain.ForkBody = {
    txids = old.txids;
    firstTxIndex = old.firstTxIndex;
    coinbase = null;  // never received a coinbase before this upgrade
  };

  func convertBlock(old : OldForkBlock) : Chain.ForkBlock = {
    hash = old.hash;
    prevHash = old.prevHash;
    version = old.version;
    merkle = old.merkle;
    time = old.time;
    bits = old.bits;
    nonce = old.nonce;
    height = old.height;
    cumWork = old.cumWork;
    firstSeen = old.firstSeen;
    body = switch (old.body) {
      case null null;
      case (?b) ?convertBody(b);
    };
  };

  func convertForks(old : ForkStore.ForkStore<OldForkBlock>) : ForkStore.ForkStore<Chain.ForkBlock> {
    {
      byId = old.byId.map<Blob, OldForkBlock, Chain.ForkBlock>(func(_, b) = convertBlock(b));
      byHeight = old.byHeight;
    };
  };

  public func run(old : { chain : OldState }) : { chain : Chain.State } {
    let o = old.chain;
    {
      chain : Chain.State = {
        headerTrie = o.headerTrie;
        txTrie = o.txTrie;
        forks = convertForks(o.forks);
        uploaders = o.uploaders;
        reorgLog = o.reorgLog;
        coinbasesRegion = Region.new();
        var coinbasesRegionSize : Nat64 = 0;
        var coinbaseBackfillCursor = 0;
        var tipWork = o.tipWork;
        var bodiesNextHeight = o.bodiesNextHeight;
        var recentTimes = o.recentTimes;
        var workMemo = o.workMemo;
        var initialized = o.initialized;
      };
    };
  };

};
