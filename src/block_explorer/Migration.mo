// Inline actor migration for the chunk verifier without a backup, on a pool
// of hashers kept across blocks.
//
// Two State changes:
//
//   - The verifier of a chunked upload in progress (`bodyChunks`) loses its
//     `backup` pool, now that a chunk that does not verify traps instead of
//     being undone. `bodyChunks` is a `var` field, so its type has to stay
//     exactly the same across an upgrade, and the verifier is rebuilt here:
//     the same root, peaks (`hasher`), count and done flag, without `backup`.
//     An upload in progress survives the upgrade.
//   - New `chunkHashers`, the pool every block's verifier is put on. With an
//     upload in progress it is that verifier's `hasher` array (the same
//     CHUNK_MAX_DEPTH + 2 hashers), which the upload then goes on using;
//     otherwise a fresh pool.
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
import StableTrie "mo:stable-trie/Enumeration";

import Chain "Chain";
import Coinbases "Coinbases";
import Uploaders "Uploaders";

module {

  // --- OLD stable shape (inline, so this module stays self-contained) ---

  type OldVerifier = {
    root : Blob;
    hasher : [var Hasher.Hasher];
    backup : [var Hasher.Hasher];
    var count : Nat64;
    var done : Bool;
  };

  type OldBodyChunks = {
    hash : Blob;
    height : Nat;
    firstTxIndex : Nat;
    coinbase : Blob;
    verifier : OldVerifier;
  };

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
    var bodyChunks : ?OldBodyChunks;
    var recentTimes : [Nat32];
    var workMemo : Chain.WorkMemo;
    var initialized : Bool;
  };

  func bodyChunks(old : ?OldBodyChunks) : ?Chain.BodyChunks {
    switch old {
      case null null;
      case (?p) ?{
        hash = p.hash;
        height = p.height;
        firstTxIndex = p.firstTxIndex;
        coinbase = p.coinbase;
        verifier = {
          root = p.verifier.root;
          hasher = p.verifier.hasher;
          var count = p.verifier.count;
          var done = p.verifier.done;
        };
      };
    };
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
        var bodyChunks = bodyChunks(o.bodyChunks);
        chunkHashers = switch (o.bodyChunks) {
          case (?p) p.verifier.hasher;
          case null Chain.newChunkHashers();
        };
        var recentTimes = o.recentTimes;
        var workMemo = o.workMemo;
        var initialized = o.initialized;
      };
    };
  };

};
