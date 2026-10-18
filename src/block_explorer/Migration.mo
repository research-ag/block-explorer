// Inline actor migration for the `ForkBody.txids : Blob` → `[Blob]` change.
//
// Only the fork-body representation changes: every other State field passes
// through by reference (the two StableTrie regions, the fork store's
// `byHeight` map, the uploaders enum, the reorg log, and the `var` scalars).
// The transform walks `forks.byId` once, converts each present `ForkBody`
// from a packed txid blob into a `[Blob]` of 32-byte slices, and leaves
// bodies that were never attached as `null`.
//
// Fork bodies are rare in practice (only non-canonical blocks whose uploader
// managed to push the body before the fork died), and this migration is a
// one-shot upgrade — on fresh install the actor's own initializers run and
// this module is never touched.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat8 "mo:core/Nat8";

import ForkStore "mo:heaviest-chain/ForkStore";
import StableTrie "mo:stable-trie/Enumeration";

import Chain "Chain";
import Uploaders "Uploaders";

module {

  // --- The OLD stable shape, defined inline so this module does not depend
  // on any pre-refactor source file. The only field that differs from the
  // current `Chain` types is `OldForkBody.txids`.

  type OldForkBody = {
    txids : Blob;
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

  // Slice a packed txid blob (N × 32 bytes) back into `[Blob]`.
  func unpackTxids(packed : Blob) : [Blob] {
    let n = packed.size() / 32;
    Array.tabulate<Blob>(
      n,
      func(i) = Blob.fromArray(
        Array.tabulate<Nat8>(32, func(j) = packed[i * 32 + j])
      ),
    );
  };

  func convertBody(old : OldForkBody) : Chain.ForkBody = {
    txids = unpackTxids(old.txids);
    firstTxIndex = old.firstTxIndex;
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

  // The forks store is a plain record of two Maps; `byHeight` carries only
  // 32-byte block ids (`[Blob]`), so it passes through unchanged. `byId` has
  // the ForkBlock payload, which we rebuild with the converted bodies.
  func convertForks(old : ForkStore.ForkStore<OldForkBlock>) : ForkStore.ForkStore<Chain.ForkBlock> {
    {
      byId = Map.map<Blob, OldForkBlock, Chain.ForkBlock>(
        old.byId,
        func(_, b) = convertBlock(b),
      );
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
        var tipWork = o.tipWork;
        var bodiesNextHeight = o.bodiesNextHeight;
        var recentTimes = o.recentTimes;
        var workMemo = o.workMemo;
        var initialized = o.initialized;
      };
    };
  };

};
