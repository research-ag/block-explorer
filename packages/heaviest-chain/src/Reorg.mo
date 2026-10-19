// Fork-choice and reorg for heaviest-chain protocols, over an ABSTRACT
// canonical chain. The algorithm knows about heights, tips, forks and
// weights — never about storage or block representation.
//
// The caller's world is described by two small records:
//
//   Accessors<B> — the only three things known about a block: its id, its
//     parent's id, and its height. `B` is otherwise opaque, so it can carry
//     any payload (the demote/promote callbacks see the full value).
//
//   Canonical<B> — the abstract canonical chain, an append-only sequence
//     indexed by height. `demoteTip` must remove the tip AND return it as a
//     `B` (with whatever payload should survive into the fork set);
//     `append` must make a fork block canonical (persist it, update caches,
//     whatever the embedder needs).
//
// Reorg procedure (`maybeReorg`), given a fork-branch tip that may now be
// the heaviest:
//   1. Weigh: if newWeight <= tipWeight, do nothing (null).
//   2. Find the common ancestor: walk the branch tip-down through the fork
//      store; the parent of a branch block at height h is canonical iff the
//      canonical id at h-1 equals it — an index compare, no search.
//   3. beforeRollback(commonHeight): caller hook while the doomed canonical
//      blocks are still readable (e.g. extract payloads to demote).
//   4. Roll back: demoteTip each canonical block above the common ancestor
//      into the fork store.
//   5. afterRollback(): caller hook (e.g. rebuild tip-derived caches).
//   6. Promote the branch ancestor-first: remove from the fork store,
//      append to canonical.
// Returns the summary, or traps if the fork store is inconsistent (a
// branch parent neither in the fork store nor canonical at its height).

import List "mo:core/List";
import Runtime "mo:core/Runtime";

import ForkStore "ForkStore";

module {

  public type Accessors<B> = {
    id : B -> Blob;
    parent : B -> Blob;
    height : B -> Nat;
  };

  public type Canonical<B> = {
    tipHeight : () -> Nat;
    idAt : Nat -> ?Blob; // id of the canonical block at a height
    append : B -> (); // promote a fork block to the canonical tip
    demoteTip : () -> B; // remove the canonical tip, return it as a fork block
  };

  public type Hooks = {
    beforeRollback : (commonHeight : Nat) -> ();
    afterRollback : () -> ();
  };

  public func noHooks() : Hooks = {
    beforeRollback = func(_ : Nat) {};
    afterRollback = func() {};
  };

  public type ReorgEvent = {
    commonHeight : Nat; // height of the last shared canonical block
    displaced : Nat; // canonical blocks rolled back
    promoted : Nat; // branch blocks made canonical
  };

  // Switch the canonical chain to the branch ending at `newTipId` (which
  // must already be in `forks`) iff `newWeight > tipWeight`. Returns the
  // summary of what happened, or null if the branch is not heavier.
  public func maybeReorg<B>(
    forks : ForkStore.ForkStore<B>,
    acc : Accessors<B>,
    canon : Canonical<B>,
    hooks : Hooks,
    newTipId : Blob,
    newWeight : Nat,
    tipWeight : Nat,
  ) : ?ReorgEvent {
    if (newWeight <= tipWeight) return null;

    // 1. Walk the new branch from its tip down to the common ancestor (the
    //    first block whose parent is canonical). `branch` is tip-first.
    let tipIdx = canon.tipHeight();
    let branch = List.empty<B>();
    var curId = newTipId;
    var commonHeight : Nat = 0;
    label findCommon loop {
      let b = switch (ForkStore.get(forks, curId)) {
        case (?x) x;
        case null Runtime.trap("maybeReorg: branch block missing from fork store");
      };
      List.add(branch, b);
      let h = acc.height(b);
      // The branch block's parent is canonical iff the canonical entry at
      // its known height matches — an index read, not a search.
      if (h >= 1 and (h - 1 : Nat) <= tipIdx) {
        switch (canon.idAt(h - 1)) {
          case (?cid) if (cid == acc.parent(b)) {
            commonHeight := h - 1;
            break findCommon;
          };
          case _ {};
        };
      };
      curId := acc.parent(b);
    };

    let displaced : Nat = canon.tipHeight() - commonHeight;

    // 2. Caller hook while the doomed canonical blocks are still readable.
    hooks.beforeRollback(commonHeight);

    // 3. Roll back the canonical tip into the fork store, one block at a time.
    while (canon.tipHeight() > commonHeight) {
      let d = canon.demoteTip();
      ForkStore.add(forks, acc.id(d), acc.height(d), d);
    };

    hooks.afterRollback();

    // 4. Append the new branch (ancestor-first) into the canonical chain.
    var k = List.size(branch);
    while (k > 0) {
      k -= 1;
      let b = switch (List.get(branch, k)) {
        case (?x) x;
        case null Runtime.trap("maybeReorg: branch index out of range");
      };
      ForkStore.remove(forks, acc.id(b), acc.height(b));
      canon.append(b);
    };

    ?{ commonHeight; displaced; promoted = List.size(branch) };
  };

};
