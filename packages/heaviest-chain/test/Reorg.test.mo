// Synthetic fork-choice tests: a toy block type and a List-backed canonical
// chain exercise the generic algorithm end to end.

import { test; suite } "mo:test";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";

import ForkStore "../src/ForkStore";
import Reorg "../src/Reorg";

type B = { id : Blob; parent : Blob; height : Nat; tag : Text };

func bid(n : Nat8) : Blob = Blob.fromArray([n]);

let acc : Reorg.Accessors<B> = {
  id = func(b : B) : Blob = b.id;
  parent = func(b : B) : Blob = b.parent;
  height = func(b : B) : Nat = b.height;
};

// A List-backed canonical chain capturing demote/append order.
func mkWorld() : (List.List<B>, Reorg.Canonical<B>, ForkStore.ForkStore<B>) {
  let canon = List.empty<B>();
  let forks = ForkStore.empty<B>();
  let ops : Reorg.Canonical<B> = {
    tipHeight = func() : Nat = List.size(canon) - 1 : Nat;
    idAt = func(h : Nat) : ?Blob {
      switch (List.get(canon, h)) { case (?b) ?b.id; case null null };
    };
    append = func(b : B) { List.add(canon, b) };
    demoteTip = func() : B {
      switch (List.removeLast(canon)) {
        case (?b) b;
        case null Runtime.trap("demote on empty");
      };
    };
  };
  (canon, ops, forks);
};

func blk(id : Nat8, parent : Nat8, height : Nat, tag : Text) : B = {
  id = bid(id); parent = bid(parent); height; tag;
};

suite(
  "heaviest-chain reorg",
  func() {
    test(
      "not heavier / tie: no reorg, nothing mutated",
      func() {
        let (canon, ops, forks) = mkWorld();
        List.add(canon, blk(0, 255, 0, "g"));
        List.add(canon, blk(1, 0, 1, "a1"));
        ForkStore.add(forks, bid(11), 1, blk(11, 0, 1, "b1"));
        assert Reorg.maybeReorg(forks, acc, ops, Reorg.noHooks(), bid(11), 5, 10) == null;
        assert Reorg.maybeReorg(forks, acc, ops, Reorg.noHooks(), bid(11), 10, 10) == null;
        assert List.size(canon) == 2;
        assert ForkStore.size(forks) == 1;
      },
    );
    test(
      "heavier 2-block branch displaces 1-block tip",
      func() {
        let (canon, ops, forks) = mkWorld();
        List.add(canon, blk(0, 255, 0, "g"));
        List.add(canon, blk(1, 0, 1, "a1"));
        // branch b1 <- b2 forking off genesis
        ForkStore.add(forks, bid(11), 1, blk(11, 0, 1, "b1"));
        ForkStore.add(forks, bid(12), 11, blk(12, 11, 2, "b2"));
        let ev = switch (Reorg.maybeReorg(forks, acc, ops, Reorg.noHooks(), bid(12), 20, 10)) {
          case (?e) e;
          case null { assert false; Runtime.trap("") };
        };
        assert ev.commonHeight == 0;
        assert ev.displaced == 1;
        assert ev.promoted == 2;
        // canonical is now g, b1, b2
        assert List.size(canon) == 3;
        assert ops.idAt(1) == ?bid(11);
        assert ops.idAt(2) == ?bid(12);
        // a1 demoted into the fork store; branch removed from it
        assert ForkStore.contains(forks, bid(1));
        assert not ForkStore.contains(forks, bid(11));
        assert not ForkStore.contains(forks, bid(12));
        assert ForkStore.size(forks) == 1;
      },
    );
    test(
      "deep reorg: payload survives demotion and hook order is correct",
      func() {
        let (canon, ops, forks) = mkWorld();
        List.add(canon, blk(0, 255, 0, "g"));
        List.add(canon, blk(1, 0, 1, "a1"));
        List.add(canon, blk(2, 1, 2, "a2"));
        List.add(canon, blk(3, 2, 3, "a3"));
        // heavier branch off a1: c2 <- c3 <- c4
        ForkStore.add(forks, bid(21), 1, blk(21, 1, 2, "c2"));
        ForkStore.add(forks, bid(22), 21, blk(22, 21, 3, "c3"));
        ForkStore.add(forks, bid(23), 22, blk(23, 22, 4, "c4"));
        let events = List.empty<Text>();
        let hooks : Reorg.Hooks = {
          beforeRollback = func(common : Nat) {
            assert common == 1;
            // doomed canonical blocks still readable here
            assert ops.idAt(3) == ?bid(3);
            List.add(events, "before");
          };
          afterRollback = func() {
            // rollback done, promotion not yet started
            assert ops.tipHeight() == 1;
            List.add(events, "after");
          };
        };
        let ev = switch (Reorg.maybeReorg(forks, acc, ops, hooks, bid(23), 99, 50)) {
          case (?e) e;
          case null { assert false; Runtime.trap("") };
        };
        assert ev.commonHeight == 1;
        assert ev.displaced == 2;
        assert ev.promoted == 3;
        assert List.toArray(events) == ["before", "after"];
        assert ops.tipHeight() == 4;
        assert ops.idAt(2) == ?bid(21);
        assert ops.idAt(4) == ?bid(23);
        // demoted a2/a3 are in the fork store with payload intact
        switch (ForkStore.get(forks, bid(3))) {
          case (?b) assert b.tag == "a3";
          case null assert false;
        };
        assert ForkStore.size(forks) == 2;
      },
    );
  },
);
