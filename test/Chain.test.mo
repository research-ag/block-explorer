// @testmode wasi
// Tests for the Chain module: canonical-only stable-trie storage, the
// heap fork store, reorg via removeLast/truncate, the reorg log, and
// uploader tracking.
//
// Strategy
// --------
// Real PoW headers are scarce, so we exercise the fork/reorg machinery
// via `pushUnchecked`, which bypasses consensus rules but still goes
// through the full storage + fork-store + reorg path. `mkHeader` crafts
// arbitrary 80-byte headers; a distinct `nonce` makes each branch hash
// differently.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";

import Header "../src/block_explorer/Header";
import Chain "../src/block_explorer/Chain";
import Merkle "../src/block_explorer/Merkle";
import HeaderValue "../src/block_explorer/HeaderValue";

// --- Test harness ---------------------------------------------------------

let FUTURE_NOW : Int = 9_999_999_999;
let UPLOADER : Principal = Principal.fromText(
  "5yxw4-okdhg-twoqv-qjshi-uammo-kn5yg-guwus-r3u4m-codgm-3lle6-oae"
);
let ANON : Principal = Principal.fromText("2vxsx-fae");

// Full 32-byte keys so synthetic (non-PoW) headers store without
// tripping the production trailing-zero truncation invariant.
func newChain() : Chain.Chain = Chain.emptyForTest();

func isErr(r : Result.Result<Chain.PushOk, Text>) : Bool {
  switch r { case (#err _) true; case _ false };
};

func push(c : Chain.Chain, raw : Blob) : Result.Result<Chain.PushOk, Text> =
  c.pushUnchecked(raw, FUTURE_NOW, UPLOADER);

// --- Synthetic-header builder --------------------------------------------

func writeLE32(buf : [var Nat8], off : Nat, v : Nat32) {
  buf[off] := Nat8.fromNat(Nat32.toNat(v & 0xff));
  buf[off + 1] := Nat8.fromNat(Nat32.toNat((v >> 8) & 0xff));
  buf[off + 2] := Nat8.fromNat(Nat32.toNat((v >> 16) & 0xff));
  buf[off + 3] := Nat8.fromNat(Nat32.toNat((v >> 24) & 0xff));
};

func writeBlob(buf : [var Nat8], off : Nat, src : Blob) {
  var i = 0;
  while (i < src.size()) { buf[off + i] := src[i]; i += 1 };
};

// Build an 80-byte header. `prevHash` is internal (LE) order, 32 bytes,
// matching `Header.headerHashBlob` / `Header.parseHeader`.
func mkHeader(prevHash : Blob, bits : Nat32, time : Nat32, nonce : Nat32) : Blob {
  let buf = VarArray.repeat<Nat8>(0, 80);
  writeLE32(buf, 0, 1); // version
  writeBlob(buf, 4, prevHash); // prev hash (32B, LE internal)
  // merkle root (offset 36) left as 32 zero bytes
  writeLE32(buf, 68, time);
  writeLE32(buf, 72, bits);
  writeLE32(buf, 76, nonce);
  Blob.fromVarArray(buf);
};

// Like mkHeader but with an explicit merkle root (offset 36), so we can
// craft blocks whose body (txid list) verifies.
func mkHeaderM(prevHash : Blob, bits : Nat32, time : Nat32, nonce : Nat32, merkle : Blob) : Blob {
  let buf = VarArray.repeat<Nat8>(0, 80);
  writeLE32(buf, 0, 1);
  writeBlob(buf, 4, prevHash);
  writeBlob(buf, 36, merkle);
  writeLE32(buf, 68, time);
  writeLE32(buf, 72, bits);
  writeLE32(buf, 76, nonce);
  Blob.fromVarArray(buf);
};

func hashOf(raw : Blob) : Blob = Header.headerHashBlob(raw);

// A 32-byte txid that is all `b` bytes.
func txid(b : Nat8) : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func _ = b));

// Concatenate 32-byte txids into a flat hashes blob.
func txids(bs : [Nat8]) : Blob {
  Blob.fromArray(
    Array.tabulate<Nat8>(
      bs.size() * 32,
      func(i) = bs[i / 32],
    )
  );
};

func canon0(c : Chain.Chain) : Chain.StoredBlock {
  switch (c.canonicalAt(0)) {
    case (?b) b;
    case null Runtime.trap("no genesis");
  };
};

let GENESIS_HASH : Blob =
  Header.headerHashBlob(Header.hexToBlob(Header.GENESIS_HEADER_HEX));

// Genesis difficulty (least work per block).
let EASY_BITS : Nat32 = 0x1d00ffff;
// Slightly harder: smaller mantissa => smaller target => more work.
let HARD_BITS : Nat32 = 0x1d00fffe;

// =========================================================================
// Storage / indexing
// =========================================================================

suite(
  "Chain: initial state",
  func() {
    test(
      "starts with genesis only",
      func() {
        let c = newChain();
        assert c.size() == 1;
        assert c.tipHeight() == 0;
        let tip = c.tipBlock();
        assert tip.height == 0;
        assert tip.hash == GENESIS_HASH;
        assert tip.prevHash == ("\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" : Blob);
        assert c.forks().size() == 0;
        assert c.reorgs().size() == 0;
      },
    );

    test(
      "genesis is queryable",
      func() {
        let c = newChain();
        switch (c.canonicalAt(0)) {
          case (?b) assert b.height == 0;
          case null assert false;
        };
        assert c.allAt(0).size() == 1;
        assert c.canonicalAt(1) == null;
        assert c.allAt(1).size() == 0;
        let beHex = Header.bytesToHex(Header.reverse32(GENESIS_HASH));
        switch (c.byHashBE(beHex)) {
          case (?b) assert b.height == 0 and b.isCanonical;
          case null assert false;
        };
      },
    );
  },
);

suite(
  "Chain: synthetic canonical extension",
  func() {
    test(
      "builds a 5-block chain; index == height",
      func() {
        let c = newChain();
        var prev = GENESIS_HASH;
        var i : Nat32 = 1;
        while (i <= 5) {
          let raw = mkHeader(prev, EASY_BITS, 1_700_000_000 + i, i);
          switch (push(c, raw)) {
            case (#ok ok) {
              assert ok.height == Nat32.toNat(i);
              assert ok.is_canonical;
              assert ok.reorg_depth == 0;
            };
            case _ assert false;
          };
          prev := hashOf(raw);
          i += 1;
        };
        assert c.tipHeight() == 5;
        assert c.size() == 6;
        assert c.forks().size() == 0;
        // cumulative work strictly increases
        var prevW : Nat = 0;
        var h = 0;
        while (h <= 5) {
          switch (c.canonicalAt(h)) {
            case (?b) { assert b.cumWork > prevW; prevW := b.cumWork };
            case null assert false;
          };
          h += 1;
        };
      },
    );

    test(
      "rejects duplicate and unknown-parent",
      func() {
        let c = newChain();
        let a1 = mkHeader(GENESIS_HASH, EASY_BITS, 1, 1);
        assert not isErr(push(c, a1));
        assert isErr(push(c, a1)); // duplicate
        let orphan = mkHeader(hashOf(mkHeader(GENESIS_HASH, EASY_BITS, 9, 9)), EASY_BITS, 2, 2);
        assert isErr(push(c, orphan)); // unknown parent
        assert c.size() == 2;
      },
    );
  },
);

// =========================================================================
// Forks without reorg
// =========================================================================

suite(
  "Chain: two-way fork without reorg",
  func() {
    test(
      "equal-work sibling stays a fork; tip unchanged",
      func() {
        let c = newChain();
        let a1 = mkHeader(GENESIS_HASH, EASY_BITS, 1_700_000_000, 1);
        ignore push(c, a1);
        let a2 = mkHeader(hashOf(a1), EASY_BITS, 1_700_000_001, 2);
        ignore push(c, a2);
        let b2 = mkHeader(hashOf(a1), EASY_BITS, 1_700_000_002, 99);
        switch (push(c, b2)) {
          case (#ok ok) {
            assert ok.height == 2;
            assert ok.is_canonical == false;
            assert ok.reorg_depth == 0;
          };
          case _ assert false;
        };
        assert c.allAt(2).size() == 2;
        switch (c.canonicalAt(2)) {
          case (?b) assert b.hash == hashOf(a2);
          case null assert false;
        };
        assert c.tipHeight() == 2;
        let fs = c.forks();
        assert fs.size() == 1;
        assert fs[0].tip_height == 2 and fs[0].length == 1 and fs[0].branch_height == 1;
        assert c.reorgs().size() == 0;
      },
    );

    test(
      "forks() lists all non-canonical tips",
      func() {
        let c = newChain();
        let a1 = mkHeader(GENESIS_HASH, EASY_BITS, 1_700_000_000, 1);
        ignore push(c, a1);
        ignore push(c, mkHeader(hashOf(a1), EASY_BITS, 1_700_000_001, 2)); // a2 (canonical)
        ignore push(c, mkHeader(hashOf(a1), EASY_BITS, 1_700_000_002, 22)); // b2
        ignore push(c, mkHeader(hashOf(a1), EASY_BITS, 1_700_000_003, 222)); // c2
        let fs = c.forks();
        assert fs.size() == 2;
        for (f in fs.vals()) {
          assert f.tip_height == 2 and f.length == 1 and f.branch_height == 1;
        };
        assert c.allAt(2).size() == 3;
      },
    );
  },
);

// =========================================================================
// Reorg
// =========================================================================

suite(
  "Chain: reorg via a longer branch",
  func() {
    test(
      "longer branch takes over; removeLast moves blocks to fork store",
      func() {
        let c = newChain();
        let a1 = mkHeader(GENESIS_HASH, EASY_BITS, 1_700_000_000, 1);
        ignore push(c, a1);
        let a2 = mkHeader(hashOf(a1), EASY_BITS, 1_700_000_001, 2);
        ignore push(c, a2);
        let a3 = mkHeader(hashOf(a2), EASY_BITS, 1_700_000_002, 3);
        ignore push(c, a3);
        assert c.tipHeight() == 3;

        let b2 = mkHeader(hashOf(a1), EASY_BITS, 1_700_000_010, 102);
        switch (push(c, b2)) {
          case (#ok ok) assert not ok.is_canonical and ok.reorg_depth == 0;
          case _ assert false;
        };
        let b3 = mkHeader(hashOf(b2), EASY_BITS, 1_700_000_011, 103);
        ignore push(c, b3); // equal work to A3, no reorg yet
        let b4 = mkHeader(hashOf(b3), EASY_BITS, 1_700_000_012, 104);
        switch (push(c, b4)) {
          case (#ok ok) {
            assert ok.height == 4 and ok.is_canonical and ok.reorg_depth == 2;
          };
          case _ assert false;
        };

        // Canonical chain is now genesis-A1-B2-B3-B4 (index == height).
        assert c.tipHeight() == 4;
        switch (c.canonicalAt(2)) { case (?b) assert b.hash == hashOf(b2); case null assert false };
        switch (c.canonicalAt(3)) { case (?b) assert b.hash == hashOf(b3); case null assert false };
        switch (c.canonicalAt(4)) { case (?b) assert b.hash == hashOf(b4); case null assert false };

        // All A-branch blocks still stored (now as forks).
        assert c.allAt(2).size() == 2;
        assert c.allAt(3).size() == 2;
        assert c.allAt(4).size() == 1;

        // A3 is the lone fork tip, length 2, branched at A1 (height 1).
        let fs = c.forks();
        assert fs.size() == 1;
        assert fs[0].tip_height == 3 and fs[0].length == 2 and fs[0].branch_height == 1;
        assert fs[0].tip_hash_be_hex == Header.bytesToHex(Header.reverse32(hashOf(a3)));

        // exactly one canonical block at height 3
        var canon = 0;
        for (b in c.allAt(3).vals()) if (c.isOnCanonical(b)) canon += 1;
        assert canon == 1;

        // Reorg log records the event.
        let log = c.reorgs();
        assert log.size() == 1;
        assert log[0].common_height == 1;
        assert log[0].fork_length == 3;
        assert log[0].displaced == 2;
        assert log[0].old_tip_height == 3;
        assert log[0].new_tip_height == 4;
        assert log[0].old_tip_hash_be_hex == Header.bytesToHex(Header.reverse32(hashOf(a3)));
        assert log[0].new_tip_hash_be_hex == Header.bytesToHex(Header.reverse32(hashOf(b4)));
        assert log[0].time == FUTURE_NOW;
      },
    );
  },
);

suite(
  "Chain: reorg via a heavier (not longer) branch",
  func() {
    test(
      "equal-length branch with more work per block reorgs to genesis",
      func() {
        let c = newChain();
        let a1 = mkHeader(GENESIS_HASH, EASY_BITS, 1_700_000_000, 1);
        ignore push(c, a1);
        let a2 = mkHeader(hashOf(a1), EASY_BITS, 1_700_000_001, 2);
        ignore push(c, a2);
        let a3 = mkHeader(hashOf(a2), EASY_BITS, 1_700_000_002, 3);
        ignore push(c, a3);
        assert c.tipHeight() == 3;

        let b1 = mkHeader(GENESIS_HASH, HARD_BITS, 1_700_000_010, 1001);
        ignore push(c, b1);
        let b2 = mkHeader(hashOf(b1), HARD_BITS, 1_700_000_011, 1002);
        ignore push(c, b2);
        let b3 = mkHeader(hashOf(b2), HARD_BITS, 1_700_000_012, 1003);
        switch (push(c, b3)) {
          case (#ok ok) {
            assert ok.height == 3 and ok.is_canonical and ok.reorg_depth == 3;
          };
          case _ assert false;
        };

        switch (c.canonicalAt(1)) { case (?b) assert b.hash == hashOf(b1); case null assert false };
        switch (c.canonicalAt(3)) { case (?b) assert b.hash == hashOf(b3); case null assert false };
        assert c.tipHeight() == 3;

        let fs = c.forks();
        assert fs.size() == 1;
        assert fs[0].tip_height == 3 and fs[0].length == 3 and fs[0].branch_height == 0;

        let log = c.reorgs();
        assert log.size() == 1;
        assert log[0].common_height == 0 and log[0].displaced == 3 and log[0].fork_length == 3;
      },
    );
  },
);

// =========================================================================
// Uploader tracking (mo:enumeration registry)
// =========================================================================

suite(
  "Chain: uploader tracking",
  func() {
    test(
      "attributes blocks by hash; anonymous defaults",
      func() {
        let c = newChain();
        let a1 = mkHeader(GENESIS_HASH, EASY_BITS, 1, 1);
        ignore c.pushUnchecked(a1, FUTURE_NOW, UPLOADER);
        let a2 = mkHeader(hashOf(a1), EASY_BITS, 2, 2);
        ignore c.pushUnchecked(a2, FUTURE_NOW, ANON);

        // Non-anonymous block resolves to its uploader.
        assert c.uploaderOf(hashOf(a1)) == UPLOADER;
        // Anonymous block resolves to the anonymous principal (default).
        assert c.uploaderOf(hashOf(a2)) == ANON;

        // blocks_by_uploader returns the uploader's hashes, newest first.
        let mine = c.blocksByUploader(UPLOADER, 0, 10);
        assert mine.size() == 1;
        assert mine[0] == hashOf(a1);
        // anonymous is not individually tracked.
        assert c.blocksByUploader(ANON, 0, 10).size() == 0;

        // Stats include both genesis's uploader ("aaaaa-aa"), UPLOADER, ANON.
        let stats = c.uploaderStats();
        var anonCount = 0;
        var mineCount = 0;
        for ((p, n) in stats.vals()) {
          if (p == ANON) anonCount := n;
          if (p == UPLOADER) mineCount := n;
        };
        assert anonCount == 1;
        assert mineCount == 1;
      },
    );
  },
);

// =========================================================================
// Real reorg from a historical Bitcoin fork (production 28-byte keys)
// =========================================================================
//
// Real orphan headers taken from the repo's `stale_headers` file (the
// losing side of historical mainnet forks), anchored at their common
// ancestor — mainnet block 225429, whose 80-byte header is embedded as
// the checkpoint root. All of these are valid PoW, so their hashes end
// in >=4 zero bytes and exercise the PRODUCTION 28-byte key truncation
// path (unlike the synthetic suites above, which use full 32-byte keys).
//
//   ancestor 225429 (…2546d006)
//     ├─ B (…80e57f7f)              single-block orphan
//     ├─ C (…994e8960)              single-block orphan
//     └─ A (…2df480c023) ─ A2 (…0eca056c3)   two-block orphan branch
//
// Feeding B first makes it canonical; the heavier two-block A→A2 branch
// then triggers a real reorg (B is demoted, A/A2 promoted).

let ANCESTOR_HEX = "020000007ffca90e8dc10de4161a864dd104161c154b89897d79048a3a000000000000006503b7c6f695e6a2af6d01553c7d58163bf177fe636eb5c7e9a6a506577fc246c3533e514bd7031a8c33f2ac";
// A (file idx 1867) and its child A2 (idx 1864) — the winning branch.
let A_HEX = "0200000006d04625789f74813125765744bf8c4e0900893328ca98ce66030000000000003e388c16b9a976b142c1b98eb5a2f3cb4ed46bdab5020cfcab83fc446dd6d5db0d5d3e514bd7031a7a48cb17";
let A2_HEX = "0200000023c080f42d110bc73a9498520c80448b6f5533ddfc65b1505c01000000000000c859fdead5df264978a0ae68fef2fc28d274f9acb5c15c98ea31d74ed2c5460bcb5e3e514bd7031a8be4f564";
// B (idx 1865) and C (idx 1866) — single-block sibling orphans.
let B_HEX = "0200000006d04625789f74813125765744bf8c4e0900893328ca98ce66030000000000007d0a60c5177d95e08ab82903dc7aef1fa7f63c17c3aba40e4826f252580051a687583e514bd7031a865b53df";
let C_HEX = "0200000006d04625789f74813125765744bf8c4e0900893328ca98ce6603000000000000a6eeff902159dffcb4229785324170c04aca85096c288225c10e8071d68bc62e27583e514bd7031a269c603c";

suite(
  "Chain: real reorg from a historical Bitcoin fork (28-byte keys)",
  func() {
    test(
      "heavier two-block orphan branch reorgs over a one-block branch",
      func() {
        // Anchor at the real common ancestor, production truncation path.
        let c = Chain.fromRootHex(ANCESTOR_HEX, 28);
        assert c.tipHeight() == 0;
        assert c.forks().size() == 0;

        let bRaw = Header.hexToBlob(B_HEX);
        let cRaw = Header.hexToBlob(C_HEX);
        let aRaw = Header.hexToBlob(A_HEX);
        let a2Raw = Header.hexToBlob(A2_HEX);

        // B extends the canonical chain (real header, 28-byte key).
        switch (c.pushUnchecked(bRaw, FUTURE_NOW, UPLOADER)) {
          case (#ok ok) assert ok.height == 1 and ok.is_canonical and ok.reorg_depth == 0;
          case _ assert false;
        };
        // C and A are equal-work siblings of B → forks, no reorg.
        switch (c.pushUnchecked(cRaw, FUTURE_NOW, UPLOADER)) {
          case (#ok ok) assert not ok.is_canonical and ok.reorg_depth == 0;
          case _ assert false;
        };
        switch (c.pushUnchecked(aRaw, FUTURE_NOW, UPLOADER)) {
          case (#ok ok) assert not ok.is_canonical and ok.reorg_depth == 0;
          case _ assert false;
        };
        assert c.tipHeight() == 1;
        assert c.allAt(1).size() == 3; // B canonical + C, A forks
        assert c.forks().size() == 2;

        // A2 makes the A-branch heavier → real reorg.
        switch (c.pushUnchecked(a2Raw, FUTURE_NOW, UPLOADER)) {
          case (#ok ok) assert ok.height == 2 and ok.is_canonical and ok.reorg_depth == 1;
          case _ assert false;
        };

        // Canonical chain is now ancestor → A → A2 (round-tripped through
        // the 28-byte truncation, so the full hashes must still match).
        assert c.tipHeight() == 2;
        switch (c.canonicalAt(1)) { case (?b) assert b.hash == hashOf(aRaw); case null assert false };
        switch (c.canonicalAt(2)) { case (?b) assert b.hash == hashOf(a2Raw); case null assert false };
        assert c.allAt(1).size() == 3; // A canonical + B, C forks
        assert c.allAt(2).size() == 1;

        // B and C are now the fork tips (each one block off the ancestor).
        let fs = c.forks();
        assert fs.size() == 2;
        for (f in fs.vals()) assert f.tip_height == 1 and f.length == 1 and f.branch_height == 0;

        // Reorg log records the switch.
        let log = c.reorgs();
        assert log.size() == 1;
        assert log[0].common_height == 0;
        assert log[0].displaced == 1;
        assert log[0].fork_length == 2;
        assert log[0].old_tip_height == 1;
        assert log[0].new_tip_height == 2;
        assert log[0].old_tip_hash_be_hex == Header.bytesToHex(Header.reverse32(hashOf(bRaw)));
        assert log[0].new_tip_hash_be_hex == Header.bytesToHex(Header.reverse32(hashOf(a2Raw)));
      },
    );
  },
);

// =========================================================================
// Block bodies (canonical transaction index)
// =========================================================================

suite(
  "Chain: block bodies",
  func() {
    test(
      "canonical upload indexes in chain order; tx_count and txid lookup",
      func() {
        let c = newChain(); // 32-byte keys, real genesis
        let g = canon0(c);
        let genMerkle = HeaderValue.merkleOf(g.value); // genesis coinbase txid

        // Genesis body: a single coinbase tx (root of [coinbase] == coinbase).
        switch (c.pushBody(g.hash, 1, genMerkle)) {
          case (#ok ok) assert ok.height == 0 and ok.tx_count == 1 and ok.first_tx_index == 0 and ok.canonical_indexed and not ok.duplicate;
          case (#err _) assert false;
        };
        assert c.bodiesHeight() == 1;
        assert c.totalIndexedTxids() == 1;
        assert c.txCountAt(0) == ?1;
        assert c.lookupTxid(genMerkle).canonical == ?0;

        // Block 1 with three distinct txs; header merkle crafted to match.
        let t = txids([1, 2, 3]);
        let h1 = mkHeaderM(g.hash, EASY_BITS, 1_700_000_000, 1, Merkle.root(t, 3));
        switch (push(c, h1)) { case (#ok ok) assert ok.is_canonical; case _ assert false };
        switch (c.pushBody(hashOf(h1), 3, t)) {
          case (#ok ok) assert ok.height == 1 and ok.tx_count == 3 and ok.first_tx_index == 1 and ok.canonical_indexed;
          case (#err _) assert false;
        };
        assert c.bodiesHeight() == 2;
        assert c.totalIndexedTxids() == 4;
        assert c.txCountAt(1) == ?3;
        assert c.txCountOfHash(hashOf(h1)) == ?3;
        assert c.lookupTxid(txid(2)).canonical == ?1;
        assert c.lookupTxid(txid(9)).canonical == null;
        assert c.forkBodyCount() == 0;
      },
    );

    test(
      "out-of-order canonical and gapped fork bodies are rejected",
      func() {
        let c = newChain();
        let g = canon0(c);
        let genMerkle = HeaderValue.merkleOf(g.value);

        let t = txids([1, 2]);
        let h1 = mkHeaderM(g.hash, EASY_BITS, 1, 1, Merkle.root(t, 2));
        ignore push(c, h1);

        // Block 1 body before genesis: rejected (ancestor body unknown).
        switch (c.pushBody(hashOf(h1), 2, t)) { case (#err _) {}; case _ assert false };
        assert c.bodiesHeight() == 0;
        // Genesis first, then block 1 — strict chain order.
        switch (c.pushBody(g.hash, 1, genMerkle)) { case (#ok ok) assert ok.canonical_indexed; case _ assert false };
        switch (c.pushBody(hashOf(h1), 2, t)) { case (#ok ok) assert ok.canonical_indexed; case _ assert false };
        assert c.bodiesHeight() == 2;
        // Extend the canonical chain (header only) so the 2-block fork below
        // ties on work and does not trigger a reorg.
        ignore push(c, mkHeader(hashOf(h1), EASY_BITS, 2, 2));

        // Fork chain F1 -> F2 off genesis; F2's body needs F1's body first.
        let f1 = mkHeaderM(g.hash, EASY_BITS, 100, 9, Merkle.root(txids([30]), 1));
        ignore push(c, f1);
        let tf2 = txids([31, 32]);
        let f2 = mkHeaderM(hashOf(f1), EASY_BITS, 101, 10, Merkle.root(tf2, 2));
        ignore push(c, f2);

        // F2 body before F1 body: rejected (fork ancestor body unknown).
        switch (c.pushBody(hashOf(f2), 2, tf2)) { case (#err _) {}; case _ assert false };
        // F1 body OK (parent genesis has a body); stored in the fork record.
        switch (c.pushBody(hashOf(f1), 1, txids([30]))) {
          case (#ok ok) assert not ok.canonical_indexed and ok.first_tx_index == 1;
          case _ assert false;
        };
        // Now F2 body OK (parent F1 has a body); F = F(F1) + N(F1) = 1 + 1.
        switch (c.pushBody(hashOf(f2), 2, tf2)) {
          case (#ok ok) assert not ok.canonical_indexed and ok.first_tx_index == 2;
          case _ assert false;
        };
        assert c.forkBodyCount() == 2;
      },
    );

    test(
      "fork-block body is retained and auto-indexed across a reorg",
      func() {
        let c = newChain();
        let g = canon0(c);
        ignore c.pushBody(g.hash, 1, HeaderValue.merkleOf(g.value));

        // A1 canonical, body of 2 txs.
        let tA = txids([10, 11]);
        let a1 = mkHeaderM(g.hash, EASY_BITS, 1_700_000_000, 1, Merkle.root(tA, 2));
        ignore push(c, a1);
        ignore c.pushBody(hashOf(a1), 2, tA);
        assert c.totalIndexedTxids() == 3; // genesis + A1

        // Competing fork B1 off genesis; upload its body while non-canonical.
        let tB = txids([20, 21, 22]);
        let b1 = mkHeaderM(g.hash, EASY_BITS, 1_700_000_010, 101, Merkle.root(tB, 3));
        ignore push(c, b1);
        switch (c.pushBody(hashOf(b1), 3, tB)) {
          case (#ok ok) assert not ok.canonical_indexed and not ok.duplicate;
          case _ assert false;
        };
        assert c.forkBodyCount() == 1;
        assert c.txCountOfHash(hashOf(b1)) == ?3; // queryable while a fork

        // B2 makes the B branch heavier -> reorg.
        let b2 = mkHeader(hashOf(b1), EASY_BITS, 1_700_000_011, 102);
        switch (push(c, b2)) { case (#ok ok) assert ok.is_canonical and ok.reorg_depth == 1; case _ assert false };

        // B1 (body was known) is auto-indexed; A1's body is retained in the
        // fork store; B2 has no body.
        assert c.bodiesHeight() == 2; // genesis + B1
        assert c.txCountAt(1) == ?3; // B1, now canonical & indexed
        assert c.txCountAt(2) == null; // B2: no body
        assert c.lookupTxid(txid(20)).canonical == ?1;
        // A1 demoted: tx no longer canonical, but found in the fork-body store.
        let loc = c.lookupTxid(txid(10));
        assert loc.canonical == null;
        assert loc.forks.size() == 1 and loc.forks[0] == hashOf(a1);
        assert c.totalIndexedTxids() == 4; // genesis(1) + B1(3)
        assert c.txCountOfHash(hashOf(a1)) == ?2; // A1 body retained on heap
        assert c.forkBodyCount() == 1; // A1's body (B1 drained out)
      },
    );

    test(
      "merkle mismatch and unknown header rejected; duplicate no-ops",
      func() {
        let c = newChain();
        let g = canon0(c);
        ignore c.pushBody(g.hash, 1, HeaderValue.merkleOf(g.value));

        let t = txids([1, 2]);
        let h1 = mkHeaderM(g.hash, EASY_BITS, 1, 1, Merkle.root(t, 2));
        ignore push(c, h1);

        // Wrong txids -> merkle mismatch.
        switch (c.pushBody(hashOf(h1), 2, txids([5, 6]))) { case (#err _) {}; case _ assert false };
        // Unknown header.
        switch (c.pushBody(txid(99), 1, txid(99))) { case (#err _) {}; case _ assert false };
        // Correct body indexes it.
        switch (c.pushBody(hashOf(h1), 2, t)) { case (#ok ok) assert ok.canonical_indexed and not ok.duplicate; case _ assert false };
        // Re-upload -> duplicate no-op.
        switch (c.pushBody(hashOf(h1), 2, t)) { case (#ok ok) assert ok.duplicate; case _ assert false };
        assert c.bodiesHeight() == 2;
      },
    );
  },
);
