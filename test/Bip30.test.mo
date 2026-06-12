// @testmode wasi
// BIP30 compressed-block scheme, verified at the REAL heights: drives a
// synthetic chain past 91,880 replicating both duplicate-coinbase pairs
// (91722/91880 and 91812/91842) and asserts counts, listings, attribution
// (matches Esplora on both pairs) and trap-free locations. Slow (~18 s) —
// the 92k-block build dominates.
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Sha256 "mo:sha2/Sha256";
import VarArray "mo:core/VarArray";

import Header "mo:btc-light/Header";
import Merkle "mo:btc-light/Merkle";
import HeaderValue "../src/block_explorer/HeaderValue";
import Chain "../src/block_explorer/Chain";

let SHA = Sha256.Digest(#sha256);
let NOW : Int = 9_999_999_999;
let UP = Principal.fromText("aaaaa-aa");
let EASY : Nat32 = 0x207fffff;

func writeLE32(buf : [var Nat8], off : Nat, v : Nat32) {
  buf[off] := Nat8.fromNat(Nat32.toNat(v & 0xff));
  buf[off+1] := Nat8.fromNat(Nat32.toNat((v >> 8) & 0xff));
  buf[off+2] := Nat8.fromNat(Nat32.toNat((v >> 16) & 0xff));
  buf[off+3] := Nat8.fromNat(Nat32.toNat((v >> 24) & 0xff));
};
func mkHeader(prev : Blob, time : Nat32, merkle : Blob) : Blob {
  let buf = VarArray.repeat<Nat8>(0, 80);
  writeLE32(buf, 0, 1);
  var i = 0; while (i < 32) { buf[4+i] := prev[i]; i += 1 };
  i := 0; while (i < 32) { buf[36+i] := merkle[i]; i += 1 };
  writeLE32(buf, 68, time);
  writeLE32(buf, 72, EASY);
  writeLE32(buf, 76, 0);
  Blob.fromVarArray(buf);
};
// unique 32-byte txid per height
func txidFor(h : Nat) : Blob {
  let buf = VarArray.repeat<Nat8>(0x55, 32);
  writeLE32(buf, 0, Nat32.fromNat(h % 0x1_0000_0000));
  writeLE32(buf, 4, Nat32.fromNat(h / 256));
  Blob.fromVarArray(buf);
};
func cat2(a : Blob, b : Blob) : Blob {
  Blob.fromArray(Array.tabulate<Nat8>(64, func(i) = if (i < 32) a[i] else b[i-32]));
};

let c = Chain.emptyForTest();
let A = txidFor(1_000_001); // dup pair A txid (91722 & 91880)
let B = txidFor(1_000_002); // dup pair B txid (91812 & 91842)

// genesis body
ignore Chain.pushBody(c, SHA, Chain.tipBlock(c).hash, 1, HeaderValue.merkleOf(Chain.tipBlock(c).value));

var h = 1;
var prev = Chain.tipBlock(c).hash;
label build while (h <= 91_890) {
  let (txs, count) : (Blob, Nat) = if (h == 91_722) (A, 1)
    else if (h == 91_812) (cat2(B, txidFor(h)), 2)
    else if (h == 91_842) (B, 1)
    else if (h == 91_880) (cat2(A, txidFor(h)), 2)
    else (txidFor(h), 1);
  let merkle = Merkle.root(SHA, txs, count);
  let raw = mkHeader(prev, Nat32.fromNat(1_400_000_000 + h), merkle);
  switch (Chain.pushUnchecked(c, SHA, raw, NOW, UP)) {
    case (#ok ok) prev := ok.hash;
    case (#err e) { Debug.print("push failed at " # debug_show h # ": " # e); assert false };
  };
  switch (Chain.pushBody(c, SHA, prev, count, txs)) {
    case (#ok _) {};
    case (#err e) { Debug.print("body failed at " # debug_show h # ": " # e); assert false };
  };
  h += 1;
};
Debug.print("chain built to " # debug_show Chain.tipHeight(c) # " bodies to " # debug_show Chain.bodiesHeight(c));
Debug.print("counts: 91722=" # debug_show Chain.txCountAt(c, 91_722) # " 91812=" # debug_show Chain.txCountAt(c, 91_812) # " 91842=" # debug_show Chain.txCountAt(c, 91_842) # " 91880=" # debug_show Chain.txCountAt(c, 91_880));
Debug.print("lookup A -> " # debug_show (Chain.lookupTxid(c, A)).canonical # "  (esplora: 91880)");
Debug.print("lookup B -> " # debug_show (Chain.lookupTxid(c, B)).canonical # "  (esplora: 91812)");
Debug.print("txLocations(A) = " # debug_show Chain.txLocations(c, A));
Debug.print("txLocations(B) = " # debug_show Chain.txLocations(c, B));
func hashAt(hh : Nat) : Blob { switch (Chain.canonicalAt(c, hh)) { case (?b) b.hash; case null { assert false; "" : Blob } } };
Debug.print("blockTxids(91722) = " # debug_show Chain.blockTxids(c, hashAt(91_722), 0, 10) # " (expect [A])");
Debug.print("blockTxids(91842) = " # debug_show Chain.blockTxids(c, hashAt(91_842), 0, 10) # " (expect [B])");
assert Chain.blockTxids(c, hashAt(91_722), 0, 10) == [A];
assert Chain.blockTxids(c, hashAt(91_842), 0, 10) == [B];
assert Chain.txCountAt(c, 91_722) == ?1;
assert Chain.txCountAt(c, 91_842) == ?1;
assert Chain.txCountAt(c, 91_812) == ?2;
assert Chain.txCountAt(c, 91_880) == ?2;
assert (Chain.lookupTxid(c, A)).canonical == ?91_880;
assert (Chain.lookupTxid(c, B)).canonical == ?91_812;
Debug.print("ALL BIP30 ASSERTIONS PASS");
