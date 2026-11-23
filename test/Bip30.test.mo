// @testmode wasi
// BIP30 compressed-block scheme, verified at the REAL heights: drives a
// synthetic chain past 91,880 replicating both duplicate-coinbase pairs
// (91722/91880 and 91812/91842) and asserts counts, listings, attribution
// (matches Esplora on both pairs) and trap-free locations. Slow (~18 s) —
// the 92k-block build dominates.
import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Sha256 "mo:sha2/Sha256";
import VarArray "mo:core/VarArray";
import Nat "mo:core/Nat";

import Header "mo:btc/Header";
import Bitcoin "mo:mmr/Bitcoin";
import HeaderValue "../src/block_explorer/HeaderValue";
import Chain "../src/block_explorer/Chain";

let SHA = Sha256.new(#sha256);
let NOW : Int = 9_999_999_999;
let UP = Principal.fromText("aaaaa-aa");
let EASY : Nat32 = 0x207fffff;

func writeLE32(buf : [var Nat8], off : Nat, v : Nat32) {
  buf[off] := Nat32.toNat(v & 0xff).toNat8();
  buf[off+1] := Nat32.toNat((v >> 8) & 0xff).toNat8();
  buf[off+2] := Nat32.toNat((v >> 16) & 0xff).toNat8();
  buf[off+3] := Nat32.toNat((v >> 24) & 0xff).toNat8();
};
func mkHeader(prev : Blob, time : Nat32, merkle : Blob) : Blob {
  let buf = VarArray.repeat<Nat8>(0, 80);
  writeLE32(buf, 0, 1);
  var i = 0; while (i < 32) { buf[4+i] := prev[i]; i += 1 };
  i := 0; while (i < 32) { buf[36+i] := merkle[i]; i += 1 };
  writeLE32(buf, 68, time);
  writeLE32(buf, 72, EASY);
  writeLE32(buf, 76, 0);
  buf.toBlob();
};
// Synthetic raw-coinbase payload per height — 65 bytes to clear the
// canister's > 64-byte depth pin. The dSHA256 of this blob is the on-the-
// wire coinbase txid at height h; two heights sharing the same raw bytes
// thereby share a coinbase txid, which is the BIP30 duplicate-pair setup.
func rawCoinbaseFor(h : Nat) : Blob {
  let buf = VarArray.repeat<Nat8>(0x55, 65);
  writeLE32(buf, 0, Nat.toNat32(h % 0x1_0000_0000));
  writeLE32(buf, 4, Nat.toNat32(h / 256));
  buf.toBlob();
};
// A regular (non-coinbase) 32-byte txid filler for second-tx-in-block slots.
func txidFor(h : Nat) : Blob {
  let buf = VarArray.repeat<Nat8>(0xaa, 32);
  writeLE32(buf, 0, Nat.toNat32(h % 0x1_0000_0000));
  writeLE32(buf, 4, Nat.toNat32(h / 256));
  buf.toBlob();
};
func dSha(b : Blob) : Blob {
  let d = Sha256.new(#sha256);
  d.writeBlob(b);
  d.sumDouble();
};

let c = Chain.emptyForTest();
// Raw bytes shared across the BIP30 duplicate-coinbase pairs; the resulting
// on-the-wire txids A, B appear twice each (91722/91880 and 91812/91842).
let cbA = rawCoinbaseFor(1_000_001);
let cbB = rawCoinbaseFor(1_000_002);
let A = dSha(cbA); // dup pair A txid (91722 & 91880)
let B = dSha(cbB); // dup pair B txid (91812 & 91842)

// Real genesis coinbase bytes — the merkle root of the emptyForTest chain's
// genesis header is this coinbase's txid, so the on-chain coinbase check
// needs these exact bytes.
let GENESIS_COINBASE : Blob = Header.hexToBlob(
  "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
);

// genesis body
ignore c.pushBody(c.tipBlock().hash, [HeaderValue.merkleOf(c.tipBlock().value)], GENESIS_COINBASE);

var h = 1;
var prev = c.tipBlock().hash;
label build while (h <= 91_890) {
  // Pick the coinbase bytes and the body's txid list for this height. The
  // 2-tx heights are the real BIP30 cases where a duplicate-coinbase block
  // (91812/91880) also carries a second tx whose txid is height-unique.
  let (cbTx, txs) : (Blob, [Blob]) = if (h == 91_722) (cbA, [A])
    else if (h == 91_812) (cbB, [B, txidFor(h)])
    else if (h == 91_842) (cbB, [B])
    else if (h == 91_880) (cbA, [A, txidFor(h)])
    else (rawCoinbaseFor(h), [dSha(rawCoinbaseFor(h))]);
  let merkle = Bitcoin.merkleRoot(txs);
  let raw = mkHeader(prev, Nat.toNat32(1_400_000_000 + h), merkle);
  switch (c.pushUnchecked(SHA, raw, NOW, UP)) {
    case (#ok ok) prev := ok.hash;
    case (#err e) { Debug.print("push failed at " # debug_show h # ": " # e); assert false };
  };
  switch (c.pushBody(prev, txs, cbTx)) {
    case (#ok _) {};
    case (#err e) { Debug.print("body failed at " # debug_show h # ": " # e); assert false };
  };
  h += 1;
};
Debug.print("chain built to " # debug_show c.tipHeight() # " bodies to " # debug_show c.bodiesHeight());
Debug.print("counts: 91722=" # debug_show c.txCountAt(91_722) # " 91812=" # debug_show c.txCountAt(91_812) # " 91842=" # debug_show c.txCountAt(91_842) # " 91880=" # debug_show c.txCountAt(91_880));
Debug.print("lookup A -> " # debug_show c.lookupTxid(A).canonical # "  (esplora: 91880)");
Debug.print("lookup B -> " # debug_show c.lookupTxid(B).canonical # "  (esplora: 91812)");
Debug.print("txLocations(A) = " # debug_show c.txLocations(A));
Debug.print("txLocations(B) = " # debug_show c.txLocations(B));
func hashAt(hh : Nat) : Blob { switch (c.canonicalAt(hh)) { case (?b) b.hash; case null { assert false; "" : Blob } } };
Debug.print("blockTxids(91722) = " # debug_show c.blockTxids(hashAt(91_722), 0, 10) # " (expect [A])");
Debug.print("blockTxids(91842) = " # debug_show c.blockTxids(hashAt(91_842), 0, 10) # " (expect [B])");
assert c.blockTxids(hashAt(91_722), 0, 10) == [A];
assert c.blockTxids(hashAt(91_842), 0, 10) == [B];
assert c.txCountAt(91_722) == ?1;
assert c.txCountAt(91_842) == ?1;
assert c.txCountAt(91_812) == ?2;
assert c.txCountAt(91_880) == ?2;
assert c.lookupTxid(A).canonical == ?91_880;
assert c.lookupTxid(B).canonical == ?91_812;
Debug.print("ALL BIP30 ASSERTIONS PASS");
