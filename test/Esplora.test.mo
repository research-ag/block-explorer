// @testmode wasi
// Tests for the Esplora HTTP routes (Esplora.handle) that read block bodies:
// tx_count in the block JSON, /block/:hash/txids and /txid/:index, and
// /tx/:txid/{status, merkle-proof, merkleblock-proof, hex, raw}.
//
// Real mainnet blocks 100002 (9 txs, so every level of its tree has a node
// that pairs with itself) and 100005 (1 tx), each pushed as the root of a
// chain (so at height 0), pin the exact formats: the expected answers are
// Blockstream's esplora's, verbatim but for the height. Synthetic blocks of
// every size from 1 to 17 check each position's proofs against independent
// implementations: electrs's create_merkle_branch_and_root, and bitcoind's
// PartialMerkleTree::ExtractMatches for the merkleblock.

import { test; suite } "mo:test";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";
import Bitcoin "mo:mmr/Bitcoin";
import Prove "mo:mmr/Prove";

import Header "mo:btc/Header";
import Chain "../src/block_explorer/Chain";
import Esplora "../src/block_explorer/Esplora";
import Headers "../src/block_explorer/Headers";
import HeaderValue "../src/block_explorer/HeaderValue";

// --- Harness -------------------------------------------------------------

let SHA = Sha256.new(#sha256);
let NOW : Int = 9_999_999_999;
let UPLOADER = Principal.fromText("aaaaa-aa");
let EASY_BITS : Nat32 = 0x1d00ffff;

func get(c : Chain.State, url : Text) : Esplora.Response = Esplora.handle(
  c,
  func() = "",
  { method = "GET"; url; headers = []; body = "" },
);

func bodyText(r : Esplora.Response) : Text {
  switch (r.body.decodeUtf8()) {
    case (?t) t;
    case null Runtime.trap("body is not UTF-8");
  };
};

func contentType(r : Esplora.Response) : Text = r.headers[0].1;

// GET `url` and require status `status` and body `body`; traps with both
// sides on a mismatch.
func expect(c : Chain.State, url : Text, status : Nat16, body : Text) {
  let r = get(c, url);
  let t = bodyText(r);
  if (r.status_code != status or t != body) {
    Runtime.trap("GET " # url # "\n  got:      " # r.status_code.toText() # " " # t # "\n  expected: " # status.toText() # " " # body);
  };
};

// GET `url`, require status 200, and return the body.
func ok(c : Chain.State, url : Text) : Text {
  let r = get(c, url);
  let t = bodyText(r);
  if (r.status_code != 200) Runtime.trap("GET " # url # " -> " # r.status_code.toText() # " " # t);
  t;
};

// Display hex <-> internal bytes.
func be(h : Blob) : Text = Header.bytesToHex(Header.reverse32(h));
func internal(hex : Text) : Blob = Header.reverse32(Header.hexToBlob(hex));

func dSha(b : Blob) : Blob {
  let d = Sha256.new(#sha256);
  d.writeBlob(b);
  d.sumDouble();
};

func cat(a : Blob, b : Blob) : Blob = Array.tabulate<Nat8>(64, func(i) = if (i < 32) a[i] else b[i - 32]).toBlob();

func writeLE32(buf : [var Nat8], off : Nat, v : Nat32) {
  buf[off] := Nat32.toNat(v & 0xff).toNat8();
  buf[off + 1] := Nat32.toNat((v >> 8) & 0xff).toNat8();
  buf[off + 2] := Nat32.toNat((v >> 16) & 0xff).toNat8();
  buf[off + 3] := Nat32.toNat((v >> 24) & 0xff).toNat8();
};

func writeBlob(buf : [var Nat8], off : Nat, src : Blob) {
  var i = 0;
  while (i < src.size()) { buf[off + i] := src[i]; i += 1 };
};

// An 80-byte header with the given parent, merkle root and nonce.
func mkHeader(prevHash : Blob, merkle : Blob, nonce : Nat32) : Blob {
  let buf = VarArray.repeat<Nat8>(0, 80);
  writeLE32(buf, 0, 1);
  writeBlob(buf, 4, prevHash);
  writeBlob(buf, 36, merkle);
  writeLE32(buf, 68, 1_700_000_000 + nonce);
  writeLE32(buf, 72, EASY_BITS);
  writeLE32(buf, 76, nonce);
  buf.toBlob();
};

func hashOf(raw : Blob) : Blob = Header.headerHashBlob(SHA, raw);

// A synthetic raw coinbase keyed by `k` (65 bytes: over the 64-byte floor).
func cbTx(k : Nat) : Blob = Array.tabulate<Nat8>(65, func(i) = Nat.toNat8((k * 7 + i * 13 + 1) % 256)).toBlob();

// A distinct synthetic txid per `k`.
func tx(k : Nat) : Blob = dSha(Array.tabulate<Nat8>(4, func(i) = Nat.toNat8((k / (256 ** i)) % 256)).toBlob());

type Body = { coinbase : Blob; txids : [Blob]; root : Blob };

// A body of `n` txs: the coinbase keyed by `k`, then txs `k * 1000 + 1..`.
func body(k : Nat, n : Nat) : Body {
  let cb = cbTx(k);
  let txids = Array.tabulate<Blob>(n, func(i) = if (i == 0) dSha(cb) else tx(k * 1000 + i));
  { coinbase = cb; txids; root = Bitcoin.merkleRoot(txids) };
};

func pushHeader(c : Chain.State, raw : Blob) {
  switch (c.pushUnchecked(SHA, raw, NOW, UPLOADER)) {
    case (#ok _) {};
    case (#err e) Runtime.trap("push header: " # e);
  };
};

func pushBody(c : Chain.State, hash : Blob, b : Body) {
  switch (c.pushBody(hash, b.txids, b.coinbase)) {
    case (#ok _) {};
    case (#err e) Runtime.trap("push body: " # e);
  };
};

// The real genesis coinbase: `emptyForTest` seeds the chain with the real
// genesis header, so its body needs these bytes.
let GENESIS_COINBASE = Header.hexToBlob("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");

// Genesis with its body.
func genesisChain() : (Chain.State, Blob) {
  let c = Chain.emptyForTest();
  let g = c.tipBlock();
  switch (c.pushBody(g.hash, [HeaderValue.merkleOf(g.value)], GENESIS_COINBASE)) {
    case (#ok _) {};
    case (#err e) Runtime.trap("genesis body: " # e);
  };
  (c, g.hash);
};

// --- Independent references ----------------------------------------------

// electrs's create_merkle_branch_and_root (util/electrum_merkle.rs), ported.
func electrumBranch(txids : [Blob], pos : Nat) : [Blob] {
  var hashes = txids;
  var index = pos;
  let merkle = List.empty<Blob>();
  while (hashes.size() > 1) {
    if (hashes.size() % 2 != 0) {
      let h = hashes;
      hashes := Array.tabulate<Blob>(h.size() + 1, func(i) = if (i < h.size()) h[i] else h[h.size() - 1]);
    };
    index := if (index % 2 == 0) index + 1 else index - 1 : Nat;
    merkle.add(hashes[index]);
    index /= 2;
    let h = hashes;
    hashes := Array.tabulate<Blob>(h.size() / 2, func(i) = dSha(cat(h[2 * i], h[2 * i + 1])));
  };
  merkle.toArray();
};

func electrumJson(height : Nat, txids : [Blob], pos : Nat) : Text {
  let parts = electrumBranch(txids, pos).map(func(h) = "\"" # be(h) # "\"");
  "{\"block_height\":" # height.toText() # ",\"merkle\":[" # parts.values().join(",") # "],\"pos\":" # pos.toText() # "}";
};

// bitcoind's CMerkleBlock deserialization and PartialMerkleTree::
// ExtractMatches: the header, the root the partial tree folds to, and the
// matched (position, txid) pairs. Traps on malformed input, including
// unused hashes or flag bytes.
func extractMerkleBlock(hex : Text) : { header : Blob; root : Blob; matches : [(Nat, Blob)] } {
  let b = Header.hexToBlob(hex);
  var at = 0;
  func byte() : Nat { let v = b[at].toNat(); at += 1; v };
  func le(k : Nat) : Nat {
    var v = 0;
    var m = 1;
    var i = 0;
    while (i < k) { v += byte() * m; m *= 256; i += 1 };
    v;
  };
  func compactSize() : Nat {
    let p = byte();
    if (p < 0xfd) p else if (p == 0xfd) le(2) else if (p == 0xfe) le(4) else le(8);
  };
  func bytes(k : Nat) : Blob {
    let s = Array.tabulate<Nat8>(k, func(i) = b[at + i]).toBlob();
    at += k;
    s;
  };
  let header = bytes(80);
  let n = le(4);
  let nHashes = compactSize();
  let hashes = List.empty<Blob>();
  var i = 0;
  while (i < nHashes) { hashes.add(bytes(32)); i += 1 };
  let flagBytes = bytes(compactSize());
  if (at != b.size()) Runtime.trap("merkleblock: trailing bytes");

  func width(h : Nat) : Nat = (n + 2 ** h - 1) / (2 ** h);
  var height = 0;
  while (width(height) > 1) height += 1;
  var bitsUsed = 0;
  var hashesUsed = 0;
  let matches = List.empty<(Nat, Blob)>();
  func walk(h : Nat, p : Nat) : Blob {
    let flag = (flagBytes[bitsUsed / 8] >> (bitsUsed % 8).toNat8()) & 1 == 1;
    bitsUsed += 1;
    if (h == 0 or not flag) {
      let hash = hashes.at(hashesUsed);
      hashesUsed += 1;
      if (h == 0 and flag) matches.add((p, hash));
      return hash;
    };
    let left = walk(h - 1 : Nat, 2 * p);
    let right = if (2 * p + 1 < width(h - 1 : Nat)) walk(h - 1 : Nat, 2 * p + 1) else left;
    dSha(cat(left, right));
  };
  let root = walk(height, 0);
  if (hashesUsed != hashes.size()) Runtime.trap("merkleblock: unused hashes");
  if ((bitsUsed + 7) / 8 != flagBytes.size()) Runtime.trap("merkleblock: unused flag bytes");
  { header; root; matches = matches.toArray() };
};

// --- Real blocks -----------------------------------------------------------

// Mainnet block 100002 as Blockstream's esplora serves it.
let B100002_HASH = "0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af";
let B100002_HEADER = "0100000090f0a9f110702f808219ebea1173056042a714bad51b916cb6800000000000005275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2fdb261b4d4c86041b1ab1bf93";
let B100002_COINBASE = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b0146ffffffff0100f2052a01000000434104e18f7afbe4721580e81e8414fc8c24d7cfacf254bb5c7b949450c3e997c2dc1242487a8169507b631eb3771f2b425483fb13102c4eb5d858eef260fe70fbfae0ac00000000";
let B100002_TXIDS_JSON = "[\"ef1d870d24c85b89d92ad50f4631026f585d6a34e972eaf427475e5d60acf3a3\",\"f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07\",\"db60fb93d736894ed0b86cb92548920a3fe8310dd19b0da7ad97e48725e1e12e\",\"220ebc64e21abece964927322cba69180ed853bb187fbc6923bac7d010b9d87a\",\"71b3dbaca67e9f9189dad3617138c19725ab541ef0b49c05a94913e9f28e3f4e\",\"fe305e1ed08212d76161d853222048eea1f34af42ea0e197896a269fbf8dc2e0\",\"21d2eb195736af2a40d42107e6abd59c97eb6cffd4a5a7a7709e86590ae61987\",\"dd1fd2a6fc16404faf339881a90adbde7f4f728691ac62e8f168809cdfae1053\",\"74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20\"]";
// /tx/:txid/{status,merkle-proof,merkleblock-proof} for the txid at each position.
let B100002_PROOFS : [(Nat, Text, Text, Text)] = [
  (0, "{\"confirmed\":true,\"block_height\":100002,\"block_hash\":\"0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af\",\"block_time\":1293625051}", "{\"block_height\":100002,\"merkle\":[\"f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07\",\"4a081b6fc84b3ff52a42c14b5f06a6b9dde6908984a4439814c186c139b32d52\",\"ca837db5ad733692f334145b3b9fdaca53e557a71da71d5110dc6c31f09f1889\",\"dbcfb7f7721e0110ade91481e63155b9f22d11d4fa550bc36f6d15af382c39ac\"],\"pos\":0}", "0100000090f0a9f110702f808219ebea1173056042a714bad51b916cb6800000000000005275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2fdb261b4d4c86041b1ab1bf930900000005a3f3ac605d5e4727f4ea72e9346a5d586f0231460fd52ad9895bc8240d871def076d0317ee70ee36cf396a9871ab3bf6f8e6d538d7f8a9062437dcb71c75fcf9522db339c186c1149843a4848990e6ddb9a6065f4bc1422af53f4bc86f1b084a89189ff0316cdc10511da71da757e553cada9f3b5b1434f3923673adb57d83caac392c38af156d6fc30b55fad4112df2b95531e68114e9ad10011e72f7b7cfdb021f00"),
  (4, "{\"confirmed\":true,\"block_height\":100002,\"block_hash\":\"0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af\",\"block_time\":1293625051}", "{\"block_height\":100002,\"merkle\":[\"fe305e1ed08212d76161d853222048eea1f34af42ea0e197896a269fbf8dc2e0\",\"90cc82a0c3be470a3f8b67333bf5dce1ba11bb05ced7f0cbbe89cc183cfe0103\",\"aafa5c66ce7ad11e5a376c8644ca1c57fc77c05059791b8c0b1ccdf14c37f25e\",\"dbcfb7f7721e0110ade91481e63155b9f22d11d4fa550bc36f6d15af382c39ac\"],\"pos\":4}", "0100000090f0a9f110702f808219ebea1173056042a714bad51b916cb6800000000000005275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2fdb261b4d4c86041b1ab1bf9309000000055ef2374cf1cd1c0b8c1b795950c077fc571cca44866c375a1ed17ace665cfaaa4e3f8ef2e91349a9059cb4f01e54ab2597c1387161d3da89919f7ea6acdbb371e0c28dbf9f266a8997e1a02ef44af3a1ee48202253d86161d71282d01e5e30fe0301fe3c18cc89becbf0d7ce05bb11bae1dcf53b33678b3f0a47bec3a082cc90ac392c38af156d6fc30b55fad4112df2b95531e68114e9ad10011e72f7b7cfdb023b00"),
  (7, "{\"confirmed\":true,\"block_height\":100002,\"block_hash\":\"0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af\",\"block_time\":1293625051}", "{\"block_height\":100002,\"merkle\":[\"21d2eb195736af2a40d42107e6abd59c97eb6cffd4a5a7a7709e86590ae61987\",\"3355f448dc584f88bfa0428e514557c17acce173456e2ce77d2f1a6b9f4803d4\",\"aafa5c66ce7ad11e5a376c8644ca1c57fc77c05059791b8c0b1ccdf14c37f25e\",\"dbcfb7f7721e0110ade91481e63155b9f22d11d4fa550bc36f6d15af382c39ac\"],\"pos\":7}", "0100000090f0a9f110702f808219ebea1173056042a714bad51b916cb6800000000000005275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2fdb261b4d4c86041b1ab1bf9309000000055ef2374cf1cd1c0b8c1b795950c077fc571cca44866c375a1ed17ace665cfaaad403489f6b1a2f7de72c6e4573e1cc7ac15745518e42a0bf884f58dc48f455338719e60a59869e70a7a7a5d4ff6ceb979cd5abe60721d4402aaf365719ebd2215310aedf9c8068f1e862ac9186724f7fdedb0aa9819833af4f4016fca6d21fddac392c38af156d6fc30b55fad4112df2b95531e68114e9ad10011e72f7b7cfdb02ab00"),
  (8, "{\"confirmed\":true,\"block_height\":100002,\"block_hash\":\"0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af\",\"block_time\":1293625051}", "{\"block_height\":100002,\"merkle\":[\"74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20\",\"bb8db5f1d687839cc15a875e321ffb910d1c62d9280c1e4089122544c3528a13\",\"e7413bdf2c1215c3983536a62b1e210d9006a789cdc1427ccb4bb347745e52fc\",\"660af9921e9e17eba1106409c93aeec1b390bff99b0c25499da1b9c0e9aa56bc\"],\"pos\":8}", "0100000090f0a9f110702f808219ebea1173056042a714bad51b916cb6800000000000005275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2fdb261b4d4c86041b1ab1bf930900000002bc56aae9c0b9a19d49250c9bf9bf90b3c1ee3ac9096410a1eb179e1e92f90a66201f4587ec86b58297edc2dd32d6fcd998aa794308aac802a8af3be0e081d674013d"),
];

// Mainnet block 100005 as Blockstream's esplora serves it.
let B100005_HASH = "000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45";
let B100005_HEADER = "0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d63";
let B100005_COINBASE = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020a02ffffffff0100f2052a01000000434104ecd3229b0571c3be876feaac0442a9f13c5a572742927af1dc623353ecf8c202225f64868137a18cdd85cbbb4c74fbccfd4f49639cf1bdc94a5672bb15ad5d4cac00000000";
let B100005_TXIDS_JSON = "[\"63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5\"]";
// /tx/:txid/{status,merkle-proof,merkleblock-proof} for the txid at each position.
let B100005_PROOFS : [(Nat, Text, Text, Text)] = [
  (0, "{\"confirmed\":true,\"block_height\":100005,\"block_hash\":\"000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45\",\"block_time\":1293625703}", "{\"block_height\":100005,\"merkle\":[],\"pos\":0}", "0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101"),
];

// A chain rooted at a real block (at height 0) with its body.
func realChain(headerHex : Text, txidsJson : Text, coinbaseHex : Text) : (Chain.State, [Blob]) {
  let c = Chain.fromRootHex(headerHex, Headers.KEY_SIZE);
  let inner = txidsJson.trimStart(#char '[').trimEnd(#char ']');
  let txids = inner.split(#char ',').map(func(t : Text) : Blob = internal(t.trim(#char '\"'))).toArray();
  switch (c.pushBody(hashOf(Header.hexToBlob(headerHex)), txids, Header.hexToBlob(coinbaseHex))) {
    case (#ok _) {};
    case (#err e) Runtime.trap("real body: " # e);
  };
  (c, txids);
};

// Esplora's answer, with the real height replaced by the test chain's 0.
func atHeight0(t : Text, realHeight : Text) : Text = t.replace(#text ("\"block_height\":" # realHeight), "\"block_height\":0");

// Esplora's merkleblock, with the header's prev_hash (hex digits 8..72)
// zeroed: the root of a chain sits at height 0 and reports a zero parent,
// as genesis does (`rawHeaderOf`). The rest is compared byte for byte.
func zeroPrevHash(merkleblockHex : Text) : Text {
  let cs = merkleblockHex.toArray();
  Text.fromIter(Array.tabulate<Char>(cs.size(), func(i) = if (i >= 8 and i < 72) '0' else cs[i]).values());
};

func checkRealBlock(c : Chain.State, txids : [Blob], hashHex : Text, txidsJson : Text, coinbaseHex : Text, proofs : [(Nat, Text, Text, Text)], realHeight : Text) {
  expect(c, "/api/block/" # hashHex # "/txids", 200, txidsJson);
  for (i in txids.keys()) {
    expect(c, "/api/block/" # hashHex # "/txid/" # i.toText(), 200, be(txids[i]));
  };
  expect(c, "/api/block/" # hashHex # "/txid/" # txids.size().toText(), 404, "tx index out of range");
  for ((pos, status, merkleProof, merkleblockProof) in proofs.values()) {
    let t = be(txids[pos]);
    expect(c, "/api/tx/" # t # "/status", 200, atHeight0(status, realHeight));
    expect(c, "/api/tx/" # t # "/merkle-proof", 200, atHeight0(merkleProof, realHeight));
    expect(c, "/api/tx/" # t # "/merkleblock-proof", 200, zeroPrevHash(merkleblockProof));
  };
  // A pre-segwit coinbase: the stored (witness-stripped) bytes are the tx.
  expect(c, "/api/tx/" # be(txids[0]) # "/hex", 200, coinbaseHex);
  let raw = get(c, "/api/tx/" # be(txids[0]) # "/raw");
  assert raw.status_code == 200 and raw.body == Header.hexToBlob(coinbaseHex);
  assert contentType(raw) == "application/octet-stream";
};

suite(
  "Esplora: real blocks match Blockstream's answers",
  func() {
    test(
      "block 100002 (9 txs)",
      func() {
        let (c, txids) = realChain(B100002_HEADER, B100002_TXIDS_JSON, B100002_COINBASE);
        assert txids.size() == 9;
        checkRealBlock(c, txids, B100002_HASH, B100002_TXIDS_JSON, B100002_COINBASE, B100002_PROOFS, "100002");
        // tx_count sits after timestamp, as in electrs's BlockValue.
        let j = ok(c, "/api/block/" # B100002_HASH);
        assert j.contains(#text "\"timestamp\":1293625051,\"tx_count\":9,\"merkle_root\":\"2fda58e5959b0ee53c5253da9b9f3c0c739422ae04946966991cf55895287552\"");
        assert ok(c, "/api/blocks/0").contains(#text "\"tx_count\":9,");
        // Not a coinbase: no raw bytes.
        expect(c, "/api/tx/" # be(txids[4]) # "/hex", 404, "Raw transaction not stored (coinbase transactions only)");
        expect(c, "/api/tx/" # be(txids[4]) # "/raw", 404, "Raw transaction not stored (coinbase transactions only)");
      },
    );
    test(
      "block 100005 (1 tx)",
      func() {
        let (c, txids) = realChain(B100005_HEADER, B100005_TXIDS_JSON, B100005_COINBASE);
        assert txids.size() == 1;
        checkRealBlock(c, txids, B100005_HASH, B100005_TXIDS_JSON, B100005_COINBASE, B100005_PROOFS, "100005");
      },
    );
  },
);

// --- Synthetic blocks --------------------------------------------------------

suite(
  "Esplora: proofs for every position of blocks of 1 to 17 txs",
  func() {
    test(
      "merkle-proof is electrs's branch; merkleblock-proof extracts to the root and the one txid",
      func() {
        let (c, g) = genesisChain();
        var parent = g;
        var height = 1;
        while (height <= 17) {
          let b = body(height, height);
          let raw = mkHeader(parent, b.root, height.toNat32());
          pushHeader(c, raw);
          pushBody(c, hashOf(raw), b);
          for (pos in b.txids.keys()) {
            let t = be(b.txids[pos]);
            expect(c, "/api/tx/" # t # "/merkle-proof", 200, electrumJson(height, b.txids, pos));
            assert Bitcoin.verifyBranch(b.txids[pos], pos, electrumBranch(b.txids, pos), b.root);
            let m = extractMerkleBlock(ok(c, "/api/tx/" # t # "/merkleblock-proof"));
            assert m.header == raw;
            assert m.root == b.root;
            assert m.matches.size() == 1 and m.matches[0].0 == pos and m.matches[0].1 == b.txids[pos];
          };
          parent := hashOf(raw);
          height += 1;
        };
      },
    );
  },
);

suite(
  "Esplora: txids, tx_count and tx status",
  func() {
    test(
      "canonical block: txids in order, tx_count, status of each tx",
      func() {
        let (c, g) = genesisChain();
        let b1 = body(1, 7);
        let h1 = mkHeader(g, b1.root, 1);
        pushHeader(c, h1);
        pushBody(c, hashOf(h1), b1);
        let hash = be(hashOf(h1));
        let quoted = b1.txids.map(func(t) = "\"" # be(t) # "\"");
        expect(c, "/api/block/" # hash # "/txids", 200, "[" # quoted.values().join(",") # "]");
        assert contentType(get(c, "/api/block/" # hash # "/txids")) == "application/json";
        expect(c, "/api/block/" # hash # "/txid/6", 200, be(b1.txids[6]));
        expect(c, "/api/block/" # hash # "/txid/7", 404, "tx index out of range");
        expect(c, "/api/block/" # hash # "/txid/x", 400, "Invalid number");
        assert ok(c, "/api/block/" # hash).contains(#text ",\"tx_count\":7,");
        // /blocks lists both bodies' tx counts, newest first.
        let list = ok(c, "/api/blocks");
        assert list.contains(#text "\"height\":1,\"version\":1,\"timestamp\":1700000001,\"tx_count\":7,");
        assert list.contains(#text "\"height\":0,\"version\":1,\"timestamp\":1231006505,\"tx_count\":1,");
        for (t in b1.txids.values()) {
          expect(c, "/api/tx/" # be(t) # "/status", 200, "{\"confirmed\":true,\"block_height\":1,\"block_hash\":\"" # hash # "\",\"block_time\":1700000001}");
        };
        // Upper-case hex is a txid too.
        expect(c, "/api/tx/" # be(b1.txids[1]).toUpper() # "/status", 200, "{\"confirmed\":true,\"block_height\":1,\"block_hash\":\"" # hash # "\",\"block_time\":1700000001}");
        // The genesis coinbase, stored as the real bytes.
        let genCb = be(dSha(GENESIS_COINBASE));
        expect(c, "/api/tx/" # genCb # "/hex", 200, Header.bytesToHex(GENESIS_COINBASE));
        expect(c, "/api/tx/" # be(b1.txids[0]) # "/hex", 200, Header.bytesToHex(b1.coinbase));
      },
    );

    test(
      "block above the body tip: no tx_count, txids 404",
      func() {
        let (c, g) = genesisChain();
        let b1 = body(1, 3);
        let h1 = mkHeader(g, b1.root, 1);
        pushHeader(c, h1);
        let hash = be(hashOf(h1));
        let j = ok(c, "/api/block/" # hash);
        assert not j.contains(#text "tx_count");
        assert j.contains(#text "\"timestamp\":1700000001,\"merkle_root\":");
        expect(c, "/api/block/" # hash # "/txids", 404, "Block transactions not indexed");
        expect(c, "/api/block/" # hash # "/txid/0", 404, "Block transactions not indexed");
        let t = be(b1.txids[1]);
        expect(c, "/api/tx/" # t # "/status", 200, "{\"confirmed\":false}");
        expect(c, "/api/tx/" # t # "/merkle-proof", 404, "Transaction not found or is unconfirmed");
        expect(c, "/api/tx/" # t # "/merkleblock-proof", 404, "Transaction not found or is unconfirmed");
        expect(c, "/api/tx/" # be(b1.txids[0]) # "/hex", 404, "Transaction not found");
        expect(c, "/api/tx/" # be(b1.txids[0]) # "/raw", 404, "Transaction not found");
      },
    );

    test(
      "chunked upload in progress: its txids are unconfirmed until the last chunk",
      func() {
        let (c, g) = genesisChain();
        let b1 = body(1, 7);
        let h1 = mkHeader(g, b1.root, 1);
        pushHeader(c, h1);
        let levels = Bitcoin.levels(b1.txids);
        func chunk(lo : Nat, hi : Nat) {
          let start : Chain.ChunkStart = if (lo == 0) #coinbase_tx(b1.coinbase) else #offset(lo);
          let part = Array.tabulate<Blob>(hi - lo : Nat, func(i) = b1.txids[lo + i]);
          switch (c.pushBodyChunk(hashOf(h1), start, part, Prove.rightPeaks(levels, hi))) {
            case (#ok _) {};
            case (#err e) Runtime.trap("chunk: " # e);
          };
        };
        chunk(0, 3);
        // The first three txids are in the trie, but the block isn't complete.
        assert c.txLocations(b1.txids[1]).canonical != null;
        let hash = be(hashOf(h1));
        let t = be(b1.txids[1]);
        expect(c, "/api/tx/" # t # "/status", 200, "{\"confirmed\":false}");
        expect(c, "/api/tx/" # t # "/merkle-proof", 404, "Transaction not found or is unconfirmed");
        expect(c, "/api/block/" # hash # "/txids", 404, "Block transactions not indexed");
        assert not ok(c, "/api/block/" # hash).contains(#text "tx_count");
        chunk(3, 7);
        expect(c, "/api/tx/" # t # "/status", 200, "{\"confirmed\":true,\"block_height\":1,\"block_hash\":\"" # hash # "\",\"block_time\":1700000001}");
        expect(c, "/api/tx/" # t # "/merkle-proof", 200, electrumJson(1, b1.txids, 1));
        assert ok(c, "/api/block/" # hash).contains(#text ",\"tx_count\":7,");
      },
    );

    test(
      "fork block: txids and tx_count served; its own txids unconfirmed",
      func() {
        let (c, g) = genesisChain();
        let b1 = body(1, 3);
        let h1 = mkHeader(g, b1.root, 1);
        pushHeader(c, h1);
        pushBody(c, hashOf(h1), b1);
        // A sibling of block 1 with the same work: it stays a fork.
        let f1 = body(2, 4);
        let hf = mkHeader(g, f1.root, 2);
        pushHeader(c, hf);
        pushBody(c, hashOf(hf), f1);
        let fork = be(hashOf(hf));
        assert ok(c, "/api/block/" # fork # "/status").contains(#text "\"in_best_chain\":false");
        let quoted = f1.txids.map(func(t) = "\"" # be(t) # "\"");
        expect(c, "/api/block/" # fork # "/txids", 200, "[" # quoted.values().join(",") # "]");
        expect(c, "/api/block/" # fork # "/txid/3", 200, be(f1.txids[3]));
        assert ok(c, "/api/block/" # fork).contains(#text ",\"tx_count\":4,");
        // Esplora's tx routes follow the best chain only.
        expect(c, "/api/tx/" # be(f1.txids[2]) # "/status", 200, "{\"confirmed\":false}");
        expect(c, "/api/tx/" # be(f1.txids[2]) # "/merkle-proof", 404, "Transaction not found or is unconfirmed");
      },
    );
  },
);

suite(
  "Esplora: malformed and unknown input",
  func() {
    test(
      "status codes and texts are electrs's",
      func() {
        let (c, g) = genesisChain();
        let gHex = be(g);
        let unknown = "00000000000000000000000000000000000000000000000000000000000000aa";
        let nonHex = "zz00000000000000000000000000000000000000000000000000000000000000";
        // Block hashes: malformed -> 400 (it used to trap on non-hex
        // digits), unknown -> 404.
        for (route in ["", "/header", "/status", "/txids", "/txid/0"].values()) {
          expect(c, "/api/block/zz" # route, 400, "Invalid hex string");
          expect(c, "/api/block/" # nonHex # route, 400, "Invalid hex string");
          expect(c, "/api/block/" # unknown # route, 404, "Block not found");
        };
        expect(c, "/api/block/" # unknown # "/txid/x", 400, "Invalid number");
        expect(c, "/api/block/" # gHex # "/txid/0", 200, be(dSha(GENESIS_COINBASE)));
        expect(c, "/api/block/" # gHex # "/nope", 404, "not found");
        expect(c, "/api/block/" # gHex # "/txid/0/x", 404, "not found");
        // Txids.
        for (route in ["/status", "/merkle-proof", "/merkleblock-proof", "/hex", "/raw"].values()) {
          expect(c, "/api/tx/abc" # route, 400, "Invalid hex string");
          expect(c, "/api/tx/" # nonHex # route, 400, "Invalid hex string");
        };
        expect(c, "/api/tx/" # unknown # "/status", 200, "{\"confirmed\":false}");
        expect(c, "/api/tx/" # unknown # "/merkle-proof", 404, "Transaction not found or is unconfirmed");
        expect(c, "/api/tx/" # unknown # "/merkleblock-proof", 404, "Transaction not found or is unconfirmed");
        expect(c, "/api/tx/" # unknown # "/hex", 404, "Transaction not found");
        expect(c, "/api/tx/" # unknown # "/raw", 404, "Transaction not found");
        expect(c, "/api/tx/" # unknown, 404, "not found");
        expect(c, "/api/tx/" # unknown # "/outspends", 404, "not found");
      },
    );
  },
);
