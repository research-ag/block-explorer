// Subset of the Esplora HTTP API, served from the BlockExplorer
// canister via `http_request`. All routes are mounted under `/api/`
// to match mempool.space's URL shape (e.g. `https://mempool.space/api/...`).
// Formats, status codes and error texts follow Blockstream's esplora
// (API.md) and its electrs backend (src/rest.rs).
//
// Implemented (from headers, the indexed txids and the stored coinbases):
//   GET /api/blocks/tip/height            -> text
//   GET /api/blocks/tip/hash              -> text
//   GET /api/block-height/:height         -> text (canonical hash at height)
//   GET /api/block/:hash/header           -> text (160-char hex of 80-byte header)
//   GET /api/block/:hash/status           -> json {in_best_chain, height, next_best?}
//   GET /api/block/:hash                  -> json (tx_count once the body is
//                                            indexed; omits size/weight)
//   GET /api/block/:hash/txids            -> json [txid, ...] in block order
//   GET /api/block/:hash/txid/:index      -> text (txid at :index)
//   GET /api/blocks                       -> json (10 latest, descending)
//   GET /api/blocks/:start_height         -> json (10 ending at start_height, desc)
//   GET /api/tx/:txid/status              -> json {confirmed, block_height?,
//                                            block_hash?, block_time?}
//   GET /api/tx/:txid/merkle-proof        -> json {block_height, merkle, pos}
//                                            (Electrum's get_merkle)
//   GET /api/tx/:txid/merkleblock-proof   -> text (hex of bitcoind's merkleblock,
//                                            as `gettxoutproof`)
//   GET /api/tx/:txid/hex                 -> text  (coinbase transactions
//   GET /api/tx/:txid/raw                 -> bytes  without a witness only)
//
// The tx routes see the canonical chain up to the body tip (the txid
// index): a txid that isn't there is unconfirmed as far as these routes
// know, as with Esplora for one it hasn't indexed. `/block/:hash/txids`,
// `/txid/:index` and `tx_count` serve fork blocks too, once their bodies
// are stored. A block whose body isn't indexed yet (above the body tip, or
// mid-way through a chunked upload) has no txids: 404.
//
// Raw transactions aren't stored, except each canonical block's coinbase,
// without its witness. `/hex` and `/raw` serve a coinbase only where that
// is its full serialization, byte for byte Esplora's: where it has no
// witness commitment output. A coinbase with one (every block since
// segwit, in practice) has a witness, the 32-byte witness reserved value,
// which no stored data pins down: 404, rather than other bytes than
// Esplora's.
//
// Not implemented (would require full tx / mempool / address / raw block data):
//   /block/:hash/txs[/...], /block/:hash/raw, /tx/:txid, /tx/:txid/hex and
//   /raw for non-coinbase txs, /tx/:txid/outspend[s], /address/...,
//   /scripthash/..., /mempool*, /fee-estimates, /asset/...

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import VarArray "mo:core/VarArray";
import Prim "mo:⛔";

import Bitcoin "mo:mmr/Bitcoin";
import Prove "mo:mmr/Prove";

import Chain "Chain";
import Coinbases "Coinbases";
import Header "mo:btc/Header";
import HeaderValue "HeaderValue";

module {

  public type Request = {
    method : Text;
    url : Text;
    headers : [(Text, Text)];
    body : Blob;
  };

  public type Response = {
    status_code : Nat16;
    headers : [(Text, Text)];
    body : Blob;
  };

  // Esplora-style CORS headers; allow plain GET from any origin.
  let CORS : [(Text, Text)] = [
    ("access-control-allow-origin", "*"),
    ("access-control-allow-methods", "GET, OPTIONS"),
    ("access-control-allow-headers", "*"),
  ];

  func bytes(status : Nat16, contentType : Text, body : Blob) : Response = {
    status_code = status;
    headers = [
      ("content-type", contentType),
      CORS[0],
      CORS[1],
      CORS[2],
    ];
    body;
  };

  func plain(status : Nat16, body : Text) : Response = bytes(status, "text/plain; charset=utf-8", body.encodeUtf8());

  func json(status : Nat16, body : Text) : Response = bytes(status, "application/json", body.encodeUtf8());

  func notFound(msg : Text) : Response = plain(404, msg);
  func badRequest(msg : Text) : Response = plain(400, msg);

  // Esplora's (electrs's) answers to a malformed hash or number.
  func invalidHex() : Response = badRequest("Invalid hex string");
  func invalidNumber() : Response = badRequest("Invalid number");

  // Minimal Nat parser; returns null on any non-digit.
  func parseNat(t : Text) : ?Nat {
    if (t.size() == 0) return null;
    var n : Nat = 0;
    let zero = Prim.charToNat32('0');
    for (c in t.chars()) {
      let v32 = Prim.charToNat32(c);
      if (v32 < zero or v32 > zero + 9) return null;
      n := n * 10 + Nat32.toNat(v32 - zero);
    };
    ?n;
  };

  // Strip a leading '?...' query string from a URL, then split the
  // path on '/' and drop empty segments produced by the leading '/'.
  func splitPath(url : Text) : [Text] {
    let path = switch (url.split(#char '?').next()) {
      case (?p) p;
      case null url;
    };
    let out = List.empty<Text>();
    for (seg in path.split(#char '/')) {
      if (seg.size() > 0) out.add(seg);
    };
    out.toArray();
  };

  // ------------------------------------------------------------------
  // Hex.
  // ------------------------------------------------------------------

  let HEX_DIGITS : Blob = "0123456789abcdef";

  // The value of a hex digit (either case), or null.
  func nibble(c : Char) : ?Nat8 {
    let v = Prim.charToNat32(c);
    if (v >= 0x30 and v <= 0x39) return ?(v - 0x30).toNat().toNat8();
    if (v >= 0x61 and v <= 0x66) return ?(v - 0x57).toNat().toNat8();
    if (v >= 0x41 and v <= 0x46) return ?(v - 0x37).toNat().toNat8();
    null;
  };

  // A 32-byte hash (block hash or txid) from its 64-digit display hex, in
  // internal byte order (the display is byte-reversed). Null unless exactly
  // 64 hex digits; Esplora then answers 400 "Invalid hex string". Never
  // traps, unlike Header.hexToBlob.
  func parseHash(t : Text) : ?Blob {
    if (t.size() != 64) return null;
    let out = VarArray.repeat<Nat8>(0, 32);
    var i = 0; // digit index; digit pair k is byte 31 - k
    for (c in t.chars()) {
      let n = switch (nibble(c)) { case (?n) n; case null return null };
      let k = 31 - i / 2 : Nat;
      if (i % 2 == 0) out[k] := n << 4 else out[k] := out[k] | n;
      i += 1;
    };
    ?out.toBlob();
  };

  // Write the 64-digit display hex of the 32-byte hash `h` (internal order,
  // so the bytes are written last to first) into `buf` from `at`.
  func writeHashHex(buf : [var Nat8], at : Nat, h : Blob) {
    var i = 0;
    var j = at;
    while (i < 32) {
      let b = h[31 - i : Nat];
      buf[j] := HEX_DIGITS[(b >> 4).toNat()];
      buf[j + 1] := HEX_DIGITS[(b & 0x0f).toNat()];
      i += 1;
      j += 2;
    };
  };

  // The display hex of a 32-byte hash in internal order.
  func hashHex(h : Blob) : Text = Header.bytesToHex(Header.reverse32(h));

  // ------------------------------------------------------------------
  // JSON encoders.
  // ------------------------------------------------------------------

  // difficulty_x1e8 is `nat` with 8 implied decimal places. Render as
  // a plain JSON number "X.YYYYYYYY".
  func diffJson(x1e8 : Nat) : Text {
    let whole = x1e8 / 100_000_000;
    let frac = x1e8 % 100_000_000;
    var fracStr = frac.toText();
    while (fracStr.size() < 8) fracStr := "0" # fracStr;
    whole.toText() # "." # fracStr;
  };

  func quoted(t : Text) : Text = "\"" # t # "\"";

  // Render a stored block in Esplora's `/block/:hash` schema, in its field
  // order. `tx_count` appears once the block's body is indexed; `size` and
  // `weight` never (no stored data gives them, nor could the header verify
  // them). Genesis (height 0) omits `previousblockhash` to match Esplora.
  func blockJson(chain : Chain.State, b : Chain.StoredBlock) : Text {
    let v = b.value;
    let bits = HeaderValue.bitsOf(v);
    let target = Header.nBitsToTarget(bits);
    let diff = if (target == 0) 0 else Header.POW_LIMIT_TARGET * 100_000_000 / target;
    let mediantime = chain.mediantimeOf(b);

    var out = "{";
    out #= quoted("id") # ":" # quoted(hashHex(b.hash)) # ",";
    out #= quoted("height") # ":" # b.height.toText() # ",";
    out #= quoted("version") # ":" # HeaderValue.versionOf(v).toText() # ",";
    out #= quoted("timestamp") # ":" # HeaderValue.timeOf(v).toText() # ",";
    switch (chain.txCountOf(b)) {
      case (?n) out #= quoted("tx_count") # ":" # n.toText() # ",";
      case null {};
    };
    out #= quoted("merkle_root") # ":" # quoted(hashHex(HeaderValue.merkleOf(v))) # ",";
    if (b.height > 0) {
      out #= quoted("previousblockhash") # ":" # quoted(hashHex(Chain.prevHashOf(b))) # ",";
    };
    out #= quoted("mediantime") # ":" # mediantime.toText() # ",";
    out #= quoted("nonce") # ":" # HeaderValue.nonceOf(v).toText() # ",";
    out #= quoted("bits") # ":" # bits.toText() # ",";
    out #= quoted("difficulty") # ":" # diffJson(diff);
    out #= "}";
    out;
  };

  func statusJson(chain : Chain.State, b : Chain.StoredBlock) : Text {
    let inBest = Chain.isOnCanonical(b);
    var out = "{";
    out #= quoted("in_best_chain") # ":" # (if (inBest) "true" else "false") # ",";
    out #= quoted("height") # ":" # b.height.toText();
    if (inBest) {
      switch (chain.canonicalChildOf(b)) {
        case (?nxt) {
          out #= "," # quoted("next_best") # ":" # quoted(hashHex(nxt.hash));
        };
        case null {};
      };
    };
    out #= "}";
    out;
  };

  func blocksListJson(chain : Chain.State, startHeight : Nat) : Text {
    let n : Nat = if (startHeight + 1 < 10) startHeight + 1 else 10;
    var out = "[";
    var i : Nat = 0;
    while (i < n) {
      let h : Nat = startHeight - i;
      switch (chain.canonicalAt(h)) {
        case (?b) {
          if (i > 0) out #= ",";
          out #= blockJson(chain, b);
        };
        case null {};
      };
      i += 1;
    };
    out #= "]";
    out;
  };

  // `["<txid>",...]`, display hex, written into one byte buffer: a large
  // block has over 10 000 txids, and Text concatenation per txid would cost
  // several times more.
  func txidsJson(txids : [Blob]) : Blob {
    let n = txids.size();
    let size = if (n == 0) 2 else 2 + 66 * n + (n - 1 : Nat);
    let buf = VarArray.repeat<Nat8>(0, size);
    buf[0] := 0x5b; // [
    var j = 1;
    for (i in txids.keys()) {
      if (i > 0) { buf[j] := 0x2c; j += 1 }; // ,
      buf[j] := 0x22; // "
      writeHashHex(buf, j + 1, txids[i]);
      buf[j + 65] := 0x22;
      j += 66;
    };
    buf[j] := 0x5d; // ]
    buf.toBlob();
  };

  // `/tx/:txid/status` for a txid at `loc` (null: unconfirmed). The block is
  // canonical, so the field order is electrs's TransactionStatus.
  func txStatusJson(chain : Chain.State, loc : ?Chain.TxCanonLoc) : Text {
    let l = switch (loc) {
      case (?l) l;
      case null return "{" # quoted("confirmed") # ":false}";
    };
    let b = switch (chain.canonicalAt(l.height)) {
      case (?b) b;
      case null return "{" # quoted("confirmed") # ":false}";
    };
    var out = "{" # quoted("confirmed") # ":true,";
    out #= quoted("block_height") # ":" # l.height.toText() # ",";
    out #= quoted("block_hash") # ":" # quoted(hashHex(b.hash)) # ",";
    out #= quoted("block_time") # ":" # HeaderValue.timeOf(b.value).toText();
    out # "}";
  };

  // The levels of the Merkle tree over the txids of canonical block `b`
  // (level 0 the txids, the last the root alone; Bitcoin's tree, where a
  // last node without a partner pairs with itself), or null if its body
  // isn't indexed. About one double SHA-256 per txid.
  func treeLevels(chain : Chain.State, b : Chain.StoredBlock) : ?[[Blob]] {
    switch (chain.txCountOf(b)) {
      case (?n) ?Bitcoin.levels(chain.blockTxidsOf(b, 0, n));
      case null null;
    };
  };

  // Electrum's `blockchain.transaction.get_merkle`: the sibling of each
  // ancestor of the leaf at `pos`, lowest first, with the node itself
  // written out where Bitcoin pairs it with itself. Empty for a block of
  // one transaction. The siblings in display hex.
  func merkleProofJson(height : Nat, levels : [[Blob]], pos : Nat) : Text {
    let branch = Prove.branch(levels, pos, #copy);
    var out = "{" # quoted("block_height") # ":" # height.toText() # ",";
    out #= quoted("merkle") # ":[";
    for (i in branch.keys()) {
      if (i > 0) out #= ",";
      out #= quoted(hashHex(branch[i]));
    };
    out #= "]," # quoted("pos") # ":" # pos.toText() # "}";
    out;
  };

  // Append `n` as `k` bytes, little-endian.
  func addLE(out : List.List<Nat8>, n : Nat, k : Nat) {
    var x = n;
    var i = 0;
    while (i < k) { out.add((x % 256).toNat8()); x /= 256; i += 1 };
  };

  // Append Bitcoin's CompactSize encoding of `n`.
  func addCompactSize(out : List.List<Nat8>, n : Nat) {
    if (n < 0xfd) return addLE(out, n, 1);
    let (prefix, k) : (Nat, Nat) = if (n <= 0xffff) (0xfd, 2) else if (n <= 0xffff_ffff) (0xfe, 4) else (0xff, 8);
    addLE(out, prefix, 1);
    addLE(out, n, k);
  };

  // bitcoind's merkleblock (`gettxoutproof`, CMerkleBlock) for the leaf at
  // `pos` of the tree `levels` under the 80-byte `header`: the header, the
  // tx count (u32 LE), and the partial Merkle tree of BIP37 that matches
  // that one leaf: its hashes (CompactSize count, 32 bytes each, internal
  // order) and flag bits (CompactSize byte count, bits LSB first), from a
  // depth-first walk from the root. A node not above the leaf, or the leaf
  // itself, gives flag 0 or 1 and its hash; a node above it gives flag 1
  // and descends into both children (only the left one if there is no
  // right one, as Bitcoin pairs it with itself).
  func merkleBlock(header : Blob, levels : [[Blob]], pos : Nat) : Blob {
    let hashes = List.empty<Blob>();
    let flags = List.empty<Bool>();
    func walk(h : Nat, p : Nat) {
      let above = pos / (2 ** h) == p; // the subtree holds the leaf at `pos`
      flags.add(above);
      if (h == 0 or not above) {
        hashes.add(levels[h][p]);
        return;
      };
      walk(h - 1 : Nat, 2 * p);
      if (2 * p + 1 < levels[h - 1 : Nat].size()) walk(h - 1 : Nat, 2 * p + 1);
    };
    walk(levels.size() - 1 : Nat, 0);

    let out = List.empty<Nat8>();
    for (byte in header.values()) out.add(byte);
    addLE(out, levels[0].size(), 4);
    addCompactSize(out, hashes.size());
    for (h in hashes.values()) for (byte in h.values()) out.add(byte);
    let fl = flags.toArray();
    let flagBytes = VarArray.repeat<Nat8>(0, (fl.size() + 7) / 8);
    for (k in fl.keys()) {
      if (fl[k]) flagBytes[k / 8] := flagBytes[k / 8] | ((1 : Nat8) << (k % 8).toNat8());
    };
    addCompactSize(out, flagBytes.size());
    for (byte in flagBytes.values()) out.add(byte);
    out.toArray().toBlob();
  };

  // ------------------------------------------------------------------
  // Router.
  // ------------------------------------------------------------------

  // `metricsBody` is the prerendered Prometheus exposition (called
  // lazily by main.mo when the route matches `/metrics`). Passing a
  // thunk avoids the cost when serving Esplora routes.
  public func handle(
    chain : Chain.State,
    metricsBody : () -> Text,
    req : Request,
  ) : Response {
    if (req.method == "OPTIONS") return plain(204, "");
    if (req.method != "GET") return badRequest("method not allowed");

    let segs = splitPath(req.url);

    // /metrics (kept compatible with the previous PromHttp mixin).
    if (segs.size() == 1 and segs[0] == "metrics") {
      return plain(200, metricsBody());
    };

    // All Esplora routes live under /api/...
    if (segs.size() < 2 or segs[0] != "api") {
      return notFound("not found");
    };
    let p = segs.values().drop(1).toArray();

    // /api/blocks/tip/height
    if (p.size() == 3 and p[0] == "blocks" and p[1] == "tip" and p[2] == "height") {
      return plain(200, chain.tipHeight().toText());
    };

    // /api/blocks/tip/hash
    if (p.size() == 3 and p[0] == "blocks" and p[1] == "tip" and p[2] == "hash") {
      let tip = chain.tipBlock();
      return plain(200, Header.bytesToHex(Header.reverse32(tip.hash)));
    };

    // /api/blocks            -> 10 latest
    // /api/blocks/:height    -> 10 ending at height
    if (p[0] == "blocks" and (p.size() == 1 or p.size() == 2)) {
      let start = if (p.size() == 1) chain.tipHeight() else switch (parseNat(p[1])) {
        case (?n) n;
        case null return badRequest("invalid height");
      };
      if (start > chain.tipHeight()) return notFound("height out of range");
      return json(200, blocksListJson(chain, start));
    };

    // /api/block-height/:height
    if (p.size() == 2 and p[0] == "block-height") {
      let h = switch (parseNat(p[1])) {
        case (?n) n;
        case null return badRequest("invalid height");
      };
      switch (chain.canonicalAt(h)) {
        case (?b) return plain(200, Header.bytesToHex(Header.reverse32(b.hash)));
        case null return notFound("Block not found");
      };
    };

    // /api/block/:hash[/...]
    if (p[0] == "block" and p.size() >= 2) {
      let route = if (p.size() == 2) "" else p[2];
      let known = switch (p.size()) {
        case 2 true;
        case 3 route == "header" or route == "status" or route == "txids";
        case 4 route == "txid";
        case _ false;
      };
      if (not known) return notFound("not found");
      // Parse errors first, then the lookup: electrs's order.
      let hash = switch (parseHash(p[1])) {
        case (?h) h;
        case null return invalidHex();
      };
      let index = if (route == "txid") switch (parseNat(p[3])) {
        case (?i) i;
        case null return invalidNumber();
      } else 0;
      let b = switch (chain.byHashInternal(hash)) {
        case (?b) b;
        case null return notFound("Block not found");
      };
      if (route == "") return json(200, blockJson(chain, b));
      if (route == "header") {
        return plain(200, Header.bytesToHex(Chain.rawHeaderOf(b)));
      };
      if (route == "status") return json(200, statusJson(chain, b));
      // txids, txid/:index
      let n = switch (chain.txCountOf(b)) {
        case (?n) n;
        case null return notFound("Block transactions not indexed");
      };
      if (route == "txids") {
        return bytes(200, "application/json", txidsJson(chain.blockTxidsOf(b, 0, n)));
      };
      if (index >= n) return notFound("tx index out of range");
      return plain(200, hashHex(chain.blockTxidsOf(b, index, 1)[0]));
    };

    // /api/tx/:txid/...
    if (p[0] == "tx" and p.size() == 3) {
      let route = p[2];
      if (
        route != "status" and route != "merkle-proof" and route != "merkleblock-proof" and route != "hex" and route != "raw"
      ) return notFound("not found");
      let txid = switch (parseHash(p[1])) {
        case (?t) t;
        case null return invalidHex();
      };
      let loc = chain.indexedTxLocation(txid);
      if (route == "status") return json(200, txStatusJson(chain, loc));

      let l = switch (loc) {
        case (?l) l;
        case null return notFound(if (route == "hex" or route == "raw") "Transaction not found" else "Transaction not found or is unconfirmed");
      };
      let b = switch (chain.canonicalAt(l.height)) {
        case (?b) b;
        case null return notFound("Transaction not found or is unconfirmed");
      };

      if (route == "hex" or route == "raw") {
        // Only coinbases (position 0) are stored, and only at heights the
        // coinbase backfill has reached; served only where the stored
        // (witness-stripped) bytes are the whole transaction.
        let raw = if (l.position == 0) chain.getCanonicalCoinbase(l.height) else null;
        let tx = switch (raw) {
          case (?tx) tx;
          case null return notFound("Raw transaction not stored (coinbase transactions only)");
        };
        if (Coinbases.witnessCommitted(tx) != ?false) {
          return notFound("Raw transaction not stored (the coinbase's witness is not stored)");
        };
        return if (route == "hex") plain(200, Header.bytesToHex(tx)) else bytes(200, "application/octet-stream", tx);
      };

      let levels = switch (treeLevels(chain, b)) {
        case (?lv) lv;
        case null return notFound("Transaction not found or is unconfirmed");
      };
      if (route == "merkle-proof") {
        return json(200, merkleProofJson(l.height, levels, l.position));
      };
      return plain(200, Header.bytesToHex(merkleBlock(Chain.rawHeaderOf(b), levels, l.position)));
    };

    notFound("not found");
  };

};
