// Subset of the Esplora HTTP API, served from the BlockExplorer
// canister via `http_request`. All routes are mounted under `/api/`
// to match mempool.space's URL shape (e.g. `https://mempool.space/api/...`).
//
// Implemented (header-only data):
//   GET /api/blocks/tip/height            -> text
//   GET /api/blocks/tip/hash              -> text
//   GET /api/block-height/:height         -> text (canonical hash at height)
//   GET /api/block/:hash/header           -> text (160-char hex of 80-byte header)
//   GET /api/block/:hash/status           -> json {in_best_chain, height, next_best?}
//   GET /api/block/:hash                  -> json (omits tx_count/size/weight)
//   GET /api/blocks                       -> json (10 latest, descending)
//   GET /api/blocks/:start_height         -> json (10 ending at start_height, desc)
//
// Not implemented (would require tx / mempool / address / raw block data):
//   /block/:hash/txs[/...], /block/:hash/txid/:i, /block/:hash/txids,
//   /block/:hash/raw, /tx/..., /address/..., /scripthash/...,
//   /mempool*, /fee-estimates, /asset/...

import Blob "mo:core/Blob";
import Iter "mo:core/Iter";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import Prim "mo:⛔";

import Chain "Chain";
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

  func plain(status : Nat16, body : Text) : Response = {
    status_code = status;
    headers = [
      ("content-type", "text/plain; charset=utf-8"),
      CORS[0],
      CORS[1],
      CORS[2],
    ];
    body = Text.encodeUtf8(body);
  };

  func json(status : Nat16, body : Text) : Response = {
    status_code = status;
    headers = [
      ("content-type", "application/json"),
      CORS[0],
      CORS[1],
      CORS[2],
    ];
    body = Text.encodeUtf8(body);
  };

  func notFound(msg : Text) : Response = plain(404, msg);
  func badRequest(msg : Text) : Response = plain(400, msg);

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
    let path = switch (Text.split(url, #char '?').next()) {
      case (?p) p;
      case null url;
    };
    let out = List.empty<Text>();
    for (seg in Text.split(path, #char '/')) {
      if (seg.size() > 0) List.add(out, seg);
    };
    List.toArray(out);
  };

  // ------------------------------------------------------------------
  // JSON encoders.
  // ------------------------------------------------------------------

  // difficulty_x1e8 is `nat` with 8 implied decimal places. Render as
  // a plain JSON number "X.YYYYYYYY".
  func diffJson(x1e8 : Nat) : Text {
    let whole = x1e8 / 100_000_000;
    let frac = x1e8 % 100_000_000;
    var fracStr = Nat.toText(frac);
    while (fracStr.size() < 8) fracStr := "0" # fracStr;
    Nat.toText(whole) # "." # fracStr;
  };

  func quoted(t : Text) : Text = "\"" # t # "\"";

  // Render a stored block in Esplora's `/block/:hash` schema, omitting
  // `tx_count`, `size`, `weight` (we don't have transaction data).
  // Genesis (height 0) omits `previousblockhash` to match Esplora.
  func blockJson(chain : Chain.State, b : Chain.StoredBlock) : Text {
    let v = b.value;
    let bits = HeaderValue.bitsOf(v);
    let target = Header.nBitsToTarget(bits);
    let diff = if (target == 0) 0 else Header.POW_LIMIT_TARGET * 100_000_000 / target;
    let hashHex = Header.bytesToHex(Header.reverse32(b.hash));
    let merkleHex = Header.bytesToHex(Header.reverse32(HeaderValue.merkleOf(v)));
    let mediantime = chain.mediantimeOf(b);

    var out = "{";
    out #= quoted("id") # ":" # quoted(hashHex) # ",";
    out #= quoted("height") # ":" # Nat.toText(b.height) # ",";
    out #= quoted("version") # ":" # Nat32.toText(HeaderValue.versionOf(v)) # ",";
    out #= quoted("timestamp") # ":" # Nat32.toText(HeaderValue.timeOf(v)) # ",";
    out #= quoted("merkle_root") # ":" # quoted(merkleHex) # ",";
    if (b.height > 0) {
      let prevHex = Header.bytesToHex(Header.reverse32(Chain.prevHashOf(b)));
      out #= quoted("previousblockhash") # ":" # quoted(prevHex) # ",";
    };
    out #= quoted("mediantime") # ":" # Nat32.toText(mediantime) # ",";
    out #= quoted("nonce") # ":" # Nat32.toText(HeaderValue.nonceOf(v)) # ",";
    out #= quoted("bits") # ":" # Nat32.toText(bits) # ",";
    out #= quoted("difficulty") # ":" # diffJson(diff);
    out #= "}";
    out;
  };

  func statusJson(chain : Chain.State, b : Chain.StoredBlock) : Text {
    let inBest = Chain.isOnCanonical(b);
    var out = "{";
    out #= quoted("in_best_chain") # ":" # (if (inBest) "true" else "false") # ",";
    out #= quoted("height") # ":" # Nat.toText(b.height);
    if (inBest) {
      switch (chain.canonicalChildOf(b)) {
        case (?nxt) {
          let h = Header.bytesToHex(Header.reverse32(nxt.hash));
          out #= "," # quoted("next_best") # ":" # quoted(h);
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
    let p = Iter.toArray<Text>(Iter.drop<Text>(segs.vals(), 1));

    // /api/blocks/tip/height
    if (p.size() == 3 and p[0] == "blocks" and p[1] == "tip" and p[2] == "height") {
      return plain(200, Nat.toText(chain.tipHeight()));
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
      let b = switch (chain.byHashBE(p[1])) {
        case (?b) b;
        case null return notFound("Block not found");
      };
      if (p.size() == 2) return json(200, blockJson(chain, b));
      if (p.size() == 3 and p[2] == "header") {
        return plain(200, Header.bytesToHex(Chain.rawHeaderOf(b)));
      };
      if (p.size() == 3 and p[2] == "status") {
        return json(200, statusJson(chain, b));
      };
      return notFound("not found");
    };

    notFound("not found");
  };

};
