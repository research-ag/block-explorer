// Recurring header fetcher.
//
// Every 30s (so each of the two providers gets hit once a minute),
// reconcile `block_explorer`'s chain with one
// Esplora-compatible provider (blockstream.info, mempool.space, ...)
// chosen round-robin from `PROVIDERS`, one provider per tick.
//
// Algorithm
// ---------
//   0. Call `<api>/blocks/tip/hash` — returns just the provider's
//      tip hash (64 B body; ~685 B total with HTTP headers, ~71M cycles
//      at n=13 with a 2 KiB response cap). If it matches
//      `lastSeenTipHash` from the last successful tick, the chain
//      hasn't moved and the tick is done. ~90% of ticks short-circuit
//      here, saving ~64M cycles each vs running the full /blocks path.
//   1. Otherwise call `<api>/blocks` — returns up to 10 most recent
//      blocks from the provider in descending order, each with its
//      hash (`id`), `height`, and the full header fields.
//   2. Pass all 10 hashes to `block_explorer.have_hashes` in one
//      call (it already takes an arbitrary-length array). The
//      highest hash we already store is the last common ancestor.
//   3. If none of the 10 are known (fork deeper than 10, or
//      provider more than 10 blocks ahead), page back via
//      `<api>/blocks/<lowestHeight - 1>` and repeat. Bounded by
//      MAX_BATCHES (=100) — up to 1000 blocks of walkback per tick.
//   4. Walk forwards from `common + 1` using the BlockFields already
//      collected during steps 1–3. The /blocks response carries
//      version, prev, merkle, time, bits, nonce — everything needed
//      to reconstruct the canonical 80-byte raw header locally —
//      so no /block/<hash>/header outcall is needed. The full
//      ascending batch is pushed in a single `push_headers`
//      call. Bounded by MAX_FORWARD (=100) per tick.
//
// Note: we never ask block_explorer for *its* tip. The provider's
// /blocks tells us their tip; have_hashes tells us where ours
// connects. That's enough to drive both discovery and push.
//
// This handles every case:
//   - In sync: first batch's top hash is known; nothing to push.
//   - We're a few behind: first batch contains the common ancestor;
//     push the blocks above it.
//   - Fork up to 1000 deep: page back across multiple batches until
//     we find the common ancestor; then forward-push their chain.
//     `block_explorer` accepts work-heavier siblings and reorgs.
//   - Fork deeper than 1000 (or no common ancestor in window): bail,
//     try again next tick.
//
// Per-tick call budget:
//   up to MAX_BATCHES /blocks outcalls +
//   up to MAX_BATCHES have_hashes (inter-canister, 1 per batch) +
//   at most 1 push_headers (inter-canister, regardless of N).
// In the typical "near the tip" tick this is 1 outcall + 1
// have_hashes + (0 or 1) push_headers. No /block/<hash>/header
// outcalls — every header is reconstructed locally from the
// version/prev/merkle/time/bits/nonce fields in the /blocks response.
// Esplora-compatible `/api/blocks` shape only.
//
// Outcalls are non-replicated (single node) to minimise cycle cost.
//
// Observability: each tick records one log entry per stage reached
// (#blocks / #header / #push) with an outcome (#ok or an
// error variant) plus a free-form detail string. Per-stage counters
// and a ring buffer of the last 50 entries are exposed via
// `status()` and `recent_logs(n)`.

import Array "mo:core/Array";
import Char "mo:core/Char";
import Cycles "mo:core/Cycles";
import Error "mo:core/Error";
import Int "mo:core/Int";
import Iter "mo:core/Iter";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Time "mo:core/Time";
import Timer "mo:core/Timer";
import VarArray "mo:core/VarArray";

import PT "mo:promtracker";
import { Counter } "mo:promtracker";
import Tracker "mo:promtracker/Tracker"; // for dot-notation: pt.newCounter, pt.toValue
import Http "mo:promtracker/mixins/http";

import Prim "mo:⛔";

import BEHeader "mo:btc-light/Header";

persistent actor HeaderFetcher {

  // ------------------------------------------------------------------
  // Prometheus metrics.
  //
  // `pt` (Tracker) holds the persistent counters for every diagnostic
  // value the canister tracks — these are the source of truth, and
  // `status()` reads them back. `renderer` (transient) is the thing
  // serialised to Prometheus exposition on every /metrics scrape; on
  // upgrade it's rebuilt from the persistent tracker plus the
  // system-metrics bundle.
  // ------------------------------------------------------------------
  let pt = PT.Tracker.new();
  // Hold-down 62 s (default 302). `pt` is STABLE (counters survive
  // upgrades), so a value passed to the initializer would be pinned at
  // install time — this statement re-runs on every start, applying the
  // current code's value to fresh installs AND upgrades alike. (Hold-down
  // only affects gauge watermarks; today this tracker holds only counters.)
  PT.Tracker.setHoldDown(pt, 62);
  transient let renderer = PT.Renderer();
  renderer.addCanisterLabel(HeaderFetcher);
  renderer.addValue(PT.allSystemMetrics);
  renderer.addValue(pt.toValue());
  include Http(renderer.renderExposition, "/metrics");

  // ------------------------------------------------------------------
  // block_explorer interface (subset we need).
  // ------------------------------------------------------------------

  type BatchPushResult = {
    accepted : Nat;
    last_error : ?Text;
  };

  type BlockExplorer = actor {
    have_hashes : ([Text]) -> async [Bool];
    push_headers : ([Blob]) -> async Result.Result<BatchPushResult, Text>;
  };

  transient let blockExplorerId : Principal = Principal.fromText(
    switch (Runtime.envVar<system>("PUBLIC_CANISTER_ID:block_explorer")) {
      case (?id) id;
      case null Runtime.trap("PUBLIC_CANISTER_ID:block_explorer not set");
    }
  );

  transient let blockExplorer : BlockExplorer = actor (Principal.toText(blockExplorerId));

  // ------------------------------------------------------------------
  // Management canister: http_request (HTTPS outcall).
  // ------------------------------------------------------------------

  type HttpHeader = { name : Text; value : Text };
  type HttpMethod = { #get; #post; #head };
  type HttpRequestArgs = {
    url : Text;
    max_response_bytes : ?Nat64;
    headers : [HttpHeader];
    body : ?Blob;
    method : HttpMethod;
    transform : ?{
      function : shared query { response : HttpResponse; context : Blob } -> async HttpResponse;
      context : Blob;
    };
    is_replicated : ?Bool;
  };
  type HttpResponse = { status : Nat; headers : [HttpHeader]; body : Blob };
  type IC = actor { http_request : HttpRequestArgs -> async HttpResponse };

  transient let ic : IC = actor ("aaaaa-aa");

  // Cycles attached per /blocks outcall. `is_replicated = ?false`
  // affects execution semantics (a single node makes the call, no
  // consensus on the response) but does *not* drop the cycle cost
  // — n stays at the subnet's replication factor (13 for an
  // application subnet) in the IC cost formula:
  //
  //   total = (3_000_000 + 60_000·n)·n        // base
  //         + (400·req_bytes + 800·resp_bytes)·n
  //
  // n=13, req≈200 B, resp=BLOCKS_MAX_BYTES (8 KiB):
  //   base     = 49_140_000
  //   request  =  1_040_000
  //   response = 85_196_800
  //   total    ≈ 135_376_800
  //
  // 150M leaves ~10% headroom. Any unused cycles are refunded.
  transient let OUTCALL_CYCLES : Nat = 150_000_000;

  // A /blocks response is up to 10 blocks at ~500 B each plus JSON
  // wrapping (~5–6 KiB total). 8 KiB gives modest headroom; the
  // response is rejected if it exceeds this.
  transient let BLOCKS_MAX_BYTES : Nat64 = 8_192;

  // /blocks/tip/hash returns a single 64-char hex line. NOTE:
  // `max_response_bytes` caps the HTTP response *headers + body*, not just
  // the body — and these Esplora providers send ~620-650 B of headers
  // (CSP, CORS, HSTS, cache-control, …) on top of the 64 B body (measured:
  // blockstream ≈685 B total, mempool ≈671 B). 128 B therefore rejected
  // every response ("Header size exceeds specified response size limit").
  // 2 KiB leaves ample headroom for CDN header bloat (cf-ray, nel,
  // report-to, alt-svc, …). Cost at 2 KiB ≈ 71M cycles — still well under
  // the ~135M of the full /blocks fetch, so the precheck stays worthwhile.
  transient let TIP_HASH_MAX_BYTES : Nat64 = 2_048;

  // Per-tick bounds.
  transient let BATCH_SIZE : Nat = 10; // /blocks returns up to 10
  transient let MAX_BATCHES : Nat = 100; // up to 1000 blocks of walkback
  transient let MAX_FORWARD : Nat = 100; // forward push cap per tick

  // ------------------------------------------------------------------
  // Esplora providers.
  //
  // mempool.space exposes the same Esplora REST API as
  // blockstream.info, so the same URL paths work on both. We rotate
  // through this list in order, one provider per tick (round-robin),
  // to spread load and avoid making both providers see us as a hot
  // single client. Only one provider is queried per tick — the next
  // tick uses the next provider in the list.
  transient let PROVIDERS : [Text] = [
    "https://blockstream.info/api",
    "https://mempool.space/api",
  ];

  // Persisted across upgrades so the rotation pointer survives. The
  // selected provider for tick `n` is `PROVIDERS[n % PROVIDERS.size()]`,
  // which we derive from `ticks` rather than tracking separately.
  func providerForTick(t : Nat) : Text {
    PROVIDERS[t % PROVIDERS.size()];
  };

  // ------------------------------------------------------------------
  // Log buffer.
  // ------------------------------------------------------------------

  public type Stage = { #blocks; #header; #push };

  public type Outcome = {
    #ok;
    #call_failed : Text; // catch-block: trap / timeout / out-of-cycles
    #http_status : Nat; // outcall returned non-200
    #non_utf8;
    #unexpected_payload : Text; // wrong size / shape
    #rejected : Text; // canister-side validation error
  };

  public type LogEntry = {
    tick : Nat;
    at_ns : Int;
    height : ?Nat;
    stage : Stage;
    outcome : Outcome;
    detail : Text;
  };

  // Transient: a plain `let` would be stable and pin the installed value
  // across upgrades. The ring buffer itself persists, so wrap-around math
  // follows logBuf.size(), not this constant.
  transient let LOG_CAPACITY : Nat = 50;
  var logBuf : [var ?LogEntry] = [var];
  var logNext : Nat = 0;
  var logCount : Nat = 0;

  func ensureLogBuf() {
    if (logBuf.size() == 0) {
      logBuf := VarArray.tabulate<?LogEntry>(LOG_CAPACITY, func _ = null);
    };
  };

  // ------------------------------------------------------------------
  // Counters and gauges (promtracker is the source of truth).
  //
  // Cumulative event counts go in plain Counters; "last value"
  // observables (timestamps, heights) live in Counters with `.set`
  // — single-line Prometheus output, simpler than a Gauge. The
  // Tracker itself is persistent so counter values survive upgrades;
  // each Counter binding is also non-transient for the same reason.
  // status() reads back from these via Int.abs(c.value).
  // ------------------------------------------------------------------
  let ticksCounter = pt.newCounter("ticks_total", []);
  let skippedTicksCounter = pt.newCounter("ticks_skipped_total", []);
  let blocksOkCounter = pt.newCounter("stage_blocks_ok_total", []);
  let blocksErrCounter = pt.newCounter("stage_blocks_err_total", []);
  let headerOkCounter = pt.newCounter("stage_header_ok_total", []);
  let headerErrCounter = pt.newCounter("stage_header_err_total", []);
  let pushOkCounter = pt.newCounter("stage_push_ok_total", []);
  let pushErrCounter = pt.newCounter("stage_push_err_total", []);
  let lastTickAtCounter = pt.newCounter("last_tick_at_ns", []);
  let lastSuccessAtCounter = pt.newCounter("last_success_at_ns", []);
  let lastProviderTipCounter = pt.newCounter("last_provider_tip", []);
  let lastFetchedHeightCounter = pt.newCounter("last_fetched_height", []);

  // PullValues for log-buffer state — these read the underlying
  // ring-buffer counters directly so the metric and status() share
  // the same source.
  renderer.addValue(PT.newValue("log_total", [], func() = logCount));
  renderer.addValue(PT.newValue("log_capacity", [], func() = LOG_CAPACITY));

  // Cheap Nat read of an Int-typed Counter value. Counters only get
  // .add(Nat) / .set(Nat) here, so .value is always non-negative.
  transient func cv(c : PT.Counter) : Nat = Int.abs(c.value);

  // BE-hex of the provider's tip the last time we processed a tick
  // through to completion. If a new tick's /blocks response has the
  // same first hash, the chain hasn't moved and we skip the full
  // parse + have_hashes round trip.
  var lastSeenTipHash : Text = "";

  // Re-entrancy guard. Transient so an upgrade can't strand it as
  // `true`: the in-flight call is aborted by the upgrade, and a
  // fresh post-upgrade state starts with the flag back to false.
  transient var tickInFlight : Bool = false;

  func record(tickN : Nat, height : ?Nat, stage : Stage, outcome : Outcome, detail : Text) {
    ensureLogBuf();
    logBuf[logNext] := ?{
      tick = tickN;
      at_ns = Time.now();
      height;
      stage;
      outcome;
      detail;
    };
    logNext := (logNext + 1) % logBuf.size();
    logCount += 1;

    let ok = switch outcome { case (#ok) true; case _ false };
    switch (stage, ok) {
      case (#blocks, true) blocksOkCounter.add(1);
      case (#blocks, false) blocksErrCounter.add(1);
      case (#header, true) headerOkCounter.add(1);
      case (#header, false) headerErrCounter.add(1);
      case (#push, true) pushOkCounter.add(1);
      case (#push, false) pushErrCounter.add(1);
    };
  };

  // ------------------------------------------------------------------
  // Public observability.
  // ------------------------------------------------------------------

  public type Status = {
    block_explorer : Principal;
    cycles_balance : Nat;
    ticks : Nat;
    last_tick_at_ns : Int;
    last_success_at_ns : Int;
    last_provider_tip : Nat;
    last_fetched_height : Nat;
    skipped_ticks : Nat;
    blocks_ok : Nat;
    blocks_err : Nat;
    header_ok : Nat;
    header_err : Nat;
    push_ok : Nat;
    push_err : Nat;
    log_total : Nat;
    log_capacity : Nat;
  };

  public query func status() : async Status {
    {
      block_explorer = blockExplorerId;
      cycles_balance = Cycles.balance();
      ticks = cv(ticksCounter);
      last_tick_at_ns = lastTickAtCounter.value;
      last_success_at_ns = lastSuccessAtCounter.value;
      last_provider_tip = cv(lastProviderTipCounter);
      last_fetched_height = cv(lastFetchedHeightCounter);
      skipped_ticks = cv(skippedTicksCounter);
      blocks_ok = cv(blocksOkCounter);
      blocks_err = cv(blocksErrCounter);
      header_ok = cv(headerOkCounter);
      header_err = cv(headerErrCounter);
      push_ok = cv(pushOkCounter);
      push_err = cv(pushErrCounter);
      log_total = logCount;
      log_capacity = LOG_CAPACITY;
    };
  };

  // Returns up to `n` most recent log entries, newest first.
  public query func recent_logs(n : Nat) : async [LogEntry] {
    if (logCount == 0 or logBuf.size() == 0) return [];
    let cap = logBuf.size();
    let stored = if (logCount < cap) logCount else cap;
    let want = if (n < stored) n else stored;
    Array.tabulate<LogEntry>(
      want,
      func i {
        let idx = (logNext + cap - 1 - i : Nat) % cap;
        switch (logBuf[idx]) {
          case (?e) e;
          case null Runtime.trap("log buffer hole");
        };
      },
    );
  };

  // ------------------------------------------------------------------
  // HTTP helper.
  // ------------------------------------------------------------------

  func httpGet(
    tickN : Nat,
    height : ?Nat,
    stage : Stage,
    url : Text,
    maxBytes : Nat64,
  ) : async ?Text {
    let req : HttpRequestArgs = {
      url;
      max_response_bytes = ?maxBytes;
      headers = [];
      body = null;
      method = #get;
      transform = null;
      is_replicated = ?false;
    };
    let resp = try {
      await (with cycles = OUTCALL_CYCLES) ic.http_request(req);
    } catch (e) {
      record(tickN, height, stage, #call_failed(Error.message(e)), url);
      return null;
    };
    if (resp.status != 200) {
      let snippet = bodySnippet(resp.body, 120);
      record(tickN, height, stage, #http_status(resp.status), url # " body=" # snippet);
      return null;
    };
    switch (Text.decodeUtf8(resp.body)) {
      case (?t) ?Text.trim(
        t,
        #predicate(
          func(c) = c == ' ' or c == '\n' or c == '\r' or c == '\t'
        ),
      );
      case null { record(tickN, height, stage, #non_utf8, url); null };
    };
  };

  func bodySnippet(b : Blob, maxLen : Nat) : Text {
    let s = switch (Text.decodeUtf8(b)) { case (?t) t; case null "<binary>" };
    if (Text.size(s) <= maxLen) return s;
    var out = "";
    var i = 0;
    label l for (c in s.chars()) {
      if (i >= maxLen) break l;
      out #= Text.fromChar(c);
      i += 1;
    };
    out # "...";
  };

  // ------------------------------------------------------------------
  // JSON shape extraction for /blocks responses.
  //
  // The Esplora /api/blocks response is a JSON array of flat block
  // objects. We split the array into per-object substrings via
  // brace-depth tracking (string-aware so nested quotes don't fool
  // us), then within each object find the fields we need by marker
  // search. This is robust to key reordering and ignores any extra
  // fields.
  //
  // We extract every field needed to reconstruct the canonical
  // 80-byte raw header (version, prev, merkle, time, bits, nonce),
  // so the forward push needs no additional /block/.../header
  // outcall.
  // ------------------------------------------------------------------

  public type BlockFields = {
    height : Nat;
    id : Text; // BE display hex, 64 chars
    version : Nat32;
    prev : ?Text; // BE display hex, 64 chars; null for genesis
    merkle : Text; // BE display hex, 64 chars
    timestamp : Nat32;
    bits : Nat32;
    nonce : Nat32;
  };

  // Slice cs[from..to) into a fresh Text.
  func sliceText(cs : [Char], from : Nat, to : Nat) : Text {
    let sub = Array.tabulate<Char>((to - from : Nat), func(j) = cs[from + j]);
    Text.fromIter(sub.vals());
  };

  // Split a top-level JSON array string into its per-element object
  // substrings. Each returned substring includes the outer { and }.
  // Returns null on structural failure. Walks strings with `\` escape
  // awareness so a `}` inside a string doesn't close an object.
  func splitTopLevelObjects(json : Text) : ?[Text] {
    let cs = Iter.toArray<Char>(json.chars());
    let n = cs.size();
    var i : Nat = 0;
    while (i < n and cs[i] != '[') i += 1;
    if (i >= n) return null;
    i += 1;

    let ranges = List.empty<(Nat, Nat)>();
    label outer loop {
      while (i < n) {
        let c = cs[i];
        if (c == ' ' or c == ',' or c == '\n' or c == '\r' or c == '\t') i += 1 else break;
      };
      if (i >= n) return null;
      if (cs[i] == ']') break outer;
      if (cs[i] != '{') return null;

      let start = i;
      var depth : Nat = 1;
      i += 1;
      label scan loop {
        if (i >= n) return null;
        let c = cs[i];
        if (c == '\"') {
          i += 1;
          label skip loop {
            if (i >= n) return null;
            if (cs[i] == '\\') {
              if (i + 1 >= n) return null;
              i += 2;
            } else if (cs[i] == '\"') {
              i += 1;
              break skip;
            } else i += 1;
          };
        } else if (c == '{') { depth += 1; i += 1 } else if (c == '}') {
          depth -= 1;
          i += 1;
          if (depth == 0) break scan;
        } else i += 1;
      };
      List.add(ranges, (start, i));
    };

    let rArr = List.toArray(ranges);
    ?Array.tabulate<Text>(
      rArr.size(),
      func(k) {
        let (s, e) = rArr[k];
        sliceText(cs, s, e);
      },
    );
  };

  // Take the first 64 chars of `t` and return them as a Text if they
  // are all hex digits; otherwise null.
  func first64Hex(t : Text) : ?Text {
    var out = "";
    var n : Nat = 0;
    label scan for (c in t.chars()) {
      if (n >= 64) break scan;
      let isH = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
      if (not isH) return null;
      out #= Text.fromChar(c);
      n += 1;
    };
    if (n == 64) ?out else null;
  };

  // Parse leading decimal digits as a Nat. Skips leading whitespace.
  // Returns null if no digits are found.
  func leadingNat(t : Text) : ?Nat {
    var n : Nat = 0;
    var hasDigit = false;
    label scan for (c in t.chars()) {
      if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
        if (hasDigit) break scan;
        // skip leading whitespace
      } else if (c >= '0' and c <= '9') {
        let d = Nat32.toNat(Prim.charToNat32(c) - Prim.charToNat32('0'));
        n := n * 10 + d;
        hasDigit := true;
      } else break scan;
    };
    if (hasDigit) ?n else null;
  };

  // Locate `marker` in `obj` and return the 64-hex string that
  // immediately follows. Used for fields like `"id":"...":` whose
  // marker includes the opening quote.
  func findHexAfter(obj : Text, marker : Text) : ?Text {
    let parts = Iter.toArray(Text.split(obj, #text marker));
    if (parts.size() < 2) return null;
    first64Hex(parts[1]);
  };

  // Locate `marker` in `obj` and return the Nat that immediately
  // follows. Used for numeric fields like `"height":`.
  func findNatAfter(obj : Text, marker : Text) : ?Nat {
    let parts = Iter.toArray(Text.split(obj, #text marker));
    if (parts.size() < 2) return null;
    leadingNat(parts[1]);
  };

  func findNat32After(obj : Text, marker : Text) : ?Nat32 {
    switch (findNatAfter(obj, marker)) {
      case null null;
      case (?n) {
        if (n > 0xFFFF_FFFF) null else ?Nat32.fromNat(n);
      };
    };
  };

  func parseBlock(obj : Text) : ?BlockFields {
    let id = findHexAfter(obj, "\"id\":\"");
    let height = findNatAfter(obj, "\"height\":");
    let version = findNat32After(obj, "\"version\":");
    let prev = findHexAfter(obj, "\"previousblockhash\":\"");
    let merkle = findHexAfter(obj, "\"merkle_root\":\"");
    let timestamp = findNat32After(obj, "\"timestamp\":");
    let bits = findNat32After(obj, "\"bits\":");
    let nonce = findNat32After(obj, "\"nonce\":");
    switch (id, height, version, merkle, timestamp, bits, nonce) {
      case (?i, ?h, ?v, ?m, ?t, ?b, ?n) ?{
        id = i;
        height = h;
        version = v;
        prev;
        merkle = m;
        timestamp = t;
        bits = b;
        nonce = n;
      };
      case _ null;
    };
  };

  // Parse a JSON /blocks response into per-block records, in the
  // order they appear (descending heights). Returns null on any
  // structural surprise.
  func parseBlocks(json : Text) : ?[BlockFields] {
    let objs = switch (splitTopLevelObjects(json)) {
      case (?xs) xs;
      case null return null;
    };
    if (objs.size() == 0) return null;
    let out = VarArray.repeat<?BlockFields>(null, objs.size());
    var i : Nat = 0;
    while (i < objs.size()) {
      switch (parseBlock(objs[i])) {
        case (?b) out[i] := ?b;
        case null return null;
      };
      i += 1;
    };
    ?Array.tabulate<BlockFields>(
      objs.size(),
      func(k) {
        switch (out[k]) { case (?b) b; case null Runtime.trap("unreachable") };
      },
    );
  };

  // ------------------------------------------------------------------
  // Raw 80-byte header reconstruction (160 hex chars).
  //
  // Layout (Bitcoin internal LE):
  //   off bytes field
  //     0     4 version       (LE Nat32)
  //     4    32 prev_hash     (internal LE; reverse the BE display)
  //    36    32 merkle_root   (internal LE; reverse the BE display)
  //    68     4 time          (LE Nat32)
  //    72     4 bits          (LE Nat32)
  //    76     4 nonce         (LE Nat32)
  // ------------------------------------------------------------------

  func hexCharOf(n : Nat) : Char {
    if (n < 10) {
      Char.fromNat32(0x30 + Nat32.fromNat(n));
    } else {
      Char.fromNat32(0x61 + Nat32.fromNat(n - 10 : Nat));
    };
  };

  // 8-char hex for the little-endian byte order of `v`.
  func nat32ToLeHex(v : Nat32) : Text {
    var out = "";
    var i : Nat = 0;
    while (i < 4) {
      let shift = Nat32.fromNat(i * 8);
      let byte = Nat32.toNat((v >> shift) & 0xff);
      out #= Text.fromChar(hexCharOf(byte / 16));
      out #= Text.fromChar(hexCharOf(byte % 16));
      i += 1;
    };
    out;
  };

  // Reverse a 64-hex string in 2-char chunks (byte order reversal).
  // Returns null if the input isn't 64 chars long.
  func reverseHex32(hex : Text) : ?Text {
    let cs = Iter.toArray<Char>(hex.chars());
    if (cs.size() != 64) return null;
    let buf = VarArray.repeat<Char>('0', 64);
    var i : Nat = 0;
    while (i < 32) {
      let dst = (31 - i : Nat) * 2;
      buf[dst] := cs[2 * i];
      buf[dst + 1] := cs[2 * i + 1];
      i += 1;
    };
    ?Text.fromIter(Array.fromVarArray(buf).vals());
  };

  // Reconstruct the canonical 80-byte raw header as a 160-char hex
  // string. Returns null if `prev` is missing (genesis is not pushable
  // anyway).
  func rawHeaderHex(b : BlockFields) : ?Text {
    let prevBE = switch (b.prev) { case (?p) p; case null return null };
    let prevLE = switch (reverseHex32(prevBE)) {
      case (?h) h;
      case null return null;
    };
    let merkleLE = switch (reverseHex32(b.merkle)) {
      case (?h) h;
      case null return null;
    };
    ?(
      nat32ToLeHex(b.version) #
      prevLE #
      merkleLE #
      nat32ToLeHex(b.timestamp) #
      nat32ToLeHex(b.bits) #
      nat32ToLeHex(b.nonce)
    );
  };

  // ------------------------------------------------------------------
  // Tick.
  // ------------------------------------------------------------------

  // Re-entrancy-guarded entry point. The IC's `Timer` does not wait
  // for the previous fire's call context to complete before firing
  // again, so a slow tick can overlap the next one. We skip rather
  // than queue: a missed tick is harmless (the next one picks up
  // wherever we left off), and queueing would let backed-up timers
  // pile up unboundedly.
  func tick() : async () {
    if (tickInFlight) {
      skippedTicksCounter.add(1);
      return;
    };
    tickInFlight := true;
    // try/catch covers an unexpected `throw` out of tickBody. A
    // *trap* inside tickBody can't be caught here, but the actor's
    // state-rollback on trap will revert `tickInFlight := true`
    // anyway, so the flag won't get stranded either way.
    try {
      await tickBody();
    } catch (e) {
      record(cv(ticksCounter), null, #blocks, #call_failed(Error.message(e)), "uncaught in tickBody");
    };
    tickInFlight := false;
  };

  func tickBody() : async () {
    ticksCounter.add(1);
    let myTick = cv(ticksCounter);
    lastTickAtCounter.set(Int.abs(Time.now()));

    let api = providerForTick(myTick);

    // 0. Cheap tip-hash precheck. /api/blocks/tip/hash returns a
    // 64-char hex line (~65 B), costing ~50.8M cycles at n=13 vs
    // ~135M for the full /blocks. If the provider's tip hasn't
    // moved since the last successful tick, skip the rest entirely.
    let tipUrl = api # "/blocks/tip/hash";
    let tipBody = switch (await httpGet(myTick, null, #blocks, tipUrl, TIP_HASH_MAX_BYTES)) {
      case (?t) t;
      case null return; // already logged
    };
    if (Text.size(tipBody) != 64) {
      record(myTick, null, #blocks, #unexpected_payload(tipBody), tipUrl);
      return;
    };
    let providerTipHash = switch (first64Hex(tipBody)) {
      case (?h) h;
      case null {
        record(myTick, null, #blocks, #unexpected_payload(tipBody), tipUrl);
        return;
      };
    };
    if (providerTipHash == lastSeenTipHash) {
      lastSuccessAtCounter.set(Int.abs(Time.now()));
      record(myTick, null, #blocks, #ok, "tip_unchanged " # providerTipHash);
      return;
    };

    // 1-2. Discovery via /blocks batches.
    //
    // Per batch: fetch up to 10 BlockFields from the provider, then
    // ask block_explorer in one have_hashes call which of those
    // hashes we already store. The highest known is the last common
    // ancestor; everything above is queued for the forward push.
    // We keep the full BlockFields (not just height+hash) so the
    // forward push can reconstruct each raw 80-byte header locally
    // — no /block/<hash>/header outcall needed.
    let collected = List.empty<BlockFields>();
    var theirTip : Nat = 0;
    var theirTipHash : Text = "";
    var commonH : ?Nat = null;
    var batchNum : Nat = 0;
    var nextStart : ?Nat = null;

    label discover loop {
      let url = switch nextStart {
        case null api # "/blocks";
        case (?h) api # "/blocks/" # Nat.toText(h);
      };

      let body = switch (await httpGet(myTick, null, #blocks, url, BLOCKS_MAX_BYTES)) {
        case (?t) t;
        case null return; // already logged
      };

      let blocks = switch (parseBlocks(body)) {
        case (?b) b;
        case null {
          record(myTick, null, #blocks, #unexpected_payload("parse failed"), url);
          return;
        };
      };
      if (blocks.size() == 0) {
        record(myTick, null, #blocks, #unexpected_payload("empty array"), url);
        return;
      };

      if (batchNum == 0) {
        theirTip := blocks[0].height;
        theirTipHash := blocks[0].id;
        lastProviderTipCounter.set(theirTip);
      };

      // One have_hashes call per batch — already accepts an
      // arbitrary-length array, so the full 10 go in one shot.
      let hashesArr = Array.tabulate<Text>(blocks.size(), func(i) = blocks[i].id);
      let have = try {
        await blockExplorer.have_hashes(hashesArr);
      } catch (e) {
        record(myTick, null, #blocks, #call_failed(Error.message(e)), "have_hashes");
        return;
      };
      if (have.size() != blocks.size()) {
        record(myTick, null, #blocks, #unexpected_payload("have_hashes size mismatch"), "");
        return;
      };

      // Highest known hash in the batch (descending order, so first
      // `true` is highest).
      var foundAt : ?Nat = null;
      var k : Nat = 0;
      while (k < have.size() and foundAt == null) {
        if (have[k]) foundAt := ?k;
        k += 1;
      };

      switch foundAt {
        case (?ci) {
          // Common ancestor at blocks[ci]. Everything above it
          // (indices 0..ci-1) is new to us and queued for push.
          let common = blocks[ci].height;
          commonH := ?common;
          var j : Nat = 0;
          while (j < ci) {
            List.add(collected, blocks[j]);
            j += 1;
          };
          record(
            myTick,
            ?common,
            #blocks,
            #ok,
            "common=" # Nat.toText(common) #
            " new=" # Nat.toText(ci) #
            " their_tip=" # Nat.toText(theirTip),
          );
          break discover;
        };
        case null {
          // None known; collect all and page back.
          for (b in blocks.vals()) List.add(collected, b);
          let lo = blocks[blocks.size() - 1 : Nat].height;
          record(
            myTick,
            ?lo,
            #blocks,
            #ok,
            "no_known batch=" # Nat.toText(batchNum + 1) #
            " low=" # Nat.toText(lo),
          );
          batchNum += 1;
          if (batchNum >= MAX_BATCHES) {
            record(
              myTick,
              ?lo,
              #blocks,
              #unexpected_payload(
                "no common ancestor within " #
                Nat.toText(MAX_BATCHES * BATCH_SIZE) # " blocks below tip"
              ),
              api,
            );
            return;
          };
          if (lo == 0) {
            record(
              myTick,
              ?lo,
              #blocks,
              #unexpected_payload("walked past genesis without common ancestor"),
              api,
            );
            return;
          };
          nextStart := ?(lo - 1 : Nat);
        };
      };
    };

    let common = switch commonH {
      case (?c) c;
      case null return; // unreachable: discover only exits via break-with-common or return
    };

    // Nothing new to push: either we're already on the provider's tip
    // hash, or the provider is at or behind us.
    if (List.size(collected) == 0) {
      lastSuccessAtCounter.set(Int.abs(Time.now()));
      lastSeenTipHash := theirTipHash;
      record(
        myTick,
        ?common,
        #push,
        #ok,
        "in_sync common=" # Nat.toText(common) #
        " their_tip=" # Nat.toText(theirTip),
      );
      return;
    };

    // 4. Walk forwards using the BlockFields we already have. The
    // raw 80-byte header is reconstructed locally from the fields
    // returned by /blocks — no /block/<hash>/header outcall needed.
    // `collected` is descending overall (entries appended in fetch
    // order); the smallest height sits at the end, so iterate in
    // reverse to push in chain order. Stop at `forwardEnd` and
    // leave the rest for the next tick.
    let forwardEnd : Nat = if ((theirTip - common : Nat) > MAX_FORWARD) common + MAX_FORWARD else theirTip;
    let collectedArr = List.toArray(collected);

    // Assemble the ascending rawHex array up to `forwardEnd`. We
    // iterate `collected` in reverse (it's descending) so the
    // resulting array is in chain order — required for the
    // anchor-to-parent push on the explorer side.
    let rawHeaders = List.empty<Blob>();
    let pushHeights = List.empty<Nat>();
    var ii : Nat = collectedArr.size();
    label fwd loop {
      if (ii == 0) break fwd;
      ii -= 1;
      let bf = collectedArr[ii];
      let h = bf.height;
      if (h > forwardEnd) break fwd;
      // h > common holds by construction of `collected`.

      let rawHex = switch (rawHeaderHex(bf)) {
        case (?x) x;
        case null {
          record(
            myTick,
            ?h,
            #header,
            #unexpected_payload("cannot reconstruct header (missing prev?)"),
            bf.id,
          );
          return;
        };
      };
      List.add(rawHeaders, BEHeader.hexToBlob(rawHex));
      List.add(pushHeights, h);
    };

    let toPush = List.toArray(rawHeaders);
    if (toPush.size() == 0) {
      // Nothing within the forward window. Shouldn't normally happen
      // since the `List.size(collected) == 0` short-circuit above
      // already handled it; treat as a no-op.
      return;
    };

    let heights = List.toArray(pushHeights);
    let lo = heights[0];
    let hi = heights[heights.size() - 1 : Nat];

    // One inter-canister call, regardless of batch size (capped by
    // block_explorer's MAX_PUSH_BATCH = 10 000, well above MAX_FORWARD).
    let pushRes = try {
      await blockExplorer.push_headers(toPush);
    } catch (e) {
      record(myTick, ?lo, #push, #call_failed(Error.message(e)), "push_headers");
      return;
    };
    switch pushRes {
      case (#ok r) {
        let accepted = r.accepted;
        if (accepted > 0) {
          let highestAccepted = heights[accepted - 1 : Nat];
          lastFetchedHeightCounter.set(highestAccepted);
          lastSuccessAtCounter.set(Int.abs(Time.now()));
        };
        let detail = "accepted=" # Nat.toText(accepted) # "/" # Nat.toText(toPush.size()) #
        " range=[" # Nat.toText(lo) # ".." # Nat.toText(hi) # "]";
        switch (r.last_error) {
          case (?err) {
            record(myTick, ?lo, #push, #rejected(err), detail);
          };
          case null {
            // Only cache the provider's tip hash when we fully
            // caught up to it. If the forward window was bounded by
            // MAX_FORWARD (still more to push next tick), leaving
            // the cache stale lets the next tick reprocess.
            if (hi == theirTip) lastSeenTipHash := theirTipHash;
            record(myTick, ?hi, #push, #ok, detail);
          };
        };
      };
      case (#err msg) {
        record(myTick, ?lo, #push, #rejected(msg), "");
      };
    };
  };

  //ignore Timer.recurringTimer<system>(#seconds 30, tick);

  public shared func tick_now() : async () { await tick() };

  var timerId : ?Nat = null;
  // Tick interval in seconds; 0 means the recurring timer is stopped. This
  // is a non-transient var in a persistent actor, so it is already a stable
  // variable — saved across upgrades automatically (no preupgrade needed);
  // postupgrade re-arms the timer from it.
  var timerSeconds : Nat = 0;
  renderer.addValue(PT.newValue("timer_seconds", [], func() = timerSeconds));

  public func startTimer(i : Nat) : async () {
    switch (timerId) { case (?t) Timer.cancelTimer(t); case null {} };
    timerId := ?Timer.recurringTimer<system>(#seconds i, tick);
    timerSeconds := i;
  };
  public func stopTimer() : async () {
    let ?t = timerId else return;
    Timer.cancelTimer(t);
    timerId := null;
    timerSeconds := 0;
  };

  // Recurring timers don't survive upgrades, so re-arm from the persisted
  // interval. Keeps both the schedule and `timer_seconds` accurate.
  system func postupgrade() {
    if (timerSeconds > 0) {
      timerId := ?Timer.recurringTimer<system>(#seconds timerSeconds, tick);
    };
  };

};
