// Bitcoin block-header importer with full reorg support.
//
// Two ways to add headers:
//   - import_next(n)        : pull next N from the official Bitcoin canister
//                             (ghsi2-tqaaa-aaaan-aaaca-cai)
//   - push_header(rawHex)   : push a single 80-byte raw header (hex-encoded)
//
// Every accepted header is stored forever, indexed by hash. Forks are
// tracked; the canonical chain is whichever fork has the most cumulative
// proof-of-work.
//
// The full chain state is a single stable record (`Chain.Chain`) — no
// snapshot, share/unshare, or pre/post-upgrade hooks are needed.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Cycles "mo:core/Cycles";
import Int "mo:core/Int";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Time "mo:core/Time";

import PT "mo:promtracker";

import Header "Header";
import HeaderValue "HeaderValue";
import Chain "Chain";
import Esplora "Esplora";

persistent actor BlockExplorer {

  // ---------------------------------------------------------------------
  // Prometheus metrics — exposed via the Esplora HTTP handler at
  // `/metrics`. We only use PullValues here: every metric is derived
  // from data structures the canister already maintains for its own
  // operation, so there's a single source of truth per metric.
  //
  // System metrics (cycles_balance, rts_memory_size, rts_heap_size,
  // canister_version, …) come from `PT.allSystemMetrics`. Chain-
  // specific values are registered below once `chain` exists.
  // ---------------------------------------------------------------------
  transient let renderer = PT.Renderer();
  renderer.addCanisterLabel(BlockExplorer);
  renderer.addValue(PT.allSystemMetrics);

  // ---------------------------------------------------------------------
  // Bitcoin canister interface (ghsi2-tqaaa-aaaan-aaaca-cai).
  // ---------------------------------------------------------------------

  type Network = { #mainnet; #testnet };

  type GetBlockHeadersRequest = {
    start_height : Nat32;
    end_height : ?Nat32;
    network : Network;
  };

  type GetBlockHeadersResponse = {
    tip_height : Nat32;
    block_headers : [Blob];
  };

  type BitcoinCanister = actor {
    bitcoin_get_block_headers : (GetBlockHeadersRequest) -> async GetBlockHeadersResponse;
  };

  transient let bitcoin_canister : BitcoinCanister = actor ("ghsi2-tqaaa-aaaan-aaaca-cai");

  var cyclesPerCall : Nat = 10_000_000_000;
  let MAX_BATCH : Nat = 100;

  // ---------------------------------------------------------------------
  // Chain state.
  //
  // The Chain class wraps a stable mo:stable-trie HeaderDb plus a
  // stable canonical-chain Region plus EOP-stable heap Maps. The class
  // instance itself is transient (heap-bound trie bookkeeping); we
  // share/unshare it across upgrades through `chainData`.
  // ---------------------------------------------------------------------

  var chainData : ?Chain.StableData = null;
  transient let chain : Chain.Chain = Chain.Chain();

  func nowSecs() : Int { Time.now() / 1_000_000_000 };
  func nowSecsNat32() : Nat32 {
    let s = nowSecs();
    if (s <= 0) 0 else Nat32.fromNat(Int.abs(s) % 0x1_0000_0000);
  };

  switch (chainData) {
    case (?d) chain.unshare(d);
    case null chain.initGenesis(nowSecsNat32(), Principal.fromActor(BlockExplorer));
  };

  system func preupgrade() {
    chainData := ?chain.share();
  };

  // Chain-level pull values, registered now that `chain` exists.
  // All read from `chain` directly so the metric output is always
  // consistent with what the canister currently sees.
  renderer.addValue(PT.newValue("headers_total", [], func() = chain.size()));
  renderer.addValue(PT.newValue("tip_height", [], func() = chain.tipHeight()));
  renderer.addValue(PT.newValue("fork_count", [], func() = chain.forks().size()));
  renderer.addValue(PT.newValue("uploader_count", [], func() = chain.uploaderStats().size()));
  renderer.addValue(PT.newValue("header_db_byte_size", [], func() = chain.memoryStats().byte_size));
  renderer.addValue(PT.newValue("header_db_leaf_count", [], func() = chain.memoryStats().leaf_count));
  renderer.addValue(PT.newValue("header_db_node_count", [], func() = chain.memoryStats().node_count));

  // ---------------------------------------------------------------------
  // Candid-facing types & projections.
  // ---------------------------------------------------------------------

  public type BlockInfo = {
    height : Nat;
    dbidx : Nat; // explorer's internal id; pass to block_bodies
    version : Nat32;
    prev_hash_be_hex : Text;
    merkle_root_be_hex : Text;
    time : Nat32;
    bits : Nat32;
    nonce : Nat32;
    hash_be_hex : Text;
    difficulty_x1e8 : Nat;
    cum_work : Nat;
    is_canonical : Bool;
    first_seen : Nat32; // unix seconds when first stored
    uploader : Principal; // principal that pushed this header
  };

  func toBlockInfo(b : Chain.StoredBlock, isCanonical_ : Bool) : BlockInfo {
    let v = b.value;
    let bits = HeaderValue.bitsOf(v);
    let target = Header.nBitsToTarget(bits);
    let difficulty_x1e8 : Nat = if (target == 0) 0 else Header.POW_LIMIT_TARGET * 100_000_000 / target;
    let prevHashLE = chain.prevHashOf(b);
    let merkleLE = HeaderValue.merkleOf(v);
    {
      height = b.height;
      dbidx = b.dbidx;
      version = HeaderValue.versionOf(v);
      prev_hash_be_hex = Header.bytesToHex(Header.reverse32(prevHashLE));
      merkle_root_be_hex = Header.bytesToHex(Header.reverse32(merkleLE));
      time = HeaderValue.timeOf(v);
      bits;
      nonce = HeaderValue.nonceOf(v);
      hash_be_hex = Header.bytesToHex(Header.reverse32(b.hash));
      difficulty_x1e8;
      cum_work = b.cumWork;
      is_canonical = isCanonical_;
      first_seen = HeaderValue.firstSeenOf(v);
      uploader = chain.uploaderOf(b.dbidx);
    };
  };

  // ---------------------------------------------------------------------
  // Push API.
  // ---------------------------------------------------------------------

  public type BatchPushResult = {
    accepted : Nat; // number of headers successfully appended
    new_tip : BlockInfo;
    last_error : ?Text; // first failure encountered (stops the batch)
  };

  // Maximum headers per push_headers / push_headers_hex call.
  // 10_000 * 80 = 800_000 bytes of raw header data.
  let MAX_PUSH_BATCH : Nat = 10_000;

  public shared ({ caller }) func push_header(raw_hex : Text) : async Result.Result<Chain.PushOk, Text> {
    chain.push(Header.hexToBlob(raw_hex), nowSecs(), caller);
  };

  // Loop body of push_headers / push_headers_hex, also reused by
  // inspect_message as a true dry-run. Pushes headers in order,
  // halting at the first rejection. Any state mutations made from
  // inspect_message's invocation are discarded by the IC when
  // inspect returns, so calling this from there is safe.
  func pushHeadersImpl(headers : [Blob], caller : Principal) : BatchPushResult {
    let now = nowSecs();
    var accepted : Nat = 0;
    var lastErr : ?Text = null;
    label loopH for (h in headers.vals()) {
      switch (chain.push(h, now, caller)) {
        case (#ok _) accepted += 1;
        case (#err msg) { lastErr := ?msg; break loopH };
      };
    };
    {
      accepted;
      new_tip = toBlockInfo(chain.tipBlock(), true);
      last_error = lastErr;
    };
  };

  // Push a batch of raw 80-byte headers in order. Stops at the first
  // rejection and reports how many were accepted plus the error message.
  public shared ({ caller }) func push_headers(headers : [Blob]) : async Result.Result<BatchPushResult, Text> {
    if (headers.size() > MAX_PUSH_BATCH) return #err("batch too large: max " # debug_show MAX_PUSH_BATCH # " headers per call");
    #ok(pushHeadersImpl(headers, caller));
  };

  // Hex-encoded variant of push_headers — convenience for callers that
  // already have headers as text (e.g. browser fetches from a third-party
  // explorer API). Decodes upfront and reuses the same impl.
  public shared ({ caller }) func push_headers_hex(headers_hex : [Text]) : async Result.Result<BatchPushResult, Text> {
    if (headers_hex.size() > MAX_PUSH_BATCH) return #err("batch too large: max " # debug_show MAX_PUSH_BATCH # " headers per call");
    let headers = Array.tabulate<Blob>(
      headers_hex.size(),
      func(i) = Header.hexToBlob(headers_hex[i]),
    );
    #ok(pushHeadersImpl(headers, caller));
  };

  // ---------------------------------------------------------------------
  // Ingress inspection.
  //
  // inspect_message runs at the boundary node before an ingress call
  // is forwarded to the actor. Returning `false` rejects the call
  // outright. For the three push methods we run the same code as
  // the real handler as a dry-run: the IC discards any state
  // mutations made during inspect, so calling chain.push /
  // pushHeadersImpl here is safe and gives us an exact prediction
  // of whether the call would make progress.
  //
  //   push_header        — accept iff chain.push returns #ok.
  //   push_headers       — accept iff at least one header would be
  //                        newly added (`accepted > 0`). Rejects
  //                        empty / oversize / all-known / error-
  //                        before-first-add uniformly.
  //   push_headers_hex   — same, after decoding the hex inputs.
  //
  // All other methods pass through unchanged.
  // ---------------------------------------------------------------------
  system func inspect({
    caller : Principal;
    arg : Blob;
    msg : {
      #blocks_by_uploader : () -> (p : Principal, offset : Nat, limit : Nat);
      #cycles_balance : () -> ();
      #get_by_hash : () -> (hash_be_hex : Text);
      #get_cycles_per_call : () -> ();
      #get_view : () -> (height : ?Nat);
      #have_hashes : () -> (hashes_be_hex : [Text]);
      #header_db_memory_stats : () -> ();
      #http_request : () -> (req : Esplora.Request);
      #import_next : () -> (max_batch : Nat);
      #lookup_header : () -> (hash_internal : Blob);
      #push_header : () -> (raw_hex : Text);
      #push_headers : () -> (headers : [Blob]);
      #push_headers_hex : () -> (headers_hex : [Text]);
      #set_cycles_per_call : () -> (n : Nat);
      #uploader_leaderboard : () -> (top : Nat)
    };
  }) : Bool {
    ignore arg;
    switch (msg) {
      case (#push_header fetch) {
        let raw_hex = fetch();
        switch (chain.push(Header.hexToBlob(raw_hex), nowSecs(), caller)) {
          case (#ok _) true;
          case (#err _) false;
        };
      };
      case (#push_headers fetch) {
        let headers = fetch();
        if (headers.size() > MAX_PUSH_BATCH) return false;
        pushHeadersImpl(headers, caller).accepted > 0;
      };
      case (#push_headers_hex fetch) {
        let headers_hex = fetch();
        if (headers_hex.size() > MAX_PUSH_BATCH) return false;
        let headers = Array.tabulate<Blob>(
          headers_hex.size(),
          func(i) = Header.hexToBlob(headers_hex[i]),
        );
        pushHeadersImpl(headers, caller).accepted > 0;
      };
      case (_) true;
    };
  };

  // ---------------------------------------------------------------------
  // Pull API.
  // ---------------------------------------------------------------------

  // Headers fetched from the Bitcoin canister are attributed to the
  // anonymous principal rather than to the caller of `import_next`,
  // since the caller is only triggering the relay — the content
  // originates from the IC's Bitcoin integration, not from a user.
  transient let ANONYMOUS_PRINCIPAL : Principal = Principal.fromText("2vxsx-fae");

  // Only this principal may invoke `import_next`. The function spends
  // canister cycles on every call, so it's restricted to a single
  // operator identity.
  transient let IMPORT_OPERATOR : Principal = Principal.fromText(
    "5yxw4-okdhg-twoqv-qjshi-uammo-kn5yg-guwus-r3u4m-codgm-3lle6-oae"
  );

  public shared ({ caller }) func import_next(max_batch : Nat) : async Result.Result<Nat, Text> {
    if (caller != IMPORT_OPERATOR) {
      return #err("unauthorized: import_next is restricted");
    };
    let nextHeight = chain.tipHeight() + 1;
    let batch = if (max_batch == 0) 1 else if (max_batch > MAX_BATCH) MAX_BATCH else max_batch;

    let req : GetBlockHeadersRequest = {
      start_height = Nat32.fromNat(nextHeight);
      end_height = ?Nat32.fromNat(nextHeight + batch - 1 : Nat);
      network = #mainnet;
    };

    let resp = try {
      await (with cycles = cyclesPerCall)
      bitcoin_canister.bitcoin_get_block_headers(req);
    } catch (_) {
      return #err("call to bitcoin canister failed");
    };

    var imported : Nat = 0;
    label loopH for (h in resp.block_headers.vals()) {
      switch (chain.push(h, nowSecs(), ANONYMOUS_PRINCIPAL)) {
        case (#ok _) imported += 1;
        case (#err msg) {
          if (imported == 0) return #err(msg);
          break loopH;
        };
      };
    };
    #ok(imported);
  };

  // ---------------------------------------------------------------------
  // Queries.
  // ---------------------------------------------------------------------

  // Combined "page view" query: returns the tip, the requested block (if
  // any), all siblings at that height, total blocks stored and the current
  // fork list — everything the frontend needs for one screen, in a single
  // round trip.
  public type ChainView = {
    tip : BlockInfo;
    total_blocks : Nat;
    forks : [Chain.Fork];
    block : ?BlockInfo; // canonical block at the requested height
    siblings : [BlockInfo]; // all blocks at that height (incl. canonical)
  };

  public query func get_view(height : ?Nat) : async ChainView {
    let tipBlock = chain.tipBlock();
    let h : Nat = switch height {
      case (?x) x;
      case null tipBlock.height;
    };
    let block_ : ?BlockInfo = switch (chain.canonicalAt(h)) {
      case (?b) ?toBlockInfo(b, true);
      case null null;
    };
    let siblings_ : [BlockInfo] = Array.map<Chain.StoredBlock, BlockInfo>(
      chain.allAt(h),
      func(b) = toBlockInfo(b, chain.isOnCanonical(b)),
    );
    {
      tip = toBlockInfo(tipBlock, true);
      total_blocks = chain.size();
      forks = chain.forks();
      block = block_;
      siblings = siblings_;
    };
  };

  // Single-block lookup by hash (for the search box).
  public query func get_by_hash(hash_be_hex : Text) : async ?BlockInfo {
    switch (chain.byHashBE(hash_be_hex)) {
      case (?b) ?toBlockInfo(b, chain.isOnCanonical(b));
      case null null;
    };
  };

  // Compact lookup used by the `block_bodies` canister to verify that a
  // header is known and obtain the canonical merkle root for body
  // verification. Hash is in internal LE order (raw 32 bytes).
  public type HeaderRef = {
    dbidx : Nat;
    merkle_root : Blob; // internal LE order, 32 bytes
  };

  public query func lookup_header(hash_internal : Blob) : async ?HeaderRef {
    switch (chain.byHashInternal(hash_internal)) {
      case null null;
      case (?b) ?{
        dbidx = b.dbidx;
        merkle_root = HeaderValue.merkleOf(b.value);
      };
    };
  };

  // Batched membership check. Used by client-side pre-filters to avoid
  // shipping headers whose hash is already stored or whose parent is
  // unknown. Returns one Bool per input, in the same order.
  let MAX_HAVE_HASHES : Nat = 50_000;
  public query func have_hashes(hashes_be_hex : [Text]) : async [Bool] {
    if (hashes_be_hex.size() > MAX_HAVE_HASHES) {
      // Best-effort: trap rather than silently truncate.
      Runtime.trap("have_hashes: too many entries (max " # debug_show MAX_HAVE_HASHES # ")");
    };
    Array.tabulate<Bool>(
      hashes_be_hex.size(),
      func(i) = chain.hasHashBE(hashes_be_hex[i]),
    );
  };

  // Stable-trie memory stats (bytes used + node/leaf counts).
  public type StableTrieStats = {
    byte_size : Nat;
    leaf_count : Nat;
    node_count : Nat;
  };

  public query func header_db_memory_stats() : async StableTrieStats {
    chain.memoryStats();
  };

  // ---------------------------------------------------------------------
  // Uploader leaderboard.
  // ---------------------------------------------------------------------

  public type UploaderEntry = { uploader : Principal; count : Nat };

  // Top `top` uploaders by number of distinct headers stored,
  // descending. Ties broken by registration order (older first).
  // Pass 0 to get the full list.
  public query func uploader_leaderboard(top : Nat) : async [UploaderEntry] {
    let stats = chain.uploaderStats();
    let sorted = Array.sort<(Principal, Nat)>(
      stats,
      func(a, b) = Nat.compare(b.1, a.1),
    );
    let limit = if (top == 0 or top > sorted.size()) sorted.size() else top;
    Array.tabulate<UploaderEntry>(
      limit,
      func(i) = { uploader = sorted[i].0; count = sorted[i].1 },
    );
  };

  // Page through the headers uploaded by `p`, newest-first. `offset`
  // is 0 for the most recent. `limit` is capped at 1000 to keep
  // response sizes bounded. Returns [] for the anonymous principal
  // (we don't track its individual blocks; see Chain.uploaders).
  public query func blocks_by_uploader(p : Principal, offset : Nat, limit : Nat) : async [BlockInfo] {
    let cap : Nat = if (limit > 1000) 1000 else limit;
    let dbidxs = chain.blocksByUploader(p, offset, cap);
    Array.tabulate<BlockInfo>(
      dbidxs.size(),
      func(i) {
        switch (chain.byDbidx(dbidxs[i])) {
          case (?b) toBlockInfo(b, chain.isOnCanonical(b));
          case null Runtime.trap(
            "blocks_by_uploader: dbidx " # debug_show dbidxs[i] # " missing"
          );
        };
      },
    );
  };

  // ---------------------------------------------------------------------
  // Cycles.
  // ---------------------------------------------------------------------

  public query func cycles_balance() : async Nat { Cycles.balance() };

  public query func get_cycles_per_call() : async Nat { cyclesPerCall };

  public shared ({ caller }) func set_cycles_per_call(n : Nat) : async () {
    if (not Principal.isController(caller)) {
      Runtime.trap("unauthorized: set_cycles_per_call is controller-only");
    };
    cyclesPerCall := n;
  };

  // ---------------------------------------------------------------------
  // HTTP gateway: serves /metrics (Prometheus exposition) and a subset
  // of the Esplora REST API under /api/... See src/Esplora.mo for the
  // route list. We define `http_request` ourselves (rather than using
  // the PromHttp mixin) so the same handler can dispatch all routes.
  // ---------------------------------------------------------------------

  public query func http_request(req : Esplora.Request) : async Esplora.Response {
    Esplora.handle(chain, renderer.renderExposition, req);
  };
};
