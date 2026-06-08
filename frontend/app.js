// Vanilla-JS Internet Computer client for the BlockExplorer canister.
// Uses @dfinity/agent loaded from esm.sh — no build step required.
//
// All page state for one screen is fetched in a single combined query:
//   actor.get_view([height])  ->  { tip, total_blocks, forks, block, siblings }
//
// That keeps round trips to the minimum: one query per navigation, one
// query after a successful import, plus the targeted hash lookup for the
// search box.

import { Actor, HttpAgent } from "https://esm.sh/@dfinity/agent@2.4.1";
import { Principal } from "https://esm.sh/@dfinity/principal@2.4.1";

// ---------------------------------------------------------------------------
// Read canister IDs / root key from the `ic_env` cookie set by the asset
// canister (Wasm >= 0.30.2). Format is a URL-encoded query string:
//   PUBLIC_CANISTER_ID:block_explorer=<id>&ic_root_key=<hex>&...
// ---------------------------------------------------------------------------

function readIcEnv() {
  const m = document.cookie.match(/(?:^|;\s*)ic_env=([^;]+)/);
  if (!m) return {};
  const out = {};
  for (const part of decodeURIComponent(m[1]).split("&")) {
    const eq = part.indexOf("=");
    if (eq > 0) out[part.slice(0, eq)] = part.slice(eq + 1);
  }
  return out;
}

function deriveHost() {
  const { protocol, hostname, port } = window.location;
  if (hostname.endsWith("localhost")) {
    return `${protocol}//localhost${port ? ":" + port : ""}`;
  }
  // On the IC-served subdomains (`<id>.icp0.io`, `<id>.ic0.app`), strip
  // the canister-id label to get the API host (`icp0.io`, `ic0.app`).
  // On any other hostname — including custom domains like
  // `bitcoin.ic0.info` — there's no canister-id label to strip, so
  // hard-code the IC mainnet HTTP gateway.
  if (hostname.endsWith(".icp0.io") || hostname.endsWith(".ic0.app")) {
    const dot = hostname.indexOf(".");
    const base = hostname.slice(dot + 1);
    return `${protocol}//${base}${port ? ":" + port : ""}`;
  }
  return "https://icp0.io";
}

// ---------------------------------------------------------------------------
// Candid IDL for the BlockExplorer canister.
// ---------------------------------------------------------------------------

const idlFactory = ({ IDL }) => {
  const BlockInfo = IDL.Record({
    height: IDL.Nat,
    version: IDL.Nat32,
    prev_hash_be_hex: IDL.Text,
    merkle_root_be_hex: IDL.Text,
    time: IDL.Nat32,
    bits: IDL.Nat32,
    nonce: IDL.Nat32,
    hash_be_hex: IDL.Text,
    difficulty_x1e8: IDL.Nat,
    cum_work: IDL.Nat,
    is_canonical: IDL.Bool,
    first_seen: IDL.Nat32,
    uploader: IDL.Principal,
  });
  const Fork = IDL.Record({
    tip_height: IDL.Nat,
    tip_hash_be_hex: IDL.Text,
    length: IDL.Nat,
    branch_height: IDL.Nat,
    branch_hash_be_hex: IDL.Text,
  });
  const ChainView = IDL.Record({
    tip: BlockInfo,
    total_blocks: IDL.Nat,
    forks: IDL.Vec(Fork),
    block: IDL.Opt(BlockInfo),
    siblings: IDL.Vec(BlockInfo),
  });
  const PushOk = IDL.Record({
    height: IDL.Nat,
    hash_be_hex: IDL.Text,
    is_canonical: IDL.Bool,
    reorg_depth: IDL.Nat,
  });
  const UploaderEntry = IDL.Record({
    uploader: IDL.Principal,
    count: IDL.Nat,
  });
  const ImportResult = IDL.Variant({ ok: IDL.Nat, err: IDL.Text });
  const PushResult = IDL.Variant({ ok: PushOk, err: IDL.Text });
  const TxOccurrence = IDL.Record({
    block_hash_be_hex: IDL.Text,
    height: IDL.Nat,
    is_canonical: IDL.Bool,
    block_time: IDL.Nat32,
    position: IDL.Nat,
  });
  const TxView = IDL.Record({
    txid_be_hex: IDL.Text,
    canonical_index: IDL.Opt(IDL.Nat),
    occurrences: IDL.Vec(TxOccurrence),
  });
  const TxidStatus = IDL.Record({
    total_txids: IDL.Nat,
    txid_height: IDL.Opt(IDL.Nat),
    txid_tip_time: IDL.Opt(IDL.Nat32),
  });
  return IDL.Service({
    txid_status: IDL.Func([], [TxidStatus], ["query"]),
    get_view: IDL.Func([IDL.Opt(IDL.Nat)], [ChainView], ["query"]),
    get_by_hash: IDL.Func([IDL.Text], [IDL.Opt(BlockInfo)], ["query"]),
    tx_count_of_hash: IDL.Func([IDL.Text], [IDL.Opt(IDL.Nat)], ["query"]),
    find_tx: IDL.Func([IDL.Text], [IDL.Opt(TxView)], ["query"]),
    txid_at_index: IDL.Func([IDL.Nat], [IDL.Opt(IDL.Text)], ["query"]),
    block_txids: IDL.Func(
      [IDL.Text, IDL.Nat, IDL.Nat],
      [IDL.Vec(IDL.Text)],
      ["query"],
    ),
    import_next: IDL.Func([IDL.Nat], [ImportResult], []),
    push_header: IDL.Func([IDL.Text], [PushResult], []),
    cycles_balance: IDL.Func([], [IDL.Nat], ["query"]),
    uploader_leaderboard: IDL.Func(
      [IDL.Nat],
      [IDL.Vec(UploaderEntry)],
      ["query"],
    ),
    blocks_by_uploader: IDL.Func(
      [IDL.Principal, IDL.Nat, IDL.Nat],
      [IDL.Vec(BlockInfo)],
      ["query"],
    ),
  });
};

// ---------------------------------------------------------------------------
// Bootstrap actor.
// ---------------------------------------------------------------------------

const env = readIcEnv();
const canisterId = env["PUBLIC_CANISTER_ID:block_explorer"];
if (!canisterId) {
  document.body.innerHTML =
    "<p style='color:#ff7b72;padding:2rem'>Could not find " +
    "<code>PUBLIC_CANISTER_ID:block_explorer</code> in the <code>ic_env</code> " +
    "cookie. Make sure the frontend is served from the asset canister and " +
    "that <code>icp deploy</code> has been run.</p>";
  throw new Error("missing canister id");
}

const host = deriveHost();
const isLocal = /localhost|127\.0\.0\.1/.test(host);

const agent = await HttpAgent.create({
  host,
  shouldFetchRootKey: isLocal,
});

const actor = Actor.createActor(idlFactory, { agent, canisterId });

// ---------------------------------------------------------------------------
// UI helpers.
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function fmtNat(n) {
  return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, "_");
}

function fmtTime(unixSecs) {
  const d = new Date(Number(unixSecs) * 1000);
  return d.toISOString().replace("T", " ").replace(".000Z", "");
}

function fmtDifficulty(x1e8) {
  const whole = x1e8 / 100000000n;
  const frac = x1e8 % 100000000n;
  const fracStr = frac.toString().padStart(8, "0").slice(0, 4);
  return `${fmtNat(whole)}.${fracStr}`;
}

// Abbreviated difficulty for the tip header bar: 3 significant
// figures plus an SI-style suffix (K/M/G/T/P/E). Full precision is
// still shown in the per-block details further down.
function fmtDifficultyShort(x1e8) {
  const whole = x1e8 / 100000000n;
  const n = Number(whole);
  if (!isFinite(n) || n < 1000) return `${n}`;
  const units = ["", "K", "M", "G", "T", "P", "E"];
  let u = 0;
  let v = n;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u += 1;
  }
  // 5 sig figs: 132.24, 13.224, 1.3224
  const digits = v >= 100 ? 2 : v >= 10 ? 3 : 4;
  return `${v.toFixed(digits)} ${units[u]}`;
}

function fmtBits(bits) {
  return "0x" + Number(bits).toString(16).padStart(8, "0");
}

function setStatus(el, text, kind) {
  el.textContent = text;
  el.className = "status" + (kind ? " " + kind : "");
}

// ---------------------------------------------------------------------------
// Copy-to-clipboard support. Buttons opt in via class="copy-btn" plus
// either data-copy-target="<id>" or data-copy-text="<literal>".
// Delegated at document level so dynamically inserted buttons work too.
// ---------------------------------------------------------------------------

function makeCopyBtn(text, title = "Copy") {
  const btn = document.createElement("button");
  btn.className = "copy-btn";
  btn.dataset.copyText = text;
  btn.title = title;
  btn.textContent = "\u2398";
  return btn;
}

async function copyToClipboard(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for non-secure contexts.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
    } finally {
      document.body.removeChild(ta);
    }
  }
  if (btn) {
    btn.classList.add("copied");
    const prev = btn.textContent;
    btn.textContent = "\u2713";
    setTimeout(() => {
      btn.classList.remove("copied");
      btn.textContent = prev;
    }, 900);
  }
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".copy-btn");
  if (!btn) return;
  e.stopPropagation();
  let text = btn.dataset.copyText;
  if (!text && btn.dataset.copyTarget) {
    const el = document.getElementById(btn.dataset.copyTarget);
    if (el) text = el.textContent.trim();
  }
  if (text) copyToClipboard(text, btn);
});

// ---------------------------------------------------------------------------
// Page state — kept entirely client-side; refreshed via get_view().
// ---------------------------------------------------------------------------

let currentHeight = 0n;
let tipHeight = 0n;

function renderTip(tip, totalBlocks) {
  tipHeight = tip.height;
  $("tip-height").textContent = fmtNat(tip.height);
  $("tip-hash").textContent = tip.hash_be_hex;
  $("tip-time").textContent = fmtTime(tip.time);
  $("tip-difficulty").textContent = fmtDifficultyShort(tip.difficulty_x1e8);
  $("tip-stored").textContent = fmtNat(totalBlocks);
}

// Refresh the indexed-transaction summary panels (independent of the
// current block; fired fire-and-forget alongside tip refreshes).
async function refreshTxidStatus() {
  let s;
  try {
    s = await actor.txid_status();
  } catch (e) {
    console.warn("txid_status failed:", e);
    return;
  }
  $("tip-txids").textContent = fmtNat(s.total_txids);
  $("tip-txid-height").textContent = s.txid_height.length
    ? fmtNat(s.txid_height[0])
    : "—";
  $("tip-txid-time").textContent = s.txid_tip_time.length
    ? fmtTime(s.txid_tip_time[0])
    : "—";
}

function renderBlock(bi) {
  $("bi-height").textContent = fmtNat(bi.height);
  $("bi-hash").textContent = bi.hash_be_hex;
  $("bi-prev").textContent = bi.prev_hash_be_hex;
  $("bi-merkle").textContent = bi.merkle_root_be_hex;
  $("bi-time").textContent = fmtTime(bi.time);
  $("bi-time-unix").textContent = fmtNat(bi.time);
  $("bi-version").textContent = "0x" + Number(bi.version).toString(16);
  $("bi-bits").textContent = fmtBits(bi.bits);
  $("bi-difficulty").textContent = fmtDifficulty(bi.difficulty_x1e8);
  $("bi-nonce").textContent =
    "0x" + Number(bi.nonce).toString(16).padStart(8, "0");
  $("bi-cum-work").textContent = fmtNat(bi.cum_work);
  $("bi-first-seen").textContent =
    Number(bi.first_seen) === 0 ? "—" : fmtTime(bi.first_seen);
  $("bi-uploader").textContent = bi.uploader.toText();
  const can = $("bi-canonical");
  can.textContent = bi.is_canonical ? "yes" : "no (orphan)";
  can.className = bi.is_canonical ? "ok" : "warn";

  // Placeholder; the actual value is wired up by attachTxCount() below,
  // which is fired in parallel with get_view by loadBlock.
  // Placeholder; the actual value is wired up by attachTxCount() below,
  // fired in parallel with get_view by loadBlock. Bodies can be known for
  // canonical and fork blocks alike.
  const tcEl = $("bi-tx-count");
  tcEl.textContent = "…";
  tcEl.className = "muted";
}

// Wire up the tx_count cell from a (possibly already in-flight) promise.
// Stale responses are dropped via the currentHash guard.
function attachTxCount(bi, promise) {
  const tcEl = $("bi-tx-count");
  if (!promise) return;
  promise
    .then((opt) => {
      if (currentHash !== bi.hash_be_hex) return;
      if (opt.length === 0) {
        tcEl.textContent = "unknown";
        tcEl.className = "muted";
      } else {
        tcEl.textContent = fmtNat(opt[0]);
        tcEl.className = "";
      }
    })
    .catch((e) => {
      if (currentHash !== bi.hash_be_hex) return;
      tcEl.textContent = "—";
      tcEl.className = "muted";
      console.warn("tx_count_of failed:", e);
    });
}

function renderSiblings(siblings, currentHash) {
  const tbody = $("siblings-body");
  tbody.innerHTML = "";
  if (siblings.length <= 1) {
    $("siblings-card").style.display = "none";
    return;
  }
  $("siblings-card").style.display = "";
  for (const s of siblings) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    if (s.hash_be_hex === currentHash) tr.className += " selected";
    const tdMark = document.createElement("td");
    tdMark.textContent = s.is_canonical ? "★" : "";
    const tdHash = document.createElement("td");
    tdHash.className = "hash";
    tdHash.textContent = s.hash_be_hex;
    const tdTime = document.createElement("td");
    tdTime.textContent = fmtTime(s.time);
    tr.appendChild(tdMark);
    tr.appendChild(tdHash);
    tr.appendChild(tdTime);
    tr.addEventListener("click", () => loadBlock({ hash: s.hash_be_hex }));
    tbody.appendChild(tr);
  }
}

// Cached full forks list; the table is re-rendered on filter/sort changes
// without re-querying the canister.
let allForks = [];
let forksPage = 0;

function cmpBig(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function renderForks(forks) {
  if (forks !== undefined) {
    allForks = forks;
    forksPage = 0;
  }
  $("forks-count").textContent = fmtNat(BigInt(allForks.length));
  const tbody = $("forks-body");
  tbody.innerHTML = "";
  const pager = $("forks-pager");
  if (allForks.length === 0) {
    $("forks-empty").style.display = "";
    $("forks-shown").textContent = "";
    pager.style.display = "none";
    return;
  }
  $("forks-empty").style.display = "none";

  const filter = $("forks-filter").value.trim().toLowerCase();
  let rows = filter
    ? allForks.filter((f) => f.tip_hash_be_hex.includes(filter))
    : allForks.slice();

  const sort = $("forks-sort").value;
  rows.sort((a, b) => {
    switch (sort) {
      case "length-desc":
        return cmpBig(b.length, a.length);
      case "tipheight-desc":
        return cmpBig(b.tip_height, a.tip_height);
      case "branchheight-desc":
        return cmpBig(b.branch_height, a.branch_height);
      case "branchheight-asc":
        return cmpBig(a.branch_height, b.branch_height);
    }
    return 0;
  });

  const pageSize = parseInt($("forks-page-size").value, 10) || 25;
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  if (forksPage >= totalPages) forksPage = totalPages - 1;
  if (forksPage < 0) forksPage = 0;
  const start = forksPage * pageSize;
  const end = Math.min(start + pageSize, rows.length);
  const pageRows = rows.slice(start, end);

  $("forks-shown").textContent =
    rows.length === allForks.length
      ? `${allForks.length} total`
      : `${rows.length} of ${allForks.length}`;

  pager.style.display = rows.length > pageSize ? "" : "none";
  $("forks-page-info").textContent =
    `${start + 1}\u2013${end} of ${rows.length}` +
    `  \u00b7  page ${forksPage + 1} / ${totalPages}`;
  $("forks-first").disabled = forksPage === 0;
  $("forks-prev").disabled = forksPage === 0;
  $("forks-next").disabled = forksPage >= totalPages - 1;
  $("forks-last").disabled = forksPage >= totalPages - 1;

  for (const f of pageRows) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    const tdH = document.createElement("td");
    tdH.textContent = fmtNat(f.tip_height);
    const tdLen = document.createElement("td");
    tdLen.textContent = fmtNat(f.length);
    const tdBranch = document.createElement("td");
    tdBranch.textContent = fmtNat(f.branch_height);
    const tdHash = document.createElement("td");
    tdHash.className = "hash";
    tdHash.textContent = f.tip_hash_be_hex;
    tr.appendChild(tdH);
    tr.appendChild(tdLen);
    tr.appendChild(tdBranch);
    tr.appendChild(tdHash);
    tr.addEventListener("click", () => loadBlock({ hash: f.tip_hash_be_hex }));
    tbody.appendChild(tr);
  }
}

$("forks-filter").addEventListener("input", () => {
  forksPage = 0;
  renderForks();
});
$("forks-sort").addEventListener("change", () => {
  forksPage = 0;
  renderForks();
});
$("forks-page-size").addEventListener("change", () => {
  forksPage = 0;
  renderForks();
});
$("forks-first").addEventListener("click", () => {
  forksPage = 0;
  renderForks();
});
$("forks-prev").addEventListener("click", () => {
  if (forksPage > 0) forksPage -= 1;
  renderForks();
});
$("forks-next").addEventListener("click", () => {
  forksPage += 1;
  renderForks();
});
$("forks-last").addEventListener("click", () => {
  forksPage = Number.MAX_SAFE_INTEGER;
  renderForks();
});

// ---------------------------------------------------------------------------
// Uploader leaderboard.
// ---------------------------------------------------------------------------

const LEADERBOARD_TOP = 10n;
const ANONYMOUS_PRINCIPAL = "2vxsx-fae";
const UPLOADER_PAGE_SIZE = 25n;

// principal text -> { offset: BigInt, expanded: bool }
const uploaderPanelState = new Map();

async function refreshLeaderboard() {
  let entries;
  try {
    entries = await actor.uploader_leaderboard(LEADERBOARD_TOP);
  } catch (e) {
    // Non-fatal: don't block page load if the canister is older.
    console.warn("uploader_leaderboard failed:", e);
    return;
  }
  const tbody = $("leaderboard-body");
  tbody.innerHTML = "";
  $("leaderboard-shown").textContent = entries.length.toString();
  if (entries.length === 0) {
    $("leaderboard-empty").style.display = "";
    return;
  }
  $("leaderboard-empty").style.display = "none";
  entries.forEach((e, i) => {
    const principalText = e.uploader.toText();
    const isAnon = principalText === ANONYMOUS_PRINCIPAL;

    const tr = document.createElement("tr");
    const tdRank = document.createElement("td");
    tdRank.textContent = (i + 1).toString();
    const tdPrincipal = document.createElement("td");
    tdPrincipal.className = "hash";
    if (isAnon) {
      tdPrincipal.textContent = principalText + "  (anonymous)";
      tdPrincipal.title = "Anonymous uploader \u2014 individual blocks not tracked";
    } else {
      const span = document.createElement("span");
      span.className = "linkish";
      span.textContent = principalText;
      span.addEventListener("click", () =>
        toggleUploaderPanel(principalText, panelTr),
      );
      tdPrincipal.appendChild(span);
    }
    tdPrincipal.appendChild(makeCopyBtn(principalText, "Copy principal"));
    const tdCount = document.createElement("td");
    tdCount.textContent = fmtNat(e.count);
    tr.appendChild(tdRank);
    tr.appendChild(tdPrincipal);
    tr.appendChild(tdCount);
    tbody.appendChild(tr);

    // Hidden expansion row beneath this leaderboard row.
    const panelTr = document.createElement("tr");
    panelTr.className = "uploader-panel-row";
    panelTr.style.display = "none";
    const panelTd = document.createElement("td");
    panelTd.colSpan = 3;
    panelTd.className = "uploader-panel";
    panelTr.appendChild(panelTd);
    tbody.appendChild(panelTr);

    // Restore prior expansion state across leaderboard refreshes.
    if (!isAnon && uploaderPanelState.get(principalText)?.expanded) {
      openUploaderPanel(principalText, panelTr);
    }
  });
}

async function toggleUploaderPanel(principalText, panelTr) {
  const state = uploaderPanelState.get(principalText) ?? {
    offset: 0n,
    expanded: false,
  };
  if (state.expanded) {
    panelTr.style.display = "none";
    state.expanded = false;
    uploaderPanelState.set(principalText, state);
    return;
  }
  await openUploaderPanel(principalText, panelTr);
}

async function openUploaderPanel(principalText, panelTr) {
  const state = uploaderPanelState.get(principalText) ?? {
    offset: 0n,
    expanded: false,
  };
  state.expanded = true;
  uploaderPanelState.set(principalText, state);
  panelTr.style.display = "";
  await loadUploaderPage(principalText, panelTr);
}

async function loadUploaderPage(principalText, panelTr) {
  const state = uploaderPanelState.get(principalText);
  const panelTd = panelTr.firstChild;
  panelTd.innerHTML = "";
  const status = document.createElement("div");
  status.className = "muted";
  status.textContent = "Loading\u2026";
  panelTd.appendChild(status);

  let blocks;
  try {
    blocks = await actor.blocks_by_uploader(
      Principal.fromText(principalText),
      state.offset,
      UPLOADER_PAGE_SIZE,
    );
  } catch (e) {
    status.textContent = `Failed: ${e.message || e}`;
    return;
  }
  panelTd.innerHTML = "";

  if (blocks.length === 0 && state.offset === 0n) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No blocks recorded for this uploader.";
    panelTd.appendChild(p);
    return;
  }

  const table = document.createElement("table");
  table.className = "block-table";
  const thead = document.createElement("thead");
  thead.innerHTML =
    "<tr><th>Height</th><th>Hash</th><th>Time (UTC)</th><th>Canonical</th></tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const b of blocks) {
    const tr = document.createElement("tr");
    const tdH = document.createElement("td");
    tdH.textContent = fmtNat(b.height);
    const tdHash = document.createElement("td");
    tdHash.className = "hash linkish";
    tdHash.textContent = b.hash_be_hex;
    tdHash.addEventListener("click", () => loadBlock({ hash: b.hash_be_hex }));
    const tdTime = document.createElement("td");
    tdTime.textContent = fmtTime(b.time);
    const tdCanon = document.createElement("td");
    tdCanon.textContent = b.is_canonical ? "yes" : "no";
    tdCanon.className = b.is_canonical ? "ok" : "warn";
    tr.appendChild(tdH);
    tr.appendChild(tdHash);
    tr.appendChild(tdTime);
    tr.appendChild(tdCanon);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  panelTd.appendChild(table);

  // Pager: prev / next, page-relative (we don't know total).
  const pager = document.createElement("div");
  pager.className = "uploader-pager";
  const info = document.createElement("span");
  const start = state.offset + 1n;
  const end = state.offset + BigInt(blocks.length);
  info.className = "muted";
  info.textContent = `${fmtNat(start)}\u2013${fmtNat(end)} (newest first)`;
  const btnPrev = document.createElement("button");
  btnPrev.textContent = "\u2190 Newer";
  btnPrev.disabled = state.offset === 0n;
  btnPrev.addEventListener("click", () => {
    state.offset =
      state.offset > UPLOADER_PAGE_SIZE
        ? state.offset - UPLOADER_PAGE_SIZE
        : 0n;
    loadUploaderPage(principalText, panelTr);
  });
  const btnNext = document.createElement("button");
  btnNext.textContent = "Older \u2192";
  btnNext.disabled = BigInt(blocks.length) < UPLOADER_PAGE_SIZE;
  btnNext.addEventListener("click", () => {
    state.offset += UPLOADER_PAGE_SIZE;
    loadUploaderPage(principalText, panelTr);
  });
  pager.appendChild(btnPrev);
  pager.appendChild(btnNext);
  pager.appendChild(info);
  panelTd.appendChild(pager);
}

// ---------------------------------------------------------------------------
// Unified block loader. opts is either { height } (canonical lookup) or
// { hash } (any block, canonical or not), or {} for the chain tip.
// ---------------------------------------------------------------------------

let currentHash = "";

async function loadBlock(opts) {
  setStatus($("browse-status"), "Loading…");
  let block = null;
  let height = opts.height ?? null;
  let txCountPromise = null;
  if (opts.hash) {
    const opt = await actor.get_by_hash(opts.hash);
    if (opt.length === 0) {
      setStatus($("browse-status"), "Block not found.", "error");
      return;
    }
    block = opt[0];
    height = block.height;
    // Fire tx_count in parallel with the get_view call below.
    txCountPromise = actor.tx_count_of_hash(block.hash_be_hex);
  }
  const view = await actor.get_view(height === null ? [] : [height]);

  renderTip(view.tip, view.total_blocks);
  renderForks(view.forks);

  if (!block) {
    if (view.block.length === 0) {
      setStatus(
        $("browse-status"),
        height === null ? "Chain empty" : `No block at height ${height}`,
        "error",
      );
      return;
    }
    block = view.block[0];
    txCountPromise = actor.tx_count_of_hash(block.hash_be_hex);
  }

  currentHeight = block.height;
  currentHash = block.hash_be_hex;
  renderBlock(block);
  attachTxCount(block, txCountPromise);
  renderSiblings(view.siblings, currentHash);
  $("tx-view-card").style.display = "none"; // showing a block, not a tx
  renderTxList(block.hash_be_hex);
  writeUrlHash(block);
  setStatus($("browse-status"), "");
  // Fire-and-forget: leaderboard + txid status are independent of the block.
  refreshLeaderboard();
  refreshTxidStatus();
}

// ---------------------------------------------------------------------------
// URL hash <-> view sync. `#h=N` for canonical-by-height,
// `#hash=<64hex>` for any block.
// ---------------------------------------------------------------------------

let suppressHashChange = false;

function writeUrlHash(bi) {
  const want = bi.is_canonical ? `#h=${bi.height}` : `#hash=${bi.hash_be_hex}`;
  if (location.hash !== want) {
    suppressHashChange = true;
    history.replaceState(null, "", want);
  }
}

// ---------------------------------------------------------------------------
// Transactions: per-block tx list + transaction view.
// ---------------------------------------------------------------------------

const TX_PAGE = 100;
let txListHash = null;
let txListOffset = 0;
let txListTotal = 0;

// Show the current block's transaction list (paginated). Hidden if the
// block has no indexed body.
async function renderTxList(blockHashBeHex) {
  txListHash = blockHashBeHex;
  txListOffset = 0;
  $("tx-list-body").innerHTML = "";
  const wrap = $("tx-list-wrap");
  let count = null;
  try {
    const opt = await actor.tx_count_of_hash(blockHashBeHex);
    count = opt.length ? Number(opt[0]) : null;
  } catch {
    count = null;
  }
  if (txListHash !== blockHashBeHex) return; // navigated away while awaiting
  if (count === null || count === 0) {
    wrap.style.display = "none";
    return;
  }
  txListTotal = count;
  $("tx-list-count").textContent = fmtNat(BigInt(count));
  wrap.style.display = "";
  await loadMoreTxids();
}

async function loadMoreTxids() {
  if (txListHash === null) return;
  const want = txListHash;
  let txs;
  try {
    txs = await actor.block_txids(want, BigInt(txListOffset), BigInt(TX_PAGE));
  } catch (e) {
    console.warn("block_txids failed:", e);
    return;
  }
  if (txListHash !== want) return; // navigated away
  const body = $("tx-list-body");
  txs.forEach((txid, i) => {
    const tr = document.createElement("tr");
    const tdN = document.createElement("td");
    tdN.textContent = fmtNat(BigInt(txListOffset + i));
    const tdId = document.createElement("td");
    tdId.className = "hash linkish";
    tdId.textContent = txid;
    tdId.title = "View transaction";
    tdId.addEventListener("click", () => loadTx(txid));
    tr.append(tdN, tdId);
    body.appendChild(tr);
  });
  txListOffset += txs.length;
  $("tx-list-shown").textContent = `showing ${txListOffset} of ${txListTotal}`;
  $("tx-list-more").style.display = txListOffset < txListTotal ? "" : "none";
}

// Look up and display a transaction by big-endian txid.
async function loadTx(txidBeHex) {
  const txid = txidBeHex.trim().toLowerCase();
  const search = $("tx-search-status");
  if (!/^[0-9a-f]{64}$/.test(txid)) {
    setStatus(search, "Enter a 64-hex-char transaction id.", "error");
    return;
  }
  setStatus(search, "");
  const card = $("tx-view-card");
  card.style.display = "";
  setStatus($("tx-view-status"), "Loading…");
  let opt;
  try {
    opt = await actor.find_tx(txid);
  } catch (e) {
    setStatus($("tx-view-status"), "Lookup failed.", "error");
    return;
  }
  if (opt.length === 0) {
    $("tx-view-id").textContent = txid;
    $("tx-view-index").textContent = "—";
    $("tx-view-occ").innerHTML = "";
    setStatus(
      $("tx-view-status"),
      "Not found in any known block (its block body may not be uploaded yet).",
      "error",
    );
    writeTxUrl(txid);
    card.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  renderTxView(opt[0]);
  writeTxUrl(opt[0].txid_be_hex);
  card.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderTxView(tv) {
  $("tx-view-id").textContent = tv.txid_be_hex;
  $("tx-view-index").textContent = tv.canonical_index.length
    ? fmtNat(tv.canonical_index[0])
    : "— (not in a canonical block)";
  const tbody = $("tx-view-occ");
  tbody.innerHTML = "";
  // Canonical occurrence first, then forks.
  const occs = tv.occurrences
    .slice()
    .sort((a, b) =>
      a.is_canonical === b.is_canonical ? 0 : a.is_canonical ? -1 : 1,
    );
  for (const o of occs) {
    const tr = document.createElement("tr");
    const tdH = document.createElement("td");
    tdH.textContent = fmtNat(o.height);
    const tdC = document.createElement("td");
    tdC.textContent = o.is_canonical ? "canonical" : "fork";
    tdC.className = o.is_canonical ? "ok" : "warn";
    const tdP = document.createElement("td");
    tdP.textContent = fmtNat(o.position);
    const tdT = document.createElement("td");
    tdT.textContent = fmtTime(o.block_time);
    const tdHash = document.createElement("td");
    tdHash.className = "hash linkish";
    tdHash.textContent = o.block_hash_be_hex;
    tdHash.title = "View block";
    tdHash.addEventListener("click", () =>
      loadBlock({ hash: o.block_hash_be_hex }),
    );
    tr.append(tdH, tdC, tdP, tdT, tdHash);
    tbody.appendChild(tr);
  }
  setStatus($("tx-view-status"), "");
}

function writeTxUrl(txidBeHex) {
  const want = `#tx=${txidBeHex}`;
  if (location.hash !== want) {
    suppressHashChange = true;
    history.replaceState(null, "", want);
  }
}

function loadFromUrl() {
  const h = location.hash;
  let m;
  if ((m = h.match(/^#h=(\d+)$/))) return loadBlock({ height: BigInt(m[1]) });
  if ((m = h.match(/^#hash=([0-9a-f]{64})$/i)))
    return loadBlock({ hash: m[1].toLowerCase() });
  if ((m = h.match(/^#tx=([0-9a-f]{64})$/i))) {
    const txid = m[1].toLowerCase();
    // Render the tip block for context, then show the tx view.
    return loadBlock({}).then(() => loadTx(txid));
  }
  return loadBlock({});
}

window.addEventListener("hashchange", () => {
  if (suppressHashChange) {
    suppressHashChange = false;
    return;
  }
  loadFromUrl();
});

// Make the prev-hash field clickable -> walk to parent (works for
// fork branches too, since get_by_hash finds any stored block).
$("bi-prev").addEventListener("click", () => {
  const h = $("bi-prev").textContent.trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(h) && !/^0+$/.test(h)) {
    loadBlock({ hash: h });
  }
});

// ---------------------------------------------------------------------------
// Wire up controls.
// ---------------------------------------------------------------------------

function clampHeight(h) {
  if (h < 0n) return 0n;
  if (h > tipHeight) return tipHeight;
  return h;
}

$("btn-prev").addEventListener("click", () =>
  loadBlock({ height: clampHeight(currentHeight - 1n) }),
);
$("btn-next").addEventListener("click", () =>
  loadBlock({ height: clampHeight(currentHeight + 1n) }),
);
$("btn-tip").addEventListener("click", () => loadBlock({}));
$("btn-genesis").addEventListener("click", () => loadBlock({ height: 0n }));
$("btn-goto").addEventListener("click", () => {
  const v = $("goto-input").value.trim();
  if (v === "") return;
  let h;
  try {
    h = BigInt(v);
  } catch {
    return;
  }
  loadBlock({ height: clampHeight(h) });
});
$("goto-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("btn-goto").click();
});

$("btn-find-hash").addEventListener("click", async () => {
  const v = $("hash-input").value.trim().toLowerCase();
  const status = $("hash-status");
  if (!/^[0-9a-f]{64}$/.test(v)) {
    setStatus(status, "Enter a 64-hex-char block hash.", "error");
    return;
  }
  setStatus(status, "");
  await loadBlock({ hash: v });
});
$("hash-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("btn-find-hash").click();
});

$("btn-find-tx").addEventListener("click", () => loadTx($("txid-input").value));
$("txid-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("btn-find-tx").click();
});

$("btn-find-txindex").addEventListener("click", async () => {
  const v = $("txindex-input").value.trim();
  const status = $("tx-search-status");
  if (v === "") return;
  let idx;
  try {
    idx = BigInt(v);
  } catch {
    setStatus(status, "Enter a transaction index (number).", "error");
    return;
  }
  setStatus(status, "Looking up…");
  let opt;
  try {
    opt = await actor.txid_at_index(idx);
  } catch {
    setStatus(status, "Lookup failed.", "error");
    return;
  }
  if (opt.length === 0) {
    setStatus(status, "No transaction at that index.", "error");
    return;
  }
  setStatus(status, "");
  await loadTx(opt[0]);
});
$("txindex-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("btn-find-txindex").click();
});

$("tx-list-more").addEventListener("click", () => loadMoreTxids());

$("btn-refresh").addEventListener("click", async () => {
  const status = $("refresh-status");
  const btn = $("btn-refresh");
  btn.disabled = true;
  setStatus(status, "Refreshing…");
  try {
    // If the user is on the canonical tip, follow the new tip;
    // otherwise stay on the current block (by hash, so a fork
    // tip view doesn't drift onto canonical).
    const followTip = currentHeight === tipHeight;
    if (followTip) {
      await loadBlock({});
    } else {
      await loadBlock(
        currentHash ? { hash: currentHash } : { height: currentHeight },
      );
    }
    setStatus(status, "Up to date.", "ok");
  } catch (e) {
    setStatus(status, `Refresh failed: ${e.message || e}`, "error");
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// Initial load — honour URL hash if present.
// ---------------------------------------------------------------------------

await loadFromUrl();
