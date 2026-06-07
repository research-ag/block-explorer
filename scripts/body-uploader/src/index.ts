/**
 * body-uploader
 *
 * Pulls full blocks from a local Bitcoin Core node via JSON-RPC,
 * extracts the txid list of each block, and uploads them to the
 * block_explorer canister via `push_body` / `push_bodies`.
 *
 * Bodies may be uploaded for any block whose body the canister doesn't
 * already know — canonical or fork, in any order. The canister verifies
 * each body against the block's merkle root, indexes canonical bodies in
 * chain order, and keeps everything else in a heap fork-body store (so a
 * reorg re-indexes automatically). Re-uploading a known body is a no-op
 * (counted as `duplicate`). This uploader still walks heights in order
 * for simplicity.
 *
 * Algorithm
 * ---------
 *   1. Read state file → `next` height to process. If absent, start
 *      at `START_HEIGHT` (env var, default 0).
 *   2. Ask bitcoind for its current tip.
 *   3. For each height from `next` up to `min(tip, next + MAX_PER_RUN - 1)`:
 *        a. `getblockhash <h>`           — display-order hash
 *        b. `getblock <hash> 1`          — txid list in chain order
 *        c. Convert hash + each txid from BE display → 32-byte internal LE
 *        d. Concatenate txids into one Uint8Array (tx_count * 32 bytes)
 *        e. Call `bodies.put_body(blockHashLE, BigInt(tx_count), hashesBlob)`
 *           - On `{ ok: PutOk }`         : log accepted / duplicate
 *           - On `{ err: text }`         : log error and stop (keep state)
 *      Persist `next = h + 1` after each successful put.
 *   4. Repeat after POLL_INTERVAL seconds (or one-shot when `--once`).
 *
 * The canister rejects a push_body whose block_hash isn't already known
 * (the header must be present first), so this script depends on the
 * header relay (poll-headers.py / watch-headers.py) being ahead of it.
 *
 * State file (default: $HOME/.ic/body-uploader.state.json):
 *   { "next": <height>, "updated_at": "<iso8601>" }
 *
 * Environment variables (all optional with shown defaults):
 *   BTC_RPC_HOST=127.0.0.1
 *   BTC_RPC_PORT=8332
 *   BTC_RPC_USER=bitcoin
 *   BTC_RPC_PASSWORD=changeme
 *   IC_URL=https://icp0.io
 *   CANISTER_ID=                          # required
 *   IDENTITY_JSON=                        # path; if unset, anonymous identity
 *   START_HEIGHT=0                        # only used when state file is absent
 *   MAX_PER_RUN=1000                      # cap per loop iteration; aligns with MAX_BATCH_BLOCKS
 *   MAX_BATCH_BLOCKS=1000                 # per-call block cap (also enforced canister-side)
 *   MAX_BATCH_TXIDS=31250                 # per-call txid cap (≈1 MiB) (also enforced canister-side)
 *   POLL_INTERVAL=60                      # seconds between iterations; 0 = one-shot
 *   STATE_FILE=$HOME/.ic/body-uploader.state.json
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import { HttpAgent, Actor, AnonymousIdentity } from "@icp-sdk/core/agent";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";

import { idlFactory } from "../block_explorer.did.js";
import type { _SERVICE } from "../block_explorer.did.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BTC_RPC_HOST     = process.env.BTC_RPC_HOST     ?? "127.0.0.1";
const BTC_RPC_PORT     = Number(process.env.BTC_RPC_PORT ?? 8332);
const BTC_RPC_USER     = process.env.BTC_RPC_USER     ?? "bitcoin";
const BTC_RPC_PASSWORD = process.env.BTC_RPC_PASSWORD ?? "changeme";

const IC_URL          = process.env.IC_URL          ?? "https://icp0.io";
const CANISTER_ID     = required("CANISTER_ID");
const IDENTITY_JSON   = process.env.IDENTITY_JSON   ?? "";

const START_HEIGHT    = Number(process.env.START_HEIGHT    ?? 0);
// MAX_PER_RUN bounds how many heights one iteration walks. Set to
// match MAX_BATCH_BLOCKS so each iteration can fill at least one
// full batch (and on dense modern blocks the MAX_BATCH_TXIDS cap
// kicks in to flush early, several times per iteration).
const MAX_PER_RUN     = Number(process.env.MAX_PER_RUN     ?? 1000);
const POLL_INTERVAL_S = Number(process.env.POLL_INTERVAL   ?? 60);
const STATE_FILE      = process.env.STATE_FILE
  ?? path.join(os.homedir(), ".ic", "body-uploader.state.json");

// Per-call batch caps; mirror the canister-side limits in put_bodies.
// The 31_250-txid cap keeps the txid payload at ≤1 MiB, well under
// the ~2 MiB IC ingress limit even after Candid framing. The
// 1_000-block cap matches the canister's MAX_BATCH_BLOCKS.
const MAX_BATCH_BLOCKS = Number(process.env.MAX_BATCH_BLOCKS ?? 1000);
const MAX_BATCH_TXIDS  = Number(process.env.MAX_BATCH_TXIDS  ?? 31_250);

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`Missing required env var: ${name}`);
    process.exit(2);
  }
  return v;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(msg: string, ...args: unknown[]): void {
  const ts = new Date().toISOString();
  console.log(`${ts} ${msg}`, ...args);
}
function logErr(msg: string, ...args: unknown[]): void {
  const ts = new Date().toISOString();
  console.error(`${ts} ERROR ${msg}`, ...args);
}

// ---------------------------------------------------------------------------
// Bitcoin Core JSON-RPC
// ---------------------------------------------------------------------------

const BTC_RPC_URL  = `http://${BTC_RPC_HOST}:${BTC_RPC_PORT}/`;
const BTC_RPC_AUTH = "Basic " + Buffer.from(`${BTC_RPC_USER}:${BTC_RPC_PASSWORD}`).toString("base64");

async function btcRpc<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
  const res = await fetch(BTC_RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json", "authorization": BTC_RPC_AUTH },
    body: JSON.stringify({ jsonrpc: "1.0", id: method, method, params }),
  });
  if (!res.ok) throw new Error(`bitcoind RPC HTTP ${res.status}: ${await res.text()}`);
  const body = await res.json() as { result: T; error: unknown };
  if (body.error) throw new Error(`bitcoind RPC error: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function getBlockCount(): Promise<number> {
  return await btcRpc<number>("getblockcount");
}
async function getBlockHash(height: number): Promise<string> {
  return await btcRpc<string>("getblockhash", [height]);
}
async function getBlockVerbose(hash: string): Promise<{ tx: string[] }> {
  // verbosity=1 returns the block with tx[] as an array of txid strings
  // (vs verbosity=2 which would return the full transaction objects).
  return await btcRpc<{ tx: string[] }>("getblock", [hash, 1]);
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/** Decode a 64-char display-order (big-endian) hex string into a 32-byte
 *  internal-LE byte array. */
function hexReverse32(hex: string): Uint8Array {
  if (hex.length !== 64) throw new Error(`expected 64-char hex, got ${hex.length}: ${hex}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    const j = 31 - i;
    out[i] = parseInt(hex.slice(j * 2, j * 2 + 2), 16);
  }
  return out;
}

// ---------------------------------------------------------------------------
// State file (resumable progress)
// ---------------------------------------------------------------------------

interface State { next: number; updated_at: string }

function loadState(): State {
  try {
    const raw = fs.readFileSync(STATE_FILE, "utf8");
    const s = JSON.parse(raw) as State;
    if (typeof s.next !== "number" || !Number.isInteger(s.next)) {
      throw new Error("malformed state");
    }
    return s;
  } catch {
    return { next: START_HEIGHT, updated_at: new Date().toISOString() };
  }
}

function saveState(s: State): void {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2) + "\n", "utf8");
}

// ---------------------------------------------------------------------------
// IC agent / actor
// ---------------------------------------------------------------------------

function makeIdentity() {
  if (!IDENTITY_JSON) {
    log("no IDENTITY_JSON set — using AnonymousIdentity");
    return new AnonymousIdentity();
  }
  const json = fs.readFileSync(IDENTITY_JSON, "utf8");
  const id = Ed25519KeyIdentity.fromJSON(json);
  log(`Identity from ${IDENTITY_JSON} (principal=${id.getPrincipal().toText()})`);
  return id;
}

// IC mainnet HTTP gateway hosts. If IC_URL points at anything else we
// assume a local replica and must fetch the root key. Note: icp-api.io
// is NOT the IC — it's a third-party service and must not appear here.
const MAINNET_HOSTS = ["icp0.io", "ic0.app"];

async function makeActor(): Promise<_SERVICE> {
  const identity = makeIdentity();
  const agent = await HttpAgent.create({ host: IC_URL, identity });
  const isMainnet = MAINNET_HOSTS.some((h) => IC_URL.includes(h));
  if (!isMainnet) {
    await agent.fetchRootKey();
  }
  return Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId: CANISTER_ID });
}

// ---------------------------------------------------------------------------
// One iteration: process heights from `state.next` up to a cap
// ---------------------------------------------------------------------------

// Type aliases for readability — these match block_bodies.did.d.ts.
type BatchEntry = [Uint8Array, bigint, Uint8Array]; // (block_hash_LE, tx_count, hashes_blob)

interface PendingEntry {
  height: number;
  hashHex: string;
  txCount: number;
  entry: BatchEntry;
}

async function processOneIteration(actor: _SERVICE, state: State): Promise<State> {
  const tip = await getBlockCount();
  if (state.next > tip) {
    log(`up to date: next=${state.next} > bitcoind tip=${tip}`);
    return state;
  }

  const end = Math.min(tip, state.next + MAX_PER_RUN - 1);
  log(`processing heights ${state.next}..${end} (tip=${tip})`);

  // Accumulate blocks into a batch until either MAX_BATCH_BLOCKS or
  // MAX_BATCH_TXIDS would be exceeded, then flush via put_bodies and
  // continue. Persist state after each successful flush.
  let pending: PendingEntry[] = [];
  let pendingTxids = 0;

  // Flush helper — sends the current batch and updates `state`.
  // Returns the *new* state (advancing past the accepted blocks) and
  // a boolean: true means "stop the iteration", e.g. the canister
  // reported an error.
  const flush = async (): Promise<{ state: State; stop: boolean }> => {
    if (pending.length === 0) return { state, stop: false };

    const batch: BatchEntry[] = pending.map((p) => p.entry);
    const firstH = pending[0].height;
    const lastH = pending[pending.length - 1].height;
    const totalTxs = pendingTxids;

    // Two log lines bracketing the IC call so you can read off:
    //   prepare time  = "submitting" timestamp − previous "processing" /
    //                   previous flush's "result" timestamp
    //   submit  time  = "result" timestamp     − "submitting" timestamp
    log(
      `submitting heights=${firstH}..${lastH} (${pending.length} blocks, ` +
        `${totalTxs} txids)`,
    );
    const submitT0 = Date.now();
    const result = await actor.push_bodies(batch);
    const submitMs = Date.now() - submitT0;

    if ("err" in result) {
      logErr(
        `push_bodies heights=${firstH}..${lastH} (${pending.length} blocks, ` +
          `${totalTxs} txids) submit_ms=${submitMs}: ${result.err}`,
      );
      // Hard failure (e.g. malformed input) — don't advance state.
      pending = [];
      pendingTxids = 0;
      return { state, stop: true };
    }

    const ok = result.ok;
    const accepted = Number(ok.accepted);
    const duplicate = Number(ok.duplicate);
    const processed = accepted + duplicate;
    const lastError = ok.last_error.length > 0 ? ok.last_error[0]! : null;

    log(
      `result      heights=${firstH}..${lastH} (${pending.length} blocks, ` +
        `${totalTxs} txids) accepted=${accepted} duplicate=${duplicate}` +
        ` submit_ms=${submitMs}` +
        (lastError ? ` last_error="${lastError}"` : ""),
    );

    // Advance state past every block the canister processed without an
    // error (both accepted and duplicate are progress).
    if (processed > 0) {
      const advancedTo = pending[processed - 1].height + 1;
      const nextState: State = {
        next: advancedTo,
        updated_at: new Date().toISOString(),
      };
      saveState(nextState);
      pending = [];
      pendingTxids = 0;
      return { state: nextState, stop: lastError !== null };
    }

    // processed == 0 with last_error set — the very first block in the
    // batch failed. Don't advance; surface the error.
    pending = [];
    pendingTxids = 0;
    return { state, stop: lastError !== null };
  };

  for (let h = state.next; h <= end; h += 1) {
    if (shuttingDown) break;

    const hashHex = await getBlockHash(h);
    const block = await getBlockVerbose(hashHex);
    const txids = block.tx;
    const txCount = txids.length;
    if (txCount === 0) {
      throw new Error(`block ${h} has zero transactions, this shouldn't happen`);
    }

    // Adding this block would overflow either cap — flush first.
    if (
      pending.length >= MAX_BATCH_BLOCKS ||
      pendingTxids + txCount > MAX_BATCH_TXIDS
    ) {
      const r = await flush();
      state = r.state;
      if (r.stop) return state;
    }

    // Single block bigger than the per-batch txid cap — can't be sent
    // even as its own batch via put_bodies. Fall back to put_body
    // (single, no batch cap on the canister side).
    if (txCount > MAX_BATCH_TXIDS) {
      const blockHashLE = hexReverse32(hashHex);
      const hashesBlob = new Uint8Array(txCount * 32);
      for (let i = 0; i < txCount; i += 1) {
        hashesBlob.set(hexReverse32(txids[i]), i * 32);
      }
      const result = await actor.push_body(blockHashLE, BigInt(txCount), hashesBlob);
      if ("ok" in result) {
        const ok = result.ok;
        log(
          `push_body (oversize) height=${h} hash=${hashHex} tx_count=${txCount} ` +
            `indexed=${ok.canonical_indexed} duplicate=${ok.duplicate}`,
        );
        state = { next: h + 1, updated_at: new Date().toISOString() };
        saveState(state);
        continue;
      }
      logErr(`push_body (oversize) height=${h} hash=${hashHex}: ${result.err}`);
      return state;
    }

    const blockHashLE = hexReverse32(hashHex);
    const hashesBlob = new Uint8Array(txCount * 32);
    for (let i = 0; i < txCount; i += 1) {
      hashesBlob.set(hexReverse32(txids[i]), i * 32);
    }

    pending.push({
      height: h,
      hashHex,
      txCount,
      entry: [blockHashLE, BigInt(txCount), hashesBlob],
    });
    pendingTxids += txCount;
  }

  // Final flush at end of iteration.
  if (pending.length > 0) {
    const r = await flush();
    state = r.state;
    if (r.stop) return state;
  }

  return state;
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

let shuttingDown = false;
function installSignalHandlers() {
  const handle = (sig: NodeJS.Signals) => {
    log(`signal ${sig} received, shutting down at end of current iteration`);
    shuttingDown = true;
  };
  process.on("SIGINT", handle);
  process.on("SIGTERM", handle);
}

async function main(): Promise<number> {
  log(`body-uploader starting`);
  log(`  bitcoind = ${BTC_RPC_HOST}:${BTC_RPC_PORT}`);
  log(`  canister = ${CANISTER_ID} via ${IC_URL}`);
  log(`  state    = ${STATE_FILE}`);

  installSignalHandlers();
  const actor = await makeActor();
  let state = loadState();
  log(`resume at height ${state.next}`);

  const oneShot = POLL_INTERVAL_S <= 0 || process.argv.includes("--once");

  while (!shuttingDown) {
    try {
      state = await processOneIteration(actor, state);
      saveState(state);
    } catch (e) {
      logErr(`iteration failed: ${e instanceof Error ? e.message : e}`);
    }
    if (oneShot) break;
    await sleep(POLL_INTERVAL_S * 1000);
  }
  return 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    // Resolve early if a signal comes in.
    const tick = setInterval(() => {
      if (shuttingDown) { clearTimeout(t); clearInterval(tick); resolve(); }
    }, 500);
  });
}

main().then(
  (code) => process.exit(code),
  (err)  => { logErr(`fatal: ${err?.stack ?? err}`); process.exit(1); },
);
