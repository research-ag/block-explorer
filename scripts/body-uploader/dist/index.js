/**
 * body-uploader
 *
 * Pulls full blocks from a local Bitcoin Core node via JSON-RPC,
 * extracts the txid list of each block, and uploads them to the
 * block_explorer canister via `push_body` / `push_bodies`.
 *
 * A body may be uploaded only once all of the block's ancestor bodies are
 * known (so its first-tx serial number is determined): canonical bodies in
 * strict height order, and a fork block's body only after its parent's.
 * This uploader walks heights in order, which satisfies that for the
 * canonical chain. The canister verifies each body against the block's
 * merkle root, indexes canonical bodies into the txid trie, and stores fork
 * bodies in the fork-block record (so a reorg re-indexes automatically).
 * Re-uploading a known body is a no-op (counted as `duplicate`).
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
 *        e. Call `push_body(blockHashLE, BigInt(tx_count), hashesBlob)`
 *           - On `{ ok: PushBodyOk }`    : log accepted / duplicate
 *           - On `{ err: text }`         : log error and stop (keep state)
 *      Persist `next = h + 1` after each successful put.
 *   4. Repeat after POLL_INTERVAL seconds (or one-shot when `--once`).
 *
 * The canister rejects a push_body whose block_hash isn't already known
 * (the header must be present first), so this script depends on the
 * header relay (poll-headers.py / watch-headers.py) being ahead of it.
 * To avoid burning cycles when the header relay stalls, the uploader
 * pre-checks each batch with the canister's `have_hashes` query and
 * only submits the prefix whose headers are already known. If none
 * are known it skips the iteration entirely — no push_body call, no
 * cycles spent — and retries after POLL_INTERVAL.
 *
 * Reorg handling
 * --------------
 * If a Bitcoin reorg replaced canonical blocks below the uploader's
 * cursor after they were uploaded, the canister will reject the next
 * push with
 *   "ancestor bodies unknown: expected canonical body for height H, got G"
 * The uploader parses H out of that message and rolls the state file
 * back to H. The next iteration then re-uploads the (now current)
 * canonical bodies from H onward — bodies whose hashes still match are
 * counted as `duplicate` and state fast-forwards through them; bodies
 * that changed under the reorg are re-indexed. A safety cap
 * (MAX_REORG_ROLLBACK, default 10_000) prevents a parser slip or a
 * garbled canister error from rewinding state all the way to zero.
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
 *   MAX_REORG_ROLLBACK=10000              # cap on auto-rollback when the canister reports a reorg
 *   POLL_INTERVAL=60                      # seconds between iterations; 0 = one-shot
 *   STATE_FILE=$HOME/.ic/body-uploader.state.json
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { HttpAgent, Actor, AnonymousIdentity } from "@icp-sdk/core/agent";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import { idlFactory } from "../block_explorer.did.js";
// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const BTC_RPC_HOST = process.env.BTC_RPC_HOST ?? "127.0.0.1";
const BTC_RPC_PORT = Number(process.env.BTC_RPC_PORT ?? 8332);
const BTC_RPC_USER = process.env.BTC_RPC_USER ?? "bitcoin";
const BTC_RPC_PASSWORD = process.env.BTC_RPC_PASSWORD ?? "changeme";
const IC_URL = process.env.IC_URL ?? "https://icp0.io";
const CANISTER_ID = required("CANISTER_ID");
const IDENTITY_JSON = process.env.IDENTITY_JSON ?? "";
const START_HEIGHT = Number(process.env.START_HEIGHT ?? 0);
// MAX_PER_RUN bounds how many heights one iteration walks. Set to
// match MAX_BATCH_BLOCKS so each iteration can fill at least one
// full batch (and on dense modern blocks the MAX_BATCH_TXIDS cap
// kicks in to flush early, several times per iteration).
const MAX_PER_RUN = Number(process.env.MAX_PER_RUN ?? 1000);
const POLL_INTERVAL_S = Number(process.env.POLL_INTERVAL ?? 60);
const STATE_FILE = process.env.STATE_FILE
    ?? path.join(os.homedir(), ".ic", "body-uploader.state.json");
// Per-call batch caps; mirror the canister-side limits in put_bodies.
// The 31_250-txid cap keeps the txid payload at ≤1 MiB, well under
// the ~2 MiB IC ingress limit even after Candid framing. The
// 1_000-block cap matches the canister's MAX_BATCH_BLOCKS.
const MAX_BATCH_BLOCKS = Number(process.env.MAX_BATCH_BLOCKS ?? 1000);
const MAX_BATCH_TXIDS = Number(process.env.MAX_BATCH_TXIDS ?? 31_250);
// Cap on how far a reorg auto-rollback may rewind state.next in a
// single event. Bitcoin reorgs deeper than a handful of blocks are
// vanishingly rare; 10_000 leaves plenty of headroom while ensuring
// a garbled error message can't wind state all the way to zero.
const MAX_REORG_ROLLBACK = Number(process.env.MAX_REORG_ROLLBACK ?? 10_000);
function required(name) {
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
function log(msg, ...args) {
    const ts = new Date().toISOString();
    console.log(`${ts} ${msg}`, ...args);
}
function logErr(msg, ...args) {
    const ts = new Date().toISOString();
    console.error(`${ts} ERROR ${msg}`, ...args);
}
// ---------------------------------------------------------------------------
// Bitcoin Core JSON-RPC
// ---------------------------------------------------------------------------
const BTC_RPC_URL = `http://${BTC_RPC_HOST}:${BTC_RPC_PORT}/`;
const BTC_RPC_AUTH = "Basic " + Buffer.from(`${BTC_RPC_USER}:${BTC_RPC_PASSWORD}`).toString("base64");
async function btcRpc(method, params = []) {
    const res = await fetch(BTC_RPC_URL, {
        method: "POST",
        headers: { "content-type": "application/json", "authorization": BTC_RPC_AUTH },
        body: JSON.stringify({ jsonrpc: "1.0", id: method, method, params }),
    });
    if (!res.ok)
        throw new Error(`bitcoind RPC HTTP ${res.status}: ${await res.text()}`);
    const body = await res.json();
    if (body.error)
        throw new Error(`bitcoind RPC error: ${JSON.stringify(body.error)}`);
    return body.result;
}
async function getBlockCount() {
    return await btcRpc("getblockcount");
}
async function getBlockHash(height) {
    return await btcRpc("getblockhash", [height]);
}
async function getBlockVerbose(hash) {
    // verbosity=1 returns the block with tx[] as an array of txid strings
    // (vs verbosity=2 which would return the full transaction objects).
    return await btcRpc("getblock", [hash, 1]);
}
// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------
/** Decode a 64-char display-order (big-endian) hex string into a 32-byte
 *  internal-LE byte array. */
function hexReverse32(hex) {
    if (hex.length !== 64)
        throw new Error(`expected 64-char hex, got ${hex.length}: ${hex}`);
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) {
        const j = 31 - i;
        out[i] = parseInt(hex.slice(j * 2, j * 2 + 2), 16);
    }
    return out;
}
// ---------------------------------------------------------------------------
// Reorg detection
// ---------------------------------------------------------------------------
/** The canister's "ancestor bodies unknown" error names the height it
 *  actually expects next; the uploader's state.next got ahead of the
 *  canonical chain because a Bitcoin reorg replaced canonical blocks
 *  under us. Parse the expected height out so the caller can roll
 *  state back to it. Example message:
 *
 *    "ancestor bodies unknown: expected canonical body for height 962_722, got 962_723"
 *
 *  Underscores are Candid-style thousands separators. Returns null if
 *  the message doesn't match. */
function parseAncestorError(msg) {
    const m = msg.match(/expected canonical body for height ([\d_]+)/);
    if (!m)
        return null;
    const n = Number(m[1].replace(/_/g, ""));
    return Number.isFinite(n) && n >= 0 ? n : null;
}
function loadState() {
    try {
        const raw = fs.readFileSync(STATE_FILE, "utf8");
        const s = JSON.parse(raw);
        if (typeof s.next !== "number" || !Number.isInteger(s.next)) {
            throw new Error("malformed state");
        }
        return s;
    }
    catch {
        return { next: START_HEIGHT, updated_at: new Date().toISOString() };
    }
}
function saveState(s) {
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
async function makeActor() {
    const identity = makeIdentity();
    const agent = await HttpAgent.create({ host: IC_URL, identity });
    const isMainnet = MAINNET_HOSTS.some((h) => IC_URL.includes(h));
    if (!isMainnet) {
        await agent.fetchRootKey();
    }
    return Actor.createActor(idlFactory, { agent, canisterId: CANISTER_ID });
}
async function processOneIteration(actor, state) {
    const tip = await getBlockCount();
    if (state.next > tip) {
        log(`up to date: next=${state.next} > bitcoind tip=${tip}`);
        return state;
    }
    // Header pre-flight for the first block we plan to submit. If the canister
    // doesn't know that header yet, the header relay is behind — skip this
    // iteration entirely instead of fetching MAX_PER_RUN blocks from bitcoind
    // just to have flush() trim them all.
    const firstHashHex = await getBlockHash(state.next);
    const firstKnown = (await actor.have_hashes([firstHashHex]))[0];
    if (!firstKnown) {
        log(`header pending: canister does not yet know header at height ${state.next} ` +
            `(hash ${firstHashHex}); waiting for header relay`);
        return state;
    }
    const end = Math.min(tip, state.next + MAX_PER_RUN - 1);
    log(`processing heights ${state.next}..${end} (tip=${tip})`);
    // Accumulate blocks into a batch until either MAX_BATCH_BLOCKS or
    // MAX_BATCH_TXIDS would be exceeded, then flush via put_bodies and
    // continue. Persist state after each successful flush.
    let pending = [];
    let pendingTxids = 0;
    // Flush helper — sends the current batch and updates `state`.
    // Returns the *new* state (advancing past the accepted blocks) and
    // a boolean: true means "stop the iteration", e.g. the canister
    // reported an error.
    const flush = async () => {
        if (pending.length === 0)
            return { state, stop: false };
        // Pre-flight: which of these headers does the canister actually have?
        // A push_body(ies) for an unknown header still costs cycles and just
        // fails. Trim to the longest known prefix; defer the rest to a later
        // iteration once the header relay has caught up.
        const pendingHashesHex = pending.map((p) => p.hashHex);
        const known = await actor.have_hashes(pendingHashesHex);
        let knownPrefix = 0;
        while (knownPrefix < known.length && known[knownPrefix])
            knownPrefix += 1;
        if (knownPrefix === 0) {
            log(`header pending: canister does not yet know header for height ${pending[0].height} ` +
                `(hash ${pending[0].hashHex}); stopping iteration until header relay catches up`);
            pending = [];
            pendingTxids = 0;
            return { state, stop: true };
        }
        const trimmedTail = knownPrefix < pending.length;
        if (trimmedTail) {
            const fromH = pending[knownPrefix].height;
            const toH = pending[pending.length - 1].height;
            const dropped = pending.length - knownPrefix;
            log(`header frontier: canister knows ${knownPrefix}/${pending.length} pending; ` +
                `deferring heights ${fromH}..${toH} (${dropped} blocks) until header relay catches up`);
            pending = pending.slice(0, knownPrefix);
            pendingTxids = pending.reduce((s, p) => s + p.txCount, 0);
        }
        const batch = pending.map((p) => p.entry);
        const firstH = pending[0].height;
        const lastH = pending[pending.length - 1].height;
        const totalTxs = pendingTxids;
        // Two log lines bracketing the IC call so you can read off:
        //   prepare time  = "submitting" timestamp − previous "processing" /
        //                   previous flush's "result" timestamp
        //   submit  time  = "result" timestamp     − "submitting" timestamp
        log(`submitting heights=${firstH}..${lastH} (${pending.length} blocks, ` +
            `${totalTxs} txids)`);
        const submitT0 = Date.now();
        const result = await actor.push_bodies(batch);
        const submitMs = Date.now() - submitT0;
        if ("err" in result) {
            logErr(`push_bodies heights=${firstH}..${lastH} (${pending.length} blocks, ` +
                `${totalTxs} txids) submit_ms=${submitMs}: ${result.err}`);
            // Hard failure (e.g. malformed input) — don't advance state.
            pending = [];
            pendingTxids = 0;
            return { state, stop: true };
        }
        const ok = result.ok;
        const accepted = Number(ok.accepted);
        const duplicate = Number(ok.duplicate);
        const processed = accepted + duplicate;
        const lastError = ok.last_error.length > 0 ? ok.last_error[0] : null;
        log(`result      heights=${firstH}..${lastH} (${pending.length} blocks, ` +
            `${totalTxs} txids) accepted=${accepted} duplicate=${duplicate}` +
            ` submit_ms=${submitMs}` +
            (lastError ? ` last_error="${lastError}"` : ""));
        // Advance state past every block the canister processed without an
        // error (both accepted and duplicate are progress).
        if (processed > 0) {
            const advancedTo = pending[processed - 1].height + 1;
            const nextState = {
                next: advancedTo,
                updated_at: new Date().toISOString(),
            };
            saveState(nextState);
            pending = [];
            pendingTxids = 0;
            // If we trimmed unknown-header blocks off the tail, stop the iteration
            // — the outer loop would just fetch more of them from bitcoind for
            // nothing.
            return { state: nextState, stop: lastError !== null || trimmedTail };
        }
        // processed == 0 with last_error set — the very first block in the
        // batch failed. If the canister is telling us its canonical chain
        // has moved under us (a Bitcoin reorg), roll state.next back to
        // the height it asked for so the next iteration re-uploads. Cap
        // the rollback so a parser slip can't rewind us to zero.
        if (lastError !== null) {
            const expected = parseAncestorError(lastError);
            if (expected !== null && expected < state.next) {
                const rollback = state.next - expected;
                pending = [];
                pendingTxids = 0;
                if (rollback > MAX_REORG_ROLLBACK) {
                    logErr(`reorg rollback of ${rollback} blocks (from ${state.next} to ${expected}) ` +
                        `exceeds MAX_REORG_ROLLBACK=${MAX_REORG_ROLLBACK}; giving up. ` +
                        `Investigate before restarting.`);
                    return { state, stop: true };
                }
                const nextState = {
                    next: expected,
                    updated_at: new Date().toISOString(),
                };
                saveState(nextState);
                log(`reorg detected: rolling state back ${rollback} blocks ` +
                    `(from ${state.next} to ${expected}); will retry on next iteration`);
                return { state: nextState, stop: true };
            }
        }
        pending = [];
        pendingTxids = 0;
        return { state, stop: lastError !== null || trimmedTail };
    };
    for (let h = state.next; h <= end; h += 1) {
        if (shuttingDown)
            break;
        const hashHex = await getBlockHash(h);
        const block = await getBlockVerbose(hashHex);
        const txids = block.tx;
        const txCount = txids.length;
        if (txCount === 0) {
            throw new Error(`block ${h} has zero transactions, this shouldn't happen`);
        }
        // Adding this block would overflow either cap — flush first.
        if (pending.length >= MAX_BATCH_BLOCKS ||
            pendingTxids + txCount > MAX_BATCH_TXIDS) {
            const r = await flush();
            state = r.state;
            if (r.stop)
                return state;
        }
        // Single block bigger than the per-batch txid cap — can't be sent
        // even as its own batch via push_bodies. Fall back to push_body
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
                log(`push_body (oversize) height=${h} hash=${hashHex} tx_count=${txCount} ` +
                    `indexed=${ok.canonical_indexed} duplicate=${ok.duplicate}`);
                state = { next: h + 1, updated_at: new Date().toISOString() };
                saveState(state);
                continue;
            }
            const errMsg = result.err;
            logErr(`push_body (oversize) height=${h} hash=${hashHex}: ${errMsg}`);
            const expected = parseAncestorError(errMsg);
            if (expected !== null && expected < state.next) {
                const rollback = state.next - expected;
                if (rollback > MAX_REORG_ROLLBACK) {
                    logErr(`reorg rollback of ${rollback} blocks (from ${state.next} to ${expected}) ` +
                        `exceeds MAX_REORG_ROLLBACK=${MAX_REORG_ROLLBACK}; giving up`);
                }
                else {
                    state = { next: expected, updated_at: new Date().toISOString() };
                    saveState(state);
                    log(`reorg detected: rolling state back ${rollback} blocks ` +
                        `(from ${h} to ${expected}); will retry on next iteration`);
                }
            }
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
        if (r.stop)
            return state;
    }
    return state;
}
// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------
let shuttingDown = false;
function installSignalHandlers() {
    const handle = (sig) => {
        log(`signal ${sig} received, shutting down at end of current iteration`);
        shuttingDown = true;
    };
    process.on("SIGINT", handle);
    process.on("SIGTERM", handle);
}
async function main() {
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
        }
        catch (e) {
            logErr(`iteration failed: ${e instanceof Error ? e.message : e}`);
            // A flush may have advanced the on-disk state (saveState after each
            // successful batch) before the throw. Re-sync the in-memory state from
            // disk — otherwise the next iteration resumes from this run's stale
            // STARTING height, re-sending already-accepted batches as duplicates and
            // overwriting the file back down to that height.
            state = loadState();
        }
        if (oneShot)
            break;
        await sleep(POLL_INTERVAL_S * 1000);
    }
    return 0;
}
function sleep(ms) {
    return new Promise((resolve) => {
        const t = setTimeout(resolve, ms);
        // Resolve early if a signal comes in.
        const tick = setInterval(() => {
            if (shuttingDown) {
                clearTimeout(t);
                clearInterval(tick);
                resolve();
            }
        }, 500);
    });
}
main().then((code) => process.exit(code), (err) => { logErr(`fatal: ${err?.stack ?? err}`); process.exit(1); });
