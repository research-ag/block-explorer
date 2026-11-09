/**
 * body-uploader
 *
 * Pulls full blocks from a local Bitcoin Core node via JSON-RPC,
 * extracts the txid list of each block, and uploads them to the
 * block_explorer canister one at a time via `push_body`.
 *
 * Design: stateless. On every iteration the uploader asks the canister
 * where it needs the next body (`bodies_next_height`), fetches that
 * one block from bitcoind, and submits it. No local state file, no
 * batch flushing, no error-message parsing. The canister IS the
 * source of truth for progress:
 *
 *   - On a push_body success the next iteration's bodies_next_height
 *     has advanced; we naturally go to the next block.
 *   - On a reorg the canister's bodies_next_height moves BACKWARD to
 *     the common-ancestor height; the next iteration picks that up
 *     and re-uploads the (now-canonical) bodies from there.
 *   - On a canister-side error (`#err`) we don't try to interpret it:
 *     we sleep POLL_INTERVAL and ask again. The canister's state
 *     moves on its own schedule.
 *   - On a bitcoind error we log and sleep.
 *
 * A body may be submitted only once its block's header has been
 * indexed in the canister (the header relay runs ahead of us). To
 * avoid spending cycles on a doomed push, the uploader does one
 * `have_hashes` query per iteration before submitting; if the header
 * isn't known yet, sleep and retry.
 *
 * Environment variables (all optional with shown defaults):
 *   BTC_RPC_HOST=127.0.0.1
 *   BTC_RPC_PORT=8332
 *   BTC_RPC_USER=bitcoin
 *   BTC_RPC_PASSWORD=changeme
 *   IC_URL=https://icp0.io
 *   CANISTER_ID=                          # required
 *   IDENTITY_JSON=                        # path; if unset, anonymous identity
 *   POLL_INTERVAL=60                      # seconds to wait when idle or on error; 0 = one-shot
 */
import * as fs from "node:fs";
import { createHash } from "node:crypto";
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
const POLL_INTERVAL_S = Number(process.env.POLL_INTERVAL ?? 60);
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
    return await btcRpc("getblock", [hash, 1]);
}
async function getRawTransactionHex(txid, blockhash) {
    return await btcRpc("getrawtransaction", [txid, 0, blockhash]);
}
// ---------------------------------------------------------------------------
// Bitcoin transaction parsing — strip segwit witness to get the serialization
// the merkle tree commits to
// ---------------------------------------------------------------------------
function readVarInt(buf, off) {
    const b0 = buf[off];
    if (b0 < 0xfd)
        return [b0, 1];
    if (b0 === 0xfd)
        return [buf[off + 1] | (buf[off + 2] << 8), 3];
    if (b0 === 0xfe) {
        return [
            buf[off + 1] | (buf[off + 2] << 8) | (buf[off + 3] << 16) | (buf[off + 4] * 0x1000000),
            5,
        ];
    }
    throw new Error(`varint too large at offset ${off}: 0xff`);
}
export function stripWitness(raw) {
    if (raw.length < 10)
        throw new Error(`raw tx too short: ${raw.length} bytes`);
    let p = 0;
    const chunks = [];
    chunks.push(raw.subarray(p, p + 4));
    p += 4; // version
    const hasWitness = raw[p] === 0x00 && raw[p + 1] === 0x01;
    if (hasWitness)
        p += 2;
    const [vinCount, vinLen] = readVarInt(raw, p);
    chunks.push(raw.subarray(p, p + vinLen));
    p += vinLen;
    for (let i = 0; i < vinCount; i += 1) {
        const start = p;
        p += 32 + 4;
        const [scriptLen, scriptLenSize] = readVarInt(raw, p);
        p += scriptLenSize + scriptLen + 4;
        chunks.push(raw.subarray(start, p));
    }
    const [voutCount, voutLen] = readVarInt(raw, p);
    chunks.push(raw.subarray(p, p + voutLen));
    p += voutLen;
    for (let i = 0; i < voutCount; i += 1) {
        const start = p;
        p += 8;
        const [scriptLen, scriptLenSize] = readVarInt(raw, p);
        p += scriptLenSize + scriptLen;
        chunks.push(raw.subarray(start, p));
    }
    if (hasWitness) {
        for (let i = 0; i < vinCount; i += 1) {
            const [stackLen, stackLenSize] = readVarInt(raw, p);
            p += stackLenSize;
            for (let j = 0; j < stackLen; j += 1) {
                const [itemLen, itemLenSize] = readVarInt(raw, p);
                p += itemLenSize + itemLen;
            }
        }
    }
    chunks.push(raw.subarray(p, p + 4));
    p += 4; // locktime
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}
// ---------------------------------------------------------------------------
// Hex + hash helpers
// ---------------------------------------------------------------------------
function sha256(b) { return new Uint8Array(createHash("sha256").update(b).digest()); }
function sha256d(b) { return sha256(sha256(b)); }
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
function hexToBytes(hex) {
    if (hex.length % 2 !== 0)
        throw new Error(`odd-length hex: ${hex.length}`);
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i += 1)
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}
function bytesReverseHex(b) {
    let s = "";
    for (let i = b.length - 1; i >= 0; i -= 1)
        s += b[i].toString(16).padStart(2, "0");
    return s;
}
// ---------------------------------------------------------------------------
// Per-block coinbase: fetch, strip witness, verify dSHA matches firstTxid
// ---------------------------------------------------------------------------
async function fetchCoinbase(blockHashHex, coinbaseTxidHex, firstTxidLE) {
    const rawHex = await getRawTransactionHex(coinbaseTxidHex, blockHashHex);
    const raw = hexToBytes(rawHex);
    const stripped = stripWitness(raw);
    if (stripped.length <= 64) {
        throw new Error(`coinbase of block ${blockHashHex} is ${stripped.length} bytes after stripping — canister requires > 64`);
    }
    const got = sha256d(stripped);
    if (got.length !== firstTxidLE.length || !got.every((b, i) => b === firstTxidLE[i])) {
        throw new Error(`coinbase stripped-tx mismatch for block ${blockHashHex}: ` +
            `got ${bytesReverseHex(got)} want ${bytesReverseHex(firstTxidLE)}`);
    }
    return stripped;
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
// ---------------------------------------------------------------------------
// One iteration: ask the canister where it needs the next body, fetch it,
// submit it. No state file; the canister is the only source of truth.
//
// Return values:
//   "work"   — a body was submitted (success or error); loop again immediately.
//   "idle"   — nothing to do (uploader is at tip or header pending); sleep.
//   "error"  — a transient error we can't push past this round; sleep.
// ---------------------------------------------------------------------------
async function processOne(actor) {
    // 1. Where does the canister want the next body?
    const nextBig = await actor.bodies_next_height();
    const next = Number(nextBig);
    // 2. How far has bitcoind come?
    const tip = await getBlockCount();
    if (next > tip) {
        log(`up to date: canister next=${next} > bitcoind tip=${tip}`);
        return "idle";
    }
    // 3. Fetch the block from bitcoind.
    const hashHex = await getBlockHash(next);
    const block = await getBlockVerbose(hashHex);
    const txids = block.tx;
    const txCount = txids.length;
    if (txCount === 0) {
        throw new Error(`block ${next} has zero transactions, this shouldn't happen`);
    }
    // 4. Header pre-flight: skip (no cycles spent) if the canister hasn't
    //    indexed this header yet. The header relay runs ahead of us.
    const [known] = await actor.have_hashes([hashHex]);
    if (!known) {
        log(`header pending: canister does not yet know header at height ${next} (${hashHex}); waiting`);
        return "idle";
    }
    // 5. Prepare + submit.
    const blockHashLE = hexReverse32(hashHex);
    const txidsLE = txids.map(hexReverse32);
    const coinbaseTx = await fetchCoinbase(hashHex, txids[0], txidsLE[0]);
    log(`submitting height=${next} hash=${hashHex} tx_count=${txCount}`);
    const t0 = Date.now();
    const result = await actor.push_body(blockHashLE, txidsLE, coinbaseTx);
    const submitMs = Date.now() - t0;
    if ("ok" in result) {
        const ok = result.ok;
        log(`result    height=${next} tx_count=${txCount} ` +
            `indexed=${ok.canonical_indexed} duplicate=${ok.duplicate} submit_ms=${submitMs}`);
        return "work";
    }
    // Canister rejected the body. Don't try to parse the error — the canister's
    // own state will tell us what to do on the next iteration (reorg → smaller
    // bodies_next_height; header pending → have_hashes = false; other issues
    // resolve on retry).
    logErr(`push_body height=${next} hash=${hashHex} tx_count=${txCount} submit_ms=${submitMs}: ${result.err}`);
    return "error";
}
// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------
let shuttingDown = false;
function installSignalHandlers() {
    const handle = (sig) => {
        log(`signal ${sig} received, shutting down`);
        shuttingDown = true;
    };
    process.on("SIGINT", handle);
    process.on("SIGTERM", handle);
}
async function main() {
    log(`body-uploader starting (stateless, one block per call)`);
    log(`  bitcoind = ${BTC_RPC_HOST}:${BTC_RPC_PORT}`);
    log(`  canister = ${CANISTER_ID} via ${IC_URL}`);
    installSignalHandlers();
    const actor = await makeActor();
    const oneShot = POLL_INTERVAL_S <= 0 || process.argv.includes("--once");
    while (!shuttingDown) {
        let outcome;
        try {
            outcome = await processOne(actor);
        }
        catch (e) {
            logErr(`iteration failed: ${e instanceof Error ? e.message : e}`);
            outcome = "error";
        }
        if (oneShot)
            break;
        // "work" means we made progress — no sleep, come right back for the next block.
        // "idle" / "error" means wait before asking again.
        if (outcome !== "work") {
            await sleep(POLL_INTERVAL_S * 1000);
        }
    }
    return 0;
}
function sleep(ms) {
    return new Promise((resolve) => {
        const t = setTimeout(resolve, ms);
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
