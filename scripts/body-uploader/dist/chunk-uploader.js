/**
 * chunk-uploader
 *
 * Uploads block bodies to the block_explorer canister through the chunked
 * interface, `push_body_chunk`, at most CHUNK_SIZE (<= 5000) txids per call,
 * with the proof each chunk needs (see chunk-proof.ts).
 *
 * Design: stateless, like the push_body uploader (index.ts). Every iteration
 * asks the canister where the next txid goes (`txid_tip`: height and offset
 * within that block), fetches that block from bitcoind, and sends the next
 * chunk from that offset. The canister is the only source of truth:
 *
 *   - After an accepted chunk the tip's offset has moved on (or, after the
 *     last chunk, the height); the next iteration continues from there.
 *   - Another uploader that got there first just moves the tip; a chunk we
 *     sent for an old offset is rejected cheaply in inspect, and the next
 *     iteration re-reads the tip.
 *   - After a reorg that displaces a block mid-upload the canister drops the
 *     partial upload; the tip goes back to offset 0 (or a lower height).
 *   - Canister errors are logged, not parsed; sleep and ask again.
 *
 * Per chunk:
 *   1. txid_tip -> (height, offset); skip if bitcoind is not there yet.
 *   2. getblockhash(height), have_hashes pre-check (header must be indexed).
 *   3. getblock(hash, 1): the txids; Bitcoin's tree is built once per block
 *      (cached in memory while the block is being uploaded) and its root is
 *      checked against the block's merkleroot.
 *   4. The chunk is [offset, min(offset + CHUNK_SIZE, n)); its proof is
 *      checked off-chain with the canister's own algorithm before sending.
 *   5. The first chunk (offset 0) carries the witness-stripped coinbase
 *      (#coinbase_tx), later chunks their offset (#offset).
 *
 * Environment variables (all optional with shown defaults):
 *   BTC_RPC_HOST=127.0.0.1
 *   BTC_RPC_PORT=8332
 *   BTC_RPC_USER=bitcoin
 *   BTC_RPC_PASSWORD=changeme
 *   IC_URL=https://icp0.io
 *   CANISTER_ID=                          # required
 *   IDENTITY_JSON=                        # path; if unset, anonymous identity
 *   CHUNK_SIZE=5000                       # txids per chunk, 1..5000
 *   POLL_INTERVAL=60                      # seconds to wait when idle or on error; 0 = one-shot
 *
 * Flags:
 *   --once      one iteration, then exit
 *   --dry-run   do everything up to the push_body_chunk call, log it, skip it
 */
import * as fs from "node:fs";
import { HttpAgent, Actor, AnonymousIdentity } from "@icp-sdk/core/agent";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import { idlFactory } from "../block_explorer.did.js";
import { buildLevels, closes, proofFor, rootOf, sha256d } from "./chunk-proof.js";
// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const MAX_CHUNK_SIZE = 5000;
const BTC_RPC_HOST = process.env.BTC_RPC_HOST ?? "127.0.0.1";
const BTC_RPC_PORT = Number(process.env.BTC_RPC_PORT ?? 8332);
const BTC_RPC_USER = process.env.BTC_RPC_USER ?? "bitcoin";
const BTC_RPC_PASSWORD = process.env.BTC_RPC_PASSWORD ?? "changeme";
const IC_URL = process.env.IC_URL ?? "https://icp0.io";
const CANISTER_ID = required("CANISTER_ID");
const IDENTITY_JSON = process.env.IDENTITY_JSON ?? "";
const CHUNK_SIZE = Number(process.env.CHUNK_SIZE ?? MAX_CHUNK_SIZE);
const POLL_INTERVAL_S = Number(process.env.POLL_INTERVAL ?? 60);
const DRY_RUN = process.argv.includes("--dry-run");
if (!Number.isInteger(CHUNK_SIZE) || CHUNK_SIZE < 1 || CHUNK_SIZE > MAX_CHUNK_SIZE) {
    console.error(`CHUNK_SIZE must be an integer in 1..${MAX_CHUNK_SIZE}, got ${process.env.CHUNK_SIZE}`);
    process.exit(2);
}
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
    console.log(`${new Date().toISOString()} ${msg}`, ...args);
}
function logErr(msg, ...args) {
    console.error(`${new Date().toISOString()} ERROR ${msg}`, ...args);
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
const getBlockCount = () => btcRpc("getblockcount");
const getBlockHash = (height) => btcRpc("getblockhash", [height]);
const getBlockVerbose = (hash) => btcRpc("getblock", [hash, 1]);
const getRawTransactionHex = (txid, blockhash) => btcRpc("getrawtransaction", [txid, 0, blockhash]);
// ---------------------------------------------------------------------------
// Transaction parsing: strip the segwit witness to get the serialization the
// txid (and so the Merkle tree) commits to.
// ---------------------------------------------------------------------------
function readVarInt(buf, off) {
    const b0 = buf[off];
    if (b0 < 0xfd)
        return [b0, 1];
    if (b0 === 0xfd)
        return [buf[off + 1] | (buf[off + 2] << 8), 3];
    if (b0 === 0xfe) {
        return [buf[off + 1] | (buf[off + 2] << 8) | (buf[off + 3] << 16) | (buf[off + 4] * 0x1000000), 5];
    }
    throw new Error(`varint too large at offset ${off}: 0xff`);
}
function stripWitness(raw) {
    if (raw.length < 10)
        throw new Error(`raw tx too short: ${raw.length} bytes`);
    let p = 0;
    const parts = [];
    parts.push(raw.subarray(p, p + 4));
    p += 4; // version
    const hasWitness = raw[p] === 0x00 && raw[p + 1] === 0x01;
    if (hasWitness)
        p += 2;
    const [vinCount, vinLen] = readVarInt(raw, p);
    parts.push(raw.subarray(p, p + vinLen));
    p += vinLen;
    for (let i = 0; i < vinCount; i += 1) {
        const start = p;
        p += 32 + 4;
        const [scriptLen, scriptLenSize] = readVarInt(raw, p);
        p += scriptLenSize + scriptLen + 4;
        parts.push(raw.subarray(start, p));
    }
    const [voutCount, voutLen] = readVarInt(raw, p);
    parts.push(raw.subarray(p, p + voutLen));
    p += voutLen;
    for (let i = 0; i < voutCount; i += 1) {
        const start = p;
        p += 8;
        const [scriptLen, scriptLenSize] = readVarInt(raw, p);
        p += scriptLenSize + scriptLen;
        parts.push(raw.subarray(start, p));
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
    parts.push(raw.subarray(p, p + 4));
    p += 4; // locktime
    const out = new Uint8Array(parts.reduce((s, c) => s + c.length, 0));
    let o = 0;
    for (const c of parts) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}
// ---------------------------------------------------------------------------
// Hex helpers (display hex is the byte-reversed internal order)
// ---------------------------------------------------------------------------
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
function sameBytes(a, b) {
    return a.length === b.length && a.every((x, i) => x === b[i]);
}
let cached = null;
async function loadBlock(hashHex) {
    if (cached && cached.hashHex === hashHex)
        return cached;
    const verbose = await getBlockVerbose(hashHex);
    if (verbose.tx.length === 0)
        throw new Error(`block ${hashHex} has zero transactions`);
    const txidsLE = verbose.tx.map(hexReverse32);
    const levels = buildLevels(txidsLE);
    const root = bytesReverseHex(rootOf(levels));
    if (root !== verbose.merkleroot) {
        throw new Error(`block ${hashHex}: computed merkle root ${root} != header merkleroot ${verbose.merkleroot}`);
    }
    cached = { hashHex, txidsHex: verbose.tx, txidsLE, levels };
    return cached;
}
// The witness-stripped coinbase, checked against txid 0 and the canister's
// > 64-byte rule before it is sent.
async function fetchCoinbase(block) {
    const raw = hexToBytes(await getRawTransactionHex(block.txidsHex[0], block.hashHex));
    const stripped = stripWitness(raw);
    if (stripped.length <= 64) {
        throw new Error(`coinbase of block ${block.hashHex} is ${stripped.length} bytes after stripping; canister requires > 64`);
    }
    const got = sha256d(stripped);
    if (!sameBytes(got, block.txidsLE[0])) {
        throw new Error(`coinbase of block ${block.hashHex} hashes to ${bytesReverseHex(got)}, not txid ${block.txidsHex[0]}`);
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
    const id = Ed25519KeyIdentity.fromJSON(fs.readFileSync(IDENTITY_JSON, "utf8"));
    log(`Identity from ${IDENTITY_JSON} (principal=${id.getPrincipal().toText()})`);
    return id;
}
const MAINNET_HOSTS = ["icp0.io", "ic0.app"];
async function makeActor() {
    const agent = await HttpAgent.create({ host: IC_URL, identity: makeIdentity() });
    if (!MAINNET_HOSTS.some((h) => IC_URL.includes(h)))
        await agent.fetchRootKey();
    return Actor.createActor(idlFactory, { agent, canisterId: CANISTER_ID });
}
// Accepted chunks and completed blocks since this process started (log only).
let totalChunks = 0;
let totalBlocks = 0;
async function processOne(actor) {
    // 1. Where does the next txid go?
    const tip = await actor.txid_tip();
    const height = Number(tip.height);
    const offset = Number(tip.offset);
    const btcTip = await getBlockCount();
    if (height > btcTip) {
        log(`up to date: txid tip height=${height} > bitcoind tip=${btcTip}`);
        return "idle";
    }
    // 2. The block, if the canister has its header.
    const hashHex = await getBlockHash(height);
    const [known] = await actor.have_hashes([hashHex]);
    if (!known) {
        log(`header pending: canister does not know header ${hashHex} at height ${height} yet; waiting`);
        return "idle";
    }
    // 3. Its txids and tree.
    const block = await loadBlock(hashHex);
    const n = block.txidsLE.length;
    if (offset >= n) {
        logErr(`txid tip offset ${offset} at height ${height} is past bitcoind's block ${hashHex} of ${n} txs; the canister has another block there`);
        return "error";
    }
    // 4. The chunk and its proof, checked as the canister will check it.
    const end = Math.min(offset + CHUNK_SIZE, n);
    // Chunk k of K for this block, counted from the offset so it stays right
    // across restarts (exact while the block's chunks are all CHUNK_SIZE long).
    const chunkNo = Math.ceil(offset / CHUNK_SIZE) + 1;
    const chunkCount = chunkNo + Math.ceil((n - end) / CHUNK_SIZE);
    const proof = proofFor(block.levels, end);
    if (!closes(block.levels, end, proof)) {
        throw new Error(`local check failed for the proof of txs [${offset}, ${end}) of block ${hashHex}; not sending`);
    }
    // 5. Send it.
    const start = offset === 0
        ? { coinbase_tx: await fetchCoinbase(block) }
        : { offset: BigInt(offset) };
    const what = `height=${height} chunk=${chunkNo}/${chunkCount} txs=[${offset}, ${end}) of ${n} proof=${proof.length}`;
    if (DRY_RUN) {
        log(`dry run: would send ${what} (${offset === 0 ? "with coinbase" : "by offset"})`);
        return "work";
    }
    log(`submitting ${what}`);
    const t0 = Date.now();
    const result = await actor.push_body_chunk(hexReverse32(hashHex), start, block.txidsLE.slice(offset, end), proof);
    const ms = Date.now() - t0;
    if ("ok" in result) {
        const ok = result.ok;
        totalChunks += 1;
        if (ok.complete)
            totalBlocks += 1;
        log(`accepted  height=${ok.height} chunk=${chunkNo}/${chunkCount} offset=${ok.offset} complete=${ok.complete} ` +
            `first_tx_index=${ok.first_tx_index} submit_ms=${ms} | since start: chunks=${totalChunks} blocks=${totalBlocks}`);
        if (ok.complete) {
            log(`block done height=${ok.height} txs=${n} chunks=${chunkCount}`);
            cached = null;
        }
        return "work";
    }
    logErr(`push_body_chunk ${what} submit_ms=${ms}: ${result.err}`);
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
async function main() {
    log(`chunk-uploader starting (stateless, up to ${CHUNK_SIZE} txids per chunk${DRY_RUN ? ", DRY RUN" : ""})`);
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
        // A dry run never moves the tip, so it would repeat the same chunk.
        if (oneShot || DRY_RUN)
            break;
        if (outcome !== "work")
            await sleep(POLL_INTERVAL_S * 1000);
    }
    return 0;
}
main().then((code) => process.exit(code), (err) => { logErr(`fatal: ${err?.stack ?? err}`); process.exit(1); });
