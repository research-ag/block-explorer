/**
 * Self-test for chunk-proof.ts: for every block size n in 1..MAX_N and every
 * chunk end m in 1..n, the proof for m closes to the root, and tampered
 * proofs (a sibling flipped, one dropped, one added) do not.
 *
 *   npm run selftest
 *   node dist/chunk-proof.selftest.js --vectors   # proofs as hex, for comparing with the Motoko prover
 */
import { createHash } from "node:crypto";
import { buildLevels, closes, proofFor, rootOf } from "./chunk-proof.js";
const MAX_N = 300;
// Synthetic txid i: sha256 of the 4-byte little-endian index (distinct leaves).
function txid(i) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, i, true);
    return new Uint8Array(createHash("sha256").update(b).digest());
}
function hex(b) {
    return Buffer.from(b).toString("hex");
}
if (process.argv.includes("--vectors")) {
    // One line per (n, m): "n m root proof0,proof1,..."
    for (const n of [1, 2, 3, 5, 7, 8, 9, 13, 16, 17, 33]) {
        const levels = buildLevels(Array.from({ length: n }, (_, i) => txid(i)));
        for (let m = 1; m <= n; m += 1) {
            console.log(`${n} ${m} ${hex(rootOf(levels))} ${proofFor(levels, m).map(hex).join(",")}`);
        }
    }
    process.exit(0);
}
let checked = 0;
let failures = 0;
function fail(msg) {
    failures += 1;
    if (failures <= 20)
        console.error(`FAIL ${msg}`);
}
for (let n = 1; n <= MAX_N; n += 1) {
    const levels = buildLevels(Array.from({ length: n }, (_, i) => txid(i)));
    for (let m = 1; m <= n; m += 1) {
        const proof = proofFor(levels, m);
        checked += 1;
        if (m === n && proof.length !== 0)
            fail(`n=${n} m=${m}: last chunk proof not empty`);
        if (!closes(levels, m, proof))
            fail(`n=${n} m=${m}: valid proof rejected`);
        if (proof.length > 0) {
            const flipped = proof.map((p) => p.slice());
            flipped[flipped.length - 1][0] ^= 1;
            if (closes(levels, m, flipped))
                fail(`n=${n} m=${m}: flipped proof accepted`);
            if (closes(levels, m, proof.slice(0, -1)))
                fail(`n=${n} m=${m}: shortened proof accepted`);
        }
        if (closes(levels, m, [...proof, txid(n + 1)]))
            fail(`n=${n} m=${m}: lengthened proof accepted`);
    }
}
console.log(`${checked} (n, m) pairs checked for n <= ${MAX_N}, ${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
