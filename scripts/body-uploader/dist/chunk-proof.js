/**
 * Proofs for the canister's chunked body upload (push_body_chunk), which
 * verifies each chunk with mmr's Chunks (mo:mmr/Chunks), on one tree kept
 * across blocks and without a backup (Chunks.onTree). Proofs of more than 20
 * peaks are refused; a block's tree is at most 15 levels deep.
 *
 * A chunk that ends at leaf m (the leaves 0 .. m-1 are then in) comes with the
 * proof for m: the right siblings of leaf m-1's ancestors in Bitcoin's Merkle
 * tree, as far as they contain at least one real leaf, lowest first. That is
 * what mmr's Prove.rightPeaks(levels, m) computes; here, as there, it is read
 * off the tree's levels, which the uploader builds once per block. The proof
 * for m = n (the last chunk) is empty.
 *
 * `closes` repeats the canister's check off-chain (mmr's Peaks.close with
 * Bitcoin's rule, equal-sibling rejections included), so a bad proof is caught
 * before it costs an update call.
 *
 * Everything is in Bitcoin's INTERNAL byte order (raw double-SHA-256 output).
 */
import { createHash } from "node:crypto";
export function sha256d(b) {
    const once = createHash("sha256").update(b).digest();
    return new Uint8Array(createHash("sha256").update(once).digest());
}
function combine(left, right) {
    const buf = new Uint8Array(64);
    buf.set(left, 0);
    buf.set(right, 32);
    return sha256d(buf);
}
function equal(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i += 1)
        if (a[i] !== b[i])
            return false;
    return true;
}
/**
 * Bitcoin's Merkle tree over `txids`, level by level: levels[0] is the txids,
 * each next level pairs up the nodes of the one below, the last node with
 * itself when the count is odd, and the last level holds only the root.
 */
export function buildLevels(txids) {
    if (txids.length === 0)
        throw new Error("buildLevels: no txids");
    for (const t of txids)
        if (t.length !== 32)
            throw new Error(`buildLevels: txid of ${t.length} bytes`);
    const levels = [txids];
    let cur = txids;
    while (cur.length > 1) {
        const next = [];
        for (let i = 0; i < cur.length; i += 2)
            next.push(combine(cur[i], cur[i + 1] ?? cur[i]));
        levels.push(next);
        cur = next;
    }
    return levels;
}
export function rootOf(levels) {
    return levels[levels.length - 1][0];
}
/**
 * The proof for a chunk that ends at leaf m (1 <= m <= n). At level k the
 * ancestor of leaf m-1 has index i = (m-1) >> k; when i is even it is a left
 * child, and its right sibling, index i+1, goes into the proof if the level
 * has it, i.e. if it contains a real leaf. (Beyond that Bitcoin's rule pairs
 * the node with itself, and the canister does that without a proof peak; a
 * proof that contained such a peak would be rejected as an equal sibling.)
 */
export function proofFor(levels, m) {
    const n = levels[0].length;
    if (!Number.isInteger(m) || m < 1 || m > n)
        throw new Error(`proofFor: m=${m} outside 1..${n}`);
    const proof = [];
    for (let k = 0; k < levels.length - 1; k += 1) {
        const i = Math.floor((m - 1) / 2 ** k);
        if (i % 2 === 0 && i + 1 < levels[k].length)
            proof.push(levels[k][i + 1]);
    }
    return proof;
}
/**
 * The canister's check, off-chain: close the tree over the first m leaves with
 * `proof` and compare with the root, as the canister does (mmr's Peaks.close).
 * The tree's peaks are the nodes at the 1-bits of m: at level k, index
 * (m >> k) - 1. Starting from the lowest peak and going up, the node in hand
 * meets a peak of the tree on its left where m has a 1-bit, else the next
 * peak of the proof on its right, else nothing (it is paired with itself).
 * Two equal siblings fail the check, as on the canister.
 */
export function closes(levels, m, proof) {
    const root = rootOf(levels);
    const shifted = (k) => Math.floor(m / 2 ** k);
    const peak = (k) => levels[k][shifted(k) - 1];
    let k = 0;
    while (shifted(k) % 2 === 0)
        k += 1; // lowest 1-bit of m
    const lowest = peak(k);
    let i = 0;
    let acc;
    if (i < proof.length) {
        if (equal(lowest, proof[0]))
            return false;
        acc = combine(lowest, proof[0]);
        i = 1;
    }
    else {
        if (shifted(k) === 1)
            return equal(lowest, root); // a single peak is the root
        acc = combine(lowest, lowest);
    }
    k += 1;
    while (shifted(k) > 0 || i < proof.length) {
        if (k >= 64)
            return false;
        if (shifted(k) % 2 === 1) {
            const p = peak(k);
            if (equal(p, acc))
                return false;
            acc = combine(p, acc);
        }
        else if (i < proof.length) {
            if (equal(acc, proof[i]))
                return false;
            acc = combine(acc, proof[i]);
            i += 1;
        }
        else {
            acc = combine(acc, acc);
        }
        k += 1;
    }
    return equal(acc, root);
}
