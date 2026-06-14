# btc

Bitcoin primitives for Motoko. Everything needed to handle block headers and
verify data against them — with no opinion about how you store anything.
SPV-oriented today (light-client header validation); the package name leaves
room for full-node pieces later.

## Modules

### `Header`

- **Wire format**: `parseHeader : Blob -> ?Parsed` for raw 80-byte headers,
  plus zero-allocation field accessors straight off the blob
  (`versionOf`, `timeOf`, `bitsOf`, `nonceOf`).
- **Hashing**: `headerHashBlob(digest, raw)` — double-SHA256 on a
  caller-provided `mo:sha2` engine. Threading one long-lived engine avoids
  the ~3.3 KB Digest construction per hash.
- **Compact difficulty**: `nBitsToTarget`, `targetToNBits`,
  `chainWork` (= floor(2^256 / (target + 1))).
- **Consensus rules**: `checkPoW` (operates directly on the compact nBits
  encoding — no target bignum is computed and nothing allocates),
  `checkBits`, `checkMTP`, `checkFutureDrift`, `checkContinuity`, and the
  combined `validateParsed` / `validateAgainst`.
- **Context math**: `medianTimePast` (the 11-timestamp median) and
  `computeRetargetNBits` (the 2016-block difficulty retarget, Satoshi
  off-by-one included).
- **Constants**: `RETARGET_INTERVAL`, `TARGET_TIMESPAN`, `POW_LIMIT_NBITS`,
  `POW_LIMIT_TARGET`, `GENESIS_HEADER_HEX`, …
- **Byte/hex utilities**: `hexToBlob`, `bytesToHex` (chunked, not
  per-char), `reverse32` (internal LE <-> display BE), `leBytesToNat`.

### `Merkle`

- `root(digest, hashes, txCount)` — Bitcoin merkle root over a flat blob of
  32-byte txids (stride 32, internal LE order), with the
  duplicate-last-node rule. Reuses the caller's hash engine across the
  whole tree.

## Public API

`Header`, `Merkle`, and `Bytes` are the public surface. `Bytes` holds
generic little-endian byte helpers (`readLE32`, `writeLE32`, `slice32`) —
public because consumers that mirror raw headers in their own storage reuse
them. `src/internal/` (`Hex`) holds generic helpers used only by the
implementation — not part of the package API; don't import it directly.

## Conventions

All 32-byte hashes are in Bitcoin's *internal* little-endian order (natural
sha256d output). Big-endian display hex only at the edges, via
`reverse32` + `bytesToHex`.

## Performance notes

Written for hot canister paths: byte-level Blob indexing throughout (no
`toArray` round trips), bignum limb splits without division
(`Nat64.fromIntWrap` + `Prim.shiftRight`), and a PoW check that never
leaves fixed-width arithmetic. Measured with `Prim.rts_total_allocation`;
see the test suite.

```
mops add btc
```

```motoko
import Sha256 "mo:sha2/Sha256";
import Header "mo:btc/Header";
import Merkle "mo:btc/Merkle";

let sha = Sha256.Digest(#sha256);            // one engine, reuse forever
let parsed = Header.parseHeader(raw80);
let hash = Header.headerHashBlob(sha, raw80);
let ok = Header.validateAgainst(raw80, expectedBits, prevHash, mtp, now);
let root = Merkle.root(sha, txidsBlob, txCount);
```
