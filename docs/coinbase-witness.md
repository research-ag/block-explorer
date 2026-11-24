# Storing the coinbase witness (deferred design)

**Status:** not implemented. Written down on 2026-11-24, while adding the
Esplora tx routes ([research-ag/block-explorer#17](https://github.com/research-ag/block-explorer/pull/17)).
It is deferred because nothing needs it yet; see [Applications](#applications).

## Background

The canister stores each canonical block's coinbase **witness-stripped**
(`src/block_explorer/Coinbases.mo`). The uploaders remove the witness
before upload:

- `stripWitness` in `scripts/body-uploader/src/index.ts` and
  `chunk-uploader.ts`;
- `extract_coinbase` in `scripts/coinbase-backfill.py`.

The canister authenticates a coinbase by checking that
`dSHA256(bytes) == txid 0`, and a txid is the hash of the stripped
serialization.

Segwit activated on mainnet at height 481 824. Since then, a block with any
witness data must commit to it (BIP141):

- **The commitment output.** One of the coinbase's outputs has a
  scriptPubKey of at least 38 bytes starting `6a 24 aa 21 a9 ed`
  (OP_RETURN, push 36, the commitment header). If several outputs match,
  the one with the highest index counts.
- **The commitment.** Its bytes 6..38 are
  `commitment = SHA256d(witness_root || witness_reserved_value)`.
- **The witness root.** `witness_root` is the Merkle root of the block's
  wtxids, with the coinbase's wtxid taken as 32 zero bytes.
- **The reserved value.** The coinbase input's witness is exactly one
  32-byte item, `witness_reserved_value`. Bitcoin Core's mining code uses
  32 zero bytes, and the value has no defined meaning yet.

So the coinbase of practically every block since segwit has a witness
section the canister doesn't store. In the coinbase's full serialization
that is:

| Bytes | Content |
|---|---|
| after the version | marker `00`, flag `01` |
| before the locktime | `01 20 <reserved value>` |
| total | 36 bytes |

The marker and flag belong to the transaction, not the block (BIP144).
Each transaction in a block is serialized on its own, with marker, flag
and witness if it has a witness and without them if it doesn't. A
transaction's txid hashes its serialization without marker, flag and
witness; its wtxid hashes the full one.

The canister can't derive these bytes either: nothing it stores pins down
the reserved value. That's why `GET /api/tx/:txid/hex` and `/raw` answer 404
for such coinbases rather than serving bytes that differ from Esplora's.

### What makes a block a segwit block

The block header has no segwit flag, and a block has no marker of its own.
What decides it is the coinbase's outputs, read by Bitcoin Core's
`GetWitnessCommitmentIndex` (`src/consensus/validation.h`) and
`CheckWitnessMalleation` (`src/validation.cpp`).

**From activation on,** the last coinbase output matching the pattern above
*is* the commitment, by definition. An output can't look like a commitment
without being one. So:

- **A block with such an output** must give its coinbase exactly one
  32-byte witness item ("bad-witness-nonce-size" otherwise). That item's
  hash with the witness root must equal the commitment
  ("bad-witness-merkle-match" otherwise). The coinbase therefore always has
  a witness, even when no other transaction in the block has one.
- **A block without one** may not contain a witness in any transaction
  ("unexpected-witness").

From activation on, then, a block has witness data exactly when its
coinbase has a commitment-shaped output. The canister can test that on the
stripped coinbase it already stores; `Coinbases.witnessCommitted` does,
with the same pattern.

**Before activation,** no transaction may have a witness. A
commitment-shaped output there is an ordinary OP_RETURN output with no
meaning. (See [Pre-activation coinbases](#pre-activation-coinbases).)

## Applications

Storing `witness_root` and `witness_reserved_value` per block would enable:

1. **Esplora `/hex` and `/raw` for every coinbase,** byte for byte.
2. **A dashboard display** of both values per block.
3. **wtxid inclusion proofs.** A client holding a transaction with its
   witness, plus a wtxid Merkle branch, could check it against the root the
   canister holds. The canister holds no wtxids, so it can't produce the
   branch itself.

None of these has a consumer today. Revisit this design when one appears.

## Design: a separate witness upload

The witness data is kept completely separate from the body:

- the existing upload API and coinbase storage stay as they are;
- the witness root and the reserved value are uploaded after the block's
  coinbase is stored, through their own endpoint;
- they're stored in their own Region.

### Canister

**Endpoint.** For example:

```
push_coinbase_witnesses(start_height : nat,
  witnesses : vec opt record { witness_root : blob; witness_reserved_value : blob })
  -> (variant { ok : record { accepted : nat }; err : text })
```

It works like `push_coinbases_backfill`:

- `start_height` must equal a witness cursor, which starts at 481 824
  (nothing below it has a witness).
- Each entry is checked against the canonical coinbase already stored at
  its height, so the cursor can't pass `coinbaseBackfillCursor`.
- Processing stops at the first failure, and the entries before it are
  kept.

**Checks for each entry:**

| Stored coinbase at its height | Entry |
|---|---|
| Has a commitment | Must be present, with `SHA256d(witness_root \|\| witness_reserved_value) == commitment` |
| No commitment | Must be null: the block has no witness |

The commitment is the last matching output, as in Bitcoin Core. Null
entries move the cursor past blocks without a witness, so the uploader
states that explicitly and the canister confirms it.

**Everything stored stays pinned by the header.** The commitment binds the
pair. The commitment sits in the stored coinbase, which txid 0 binds to the
header's Merkle root. Another pair would need a second SHA256d preimage.

**Store.** A stable Region of 64-byte slots, one per height from 481 824,
plus the cursor:

- A slot is filled for a committed block below the cursor and left zero
  otherwise. Zero can't stand for "absent", because the reserved value is
  normally all zeros; the cursor and the stored coinbase say which slots
  are filled.
- Slot contents are a function of the chain alone, so the Region is
  byte-identical across ingest histories, like the coinbase region.
- Size: about 32 MB for 500 K blocks.
- **Gaps are negligible.** A scan of mainnet up to 977 357 (2026-11-24)
  found 1 363 post-activation blocks without a commitment, 0.28 % of
  495 534, from 483 162 on. About 337 a year early on, fewer than 60 a
  year recently. They leave 87 KB of zero slots, so dense packing with an
  index isn't worth it.

**Variant: store only the root.** The reserved value has no defined
meaning yet, and it is practically always zero. All 399 witnesses in a
random sample of 400 post-activation coinbases had zero; the 400th block
had no witness. So:

- **Upload and store:** the canister verifies the uploaded reserved value
  with the commitment, then stores only the root, in 32-byte slots
  (about 16 MB).
- **No flag needed:** whether the reserved value was zero can be recovered
  later. `SHA256d(root || 32 zero bytes) == commitment` holds exactly then,
  since another value with the same root would need a second preimage.
- **What `/hex` does:** it rebuilds the coinbase with zeros where that
  check holds, and answers 404 where it fails.
- **Same check for clients:** anyone can verify a stored root against the
  coinbase from `get_coinbase` this way.
- **Cost:** coinbases with a non-zero reserved value can't be served, and
  their roots can't be checked independently. The sample bounds them below
  about 0.75 % of blocks at 95 % confidence. An exact count needs every
  coinbase with its witness, from a node.

**Reorgs.** If the cursor is past the common ancestor, it rewinds to the
first height above it, together with `coinbaseBackfillCursor`. Witnesses of demoted blocks are
dropped rather than moved onto fork bodies, and are uploaded again if their
block is promoted back. Fork blocks get no witness storage. This keeps
`ForkBody` and the chunked-upload state unchanged. The new `State` fields
(the Region and the cursor) still need a migration.

**Queries.**

- **A new query,** for example
  `get_coinbase_witness(height) : opt record { witness_root : blob; witness_reserved_value : blob }`.
- **`/hex` and `/raw`** rebuild a committed coinbase that has its witness
  stored: version, `00 01`, the stripped bytes between version and
  locktime, `01 20 <reserved value>`, locktime. The rebuild is exact,
  because consensus allows the coinbase witness only that shape. Without
  a stored witness, they answer 404 as today.

**Inspect.** `canister_inspect_message` must apply the same checks, by the
repo's rule that inspect rejects exactly what the call would.

**Cost.** For each entry: one coinbase read from the Region, a parse of its
outputs, and one SHA256d of 64 bytes.

### Uploader

The witness upload is its own process, running behind the coinbase cursor.
It could live in `coinbase-backfill.py`, or in a new script. The existing
uploaders don't change.

No RPC returns the witness root directly, but one call per block gives
everything it's computed from. Either call works:

- **`getblock <hash> 2`** returns, for each transaction, `txid`, `hash` (the
  wtxid) and `hex` (the full serialization, with the witness). The
  uploader parses nothing. Two caveats:
  - The coinbase's `hash` is its real wtxid, so the uploader must replace
    it with 32 zero bytes before computing the root.
  - The JSON is much larger than the raw block, because every input and
    output is decoded.
- **`getblock <hash> 0`** returns the raw block, with witnesses. The
  uploader splits it into transactions and computes:
  - the txids: `dSHA256` of each serialization without the witness;
  - the wtxids: `dSHA256` of each full serialization, with the coinbase's
    taken as zero.

  `coinbase-backfill.py` already parses raw blocks this way.

Either way:

- `witness_root` is the Merkle root of the wtxids, built by the same tree
  rule as for txids;
- `witness_reserved_value` is the coinbase's single witness item;
- a block whose coinbase has no witness gets a null entry.

### Tests

`test/Esplora.test.mo` already holds block 500044's coinbase in both forms
(`B500044_ESPLORA_HEX`, with the witness, and `B500044_STRIPPED_HEX`). A
rebuild test would also need that block's witness root, computed from all
its wtxids (from a node, or from Esplora's `/block/:hash/txs`).

## Alternatives considered

**Uploading the witness with the body.**

- The coinbase would arrive either in full with the root alongside it, or
  stripped with an optional pair. Either way that is one optional argument.
- The canister would check the witness shape and the commitment, then run
  today's checks on the stripped form.
- **Candid:** the new arguments could be added compatibly to `push_body`,
  `push_bodies`, `push_body_chunk` and `push_fork_coinbase`.
- **Cost:** it ties the witness to every body path. `ForkBody` and the
  chunked-upload state would have to carry it, and old uploaders would need
  a rule for when the argument may be missing.

**Storing the full coinbase in the existing region.**

- **Space:** the same bytes as the separate store, plus 4 constant bytes
  per block (marker, flag, item count, item length).
- **The layout has consequences:**
  - every reader of the region bytes has to skip the marker:
    `Coinbases.scriptSig`, `Coinbases.witnessCommitted`, `get_coinbase` and
    the frontend's scriptSig parse;
  - the roughly 500 K entries already stored can be converted only by
    rebuilding the region from 481 824 up, because entries are back to
    back;
  - a block's entry would depend on which uploader sent its coinbase,
    unless stripped coinbases that have a commitment are refused.

## Pre-activation coinbases

`/hex` and `/raw` answer 404 for a coinbase with a commitment-shaped output
only from activation on, where such a coinbase always has a witness. Below
481 824 the stored bytes are always the full serialization, so every
pre-activation coinbase is served (`Coinbases.isFullSerialization`), even
one with such an output.

Such coinbases exist. On 2026-11-24 I scanned every coinbase below 481 824
stored in the mainnet canister with the same test as
`Coinbases.witnessCommitted`:

- **13 245 have a commitment-shaped output,** from height 434 499 to
  481 823, the last block before activation. That is about 28 % of the
  47 325 blocks in that range.
- **Each has exactly one such output.** In 1 792 of them the script is
  longer than 38 bytes.
- **They match Esplora.** For 8 sampled coinbases (heights 434 499,
  454 977, 462 705, 463 220, 466 827, 470 692, 479 139 and 481 823),
  Esplora's `/tx/:txid/hex` is byte for byte the stored bytes: they have no
  witness.

Presumably these came from mining software that added the commitment
ahead of activation, when nothing checked it. Block 434 499 is from
15 October 2016, shortly before Bitcoin Core 0.13.1, the first release
with segwit for mainnet.
