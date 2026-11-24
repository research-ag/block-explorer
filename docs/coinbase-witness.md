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

Bitcoin Core enforces this in `CheckWitnessMalleation`. If the block has a
commitment, the coinbase witness must have exactly that shape. If it has
none, or the block is below activation, no transaction in the block may
have a witness.

So the coinbase of practically every block since segwit has a witness
section the canister doesn't store. In the full serialization that is:

| Bytes | Content |
|---|---|
| after the version | marker `00`, flag `01` |
| before the locktime | `01 20 <reserved value>` |
| total | 36 bytes |

The canister can't derive these bytes either: nothing it stores pins down
the reserved value. That's why `GET /api/tx/:txid/hex` and `/raw` answer 404
for such coinbases rather than serving bytes that differ from Esplora's.

## Applications

Storing `witness_root` and `witness_reserved_value` per block would enable:

1. **Esplora `/hex` and `/raw` for every coinbase,** byte for byte.
2. **A dashboard display** of both values per block.
3. **wtxid inclusion proofs.** A client holding a transaction with its
   witness, plus a wtxid Merkle branch, could check it against the root the
   canister holds. The canister holds no wtxids, so it can't produce the
   branch itself.

None of these has a consumer today. Revisit this design when one appears.

## Design

### Uploader

The uploaders get their data from these RPCs today:

| Uploader | RPCs |
|---|---|
| body-uploader, chunk-uploader | `getblock <hash> 1` for the txids, `getrawtransaction` for the coinbase |
| `coinbase-backfill.py` | `getblock <hash> 0` |

No RPC returns the witness root directly. One call, `getblock <hash> 0`,
returns the raw block with its witnesses, and everything else can be
computed from it:

- **txids:** `dSHA256` of each transaction's stripped serialization;
- **wtxids:** `dSHA256` of each full serialization, with the coinbase's
  replaced by zeros;
- **`witness_root`:** the Merkle root of the wtxids, built by the same tree
  rule as for txids;
- **the coinbase:** in full, with its witness.

(`getblock <hash> 2` lists the wtxids as each transaction's `hash`, but its
JSON is far larger than the raw block.)

The body uploaders would replace `getblock 1` plus `getrawtransaction` with
one `getblock 0` and a parse, and would stop stripping the witness.

### Canister: upload

The coinbase arrives in its full serialization, with `witness_root : ?Blob`
alongside it. The canister then:

1. **Parses the coinbase.** Bytes 4..6 equal to `00 01` mark the segwit
   serialization. That is unambiguous, because in a stripped coinbase
   byte 4 is the input count, `01`.
2. **Checks the witness shape.** In the segwit form, the input's witness
   must be exactly one 32-byte item: `witness_reserved_value`.
3. **Finds the commitment:** the last output whose script is at least
   38 bytes long and starts `6a24aa21a9ed`.
4. **Verifies the commitment:**
   `SHA256d(witness_root || witness_reserved_value) == commitment`.
5. **Runs today's checks on the stripped form.** It rebuilds the stripped
   form (version, inputs, outputs, locktime) and checks it is longer than
   64 bytes and that `dSHA256` equals txid 0. The depth-of-tree binding is
   about the txid preimage, which is why the length check applies to the
   stripped form.

The canister rejects:

| Case | Reason |
|---|---|
| A witness but no commitment output | Such a block is invalid by consensus |
| A witness of any other shape than one 32-byte item | Invalid by consensus |
| Any witness below height 481 824 | Invalid by consensus |
| A commitment and a witness, with `witness_root` missing or wrong | Can't be verified |
| `witness_root` given with a stripped coinbase that has a commitment | The reserved value is missing |

**Old uploaders.** A stripped coinbase without `witness_root` is accepted
as it is today, and nothing new is stored for it. Below 481 824, an output
that looks like a commitment has no meaning and is ignored.

**Everything stored stays pinned by the header.** The commitment binds the
reserved value and the root. The commitment sits in the coinbase, which
txid 0 binds to the header's Merkle root. A different
(root, reserved value) pair would need a second SHA256d preimage.

**Inspect.** `canister_inspect_message` must apply the same checks, by the
repo's rule that inspect rejects exactly what the call would.

**Cost.** One parse and one SHA256d of 64 bytes per block: negligible next
to the txid Merkle verification.

### Candid

All of the following additions are backward compatible:

- **`push_body`:** `(hash, txids, coinbase_tx, opt blob)`, with the root as
  a trailing optional argument.
- **`push_bodies`:** a fourth, `opt blob` element in each entry's tuple. A
  record extended with an `opt` field still decodes old messages.
- **`push_body_chunk`:** a trailing `opt blob`, meaningful only together
  with `#coinbase_tx`.
- **`push_fork_coinbase`:** `(hash, coinbase, opt blob)`.
- **Backfill** of coinbases already stored, described under
  [Option B](#canister-storage) below.
- **A new query,** for example
  `get_coinbase_witness(height) : opt record { witness_root : blob; witness_reserved_value : blob }`.

### Canister: storage

There are two options.

**A. Store the full coinbase in the region.**

- `/hex` serves the bytes as stored, and the reserved value travels inside
  them.
- Each segwit-era entry grows by 36 bytes, and the root still needs its own
  32 bytes per block elsewhere.
- Every reader of region bytes has to skip the marker: `Coinbases.scriptSig`,
  `Coinbases.witnessCommitted`, `get_coinbase`, and the frontend's
  scriptSig parse.
- **Determinism breaks.** A block's entry would depend on which uploader
  sent its coinbase: stripped from an old one, full from a new one. Avoiding
  that means refusing stripped coinbases that have a commitment from some
  point on. Without that, the region loses its "byte-identical across any
  ingest history" property.
- Converting the roughly 500 K segwit-era entries already stored means
  rebuilding the region from height 481 824 up, because entries are back to
  back.

**B. Keep the stripped coinbase in the region, plus 64 bytes per block in a
separate store** (the root and the reserved value).

- **Nothing existing changes:** not the region, `get_coinbase`, the
  frontend, or fork-coinbase handling.
- **`/hex` rebuilds the full form:** version, `00 01`, inputs, outputs,
  `01 20 <reserved value>`, locktime. The rebuild is exact, because
  consensus allows the coinbase witness only that shape.
- **Size:** about 32 MB for 500 K blocks.

B is the smaller change. It consists of:

- **The store.** A stable Region of 64-byte slots indexed by height, with a
  fill cursor gated like `coinbaseBackfillCursor`. A presence bit would
  also work, but zeros can't mean "absent", since the reserved value is
  normally all zeros.
- **Reorgs.** The store rewinds together with the coinbase region, and the
  demoted 64 bytes move onto the fork body, as coinbases do.
- **State changes.** `ForkBody` and the chunked-upload state each get an
  optional 64-byte field. That is a stable-type change, so it needs a
  migration.
- **Backfill.** The stripped coinbase already stored holds the commitment.
  So for each height the uploader sends only
  `(witness_root, witness_reserved_value)`, 64 bytes. The canister checks
  `SHA256d(root || reserved) == commitment` and stores the pair. No
  coinbase is resent.

**A simpler upload API.** With B, the upload API could also keep
`coinbase_tx` stripped, adding a trailing
`opt record { witness_root : blob; witness_reserved_value : blob }` that the
canister verifies the same way. The canister then needs no segwit parser.
The uploaders still need `getblock 0` to compute the root.

### Tests

`test/Esplora.test.mo` already holds block 500044's coinbase in both forms
(`B500044_ESPLORA_HEX`, with the witness, and `B500044_STRIPPED_HEX`). A
rebuild test would also need that block's witness root, computed from all
its wtxids (from a node, or from Esplora's `/block/:hash/txs`).

## Independent of this design

Today's `/hex` rule answers 404 for any coinbase with an output shaped like
a commitment, at any height. Below 481 824, consensus allows no witness at
all, so the stored bytes there are always the full serialization. Checking
the height would let `/hex` serve those coinbases. Whether any
pre-activation coinbase has such an output hasn't been checked.
