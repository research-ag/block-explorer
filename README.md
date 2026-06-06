# block-explorer

A header-only Bitcoin block explorer running entirely on the Internet
Computer. Four canisters:

| Canister         | Source                              | Role                                                  |
| ---------------- | ----------------------------------- | ----------------------------------------------------- |
| `block_explorer` | [src/block_explorer/main.mo](src/block_explorer/main.mo)          | Stores 80-byte block headers with full reorg support. Serves an Esplora-compatible HTTP API and `/metrics`. |
| `block_bodies`   | [src/block_bodies/block_bodies.mo](src/block_bodies/block_bodies.mo) | Indexes the txids of each block, verified against the explorer's stored merkle root. |
| `header_fetcher` | [src/header_fetcher/header_fetcher.mo](src/header_fetcher/header_fetcher.mo) | Recurring timer that reconciles `block_explorer` with blockstream.info / mempool.space via HTTPS outcalls. |
| `frontend`       | [frontend/](frontend/)              | Asset canister.                                       |

Canister wiring is in [icp.yaml](icp.yaml). `block_bodies` and
`header_fetcher` resolve `block_explorer`'s principal at startup from
the `PUBLIC_CANISTER_ID:block_explorer` env var.

---

## 1. `block_explorer` storage layout

The chain state is layered across three storage tiers:

```
L1 stable trie  : hash       -> (HeaderValue, dbidx)     HeaderDb       (mo:stable-trie)
L2 stable region: height     -> dbidx                    CanonChain     (mo:core/Region)
L3 EOP heap     : siblings, forkTips, uploader tables                   (Map/Set/List)
```

### 1.1 L1 — `HeaderDb` ([src/block_explorer/HeaderDb.mo](src/block_explorer/HeaderDb.mo))

A `mo:stable-trie` `Enumeration` keyed on the block hash:

- **Key**: 28 bytes. Bitcoin's max consensus target is `0x1d00ffff`, so
  the top 4 bytes of any valid hash (in big-endian) are zero — those
  become the *trailing* 4 bytes in our internal little-endian order
  and can be dropped. We re-pad with zeros on read; external callers
  always see 32-byte hashes.
- **Value**: a 76-byte [`HeaderValue`](src/block_explorer/HeaderValue.mo) blob
  (`version`, `parentDbidx`, `merkle`, `time`, `bits`, `nonce`,
  `height`, `cumWork`, `firstSeen`).
- **dbidx**: monotonic position in the trie, assigned on insert. The
  primary key for everything else (parent links, canonical-chain slot,
  uploader bookkeeping, block-body lookup).

### 1.2 L2 — `CanonChain` ([src/block_explorer/CanonChain.mo](src/block_explorer/CanonChain.mo))

A `Region` of 4-byte little-endian Nat32 slots: `height → canonical
dbidx`. Dense, append-only with truncate-on-reorg.
`canonChain.size() - 1` is the canonical tip height.

### 1.3 L3 — EOP-stable heap state ([src/block_explorer/Chain.mo](src/block_explorer/Chain.mo))

Survives upgrades via the actor's `share` / `unshare`:

- `siblings : Map<Nat, [Nat]>` — height → non-canonical dbidxs at that
  height. The canonical dbidx is *not* in this map (it lives in L2).
- `forkTips : Set<Nat>` — dbidxs of non-canonical leaves. Lets
  `forks()` return tips in O(F + ΣLᵢ) instead of scanning the chain.
- `uploaderPrincipals : List<Principal>` — distinct uploaders in
  registration order; the position is the "uploader index".
- `uploaderOfDbidx : List<Nat>` — parallel to `HeaderDb`. Position
  `dbidx` holds the uploader index for that header. Genesis's dbidx is
  0, and `uploaderPrincipals[0]` is the explorer canister's own
  principal (recorded in `initGenesis`), so the parallel arrays line
  up at dbidx 0.

Two purely-heap views are rebuilt from the lists above in `unshare`:
the per-uploader block list (`uploaders`) and an `anonymousCount` for
the anonymous principal (whose block list is intentionally not
materialised — most historical headers were imported via anonymous
calls and the list would dominate heap).

### 1.4 Hashes

Internally everything is in Bitcoin "internal" little-endian order
(what `dSHA256` produces and what the wire format uses). Big-endian
display hex is only produced at the API boundary.

---

## 2. Memory cost

Per-header cost in stable memory (from the
[HeaderDb.mo](src/block_explorer/HeaderDb.mo) comment):

| Component                       | Bytes |
| ------------------------------- | ----: |
| trie leaf (28-byte key + 76-byte value) |   104 |
| internal trie nodes (amortised) |    ~5 |
| root region (1 MB / N)          |    ~1 |
| canonical-chain slot            |     4 |
| **per canonical block**         |  **~114** |

Heap-side overhead (uploader bookkeeping, sibling/fork sets,
stable-trie node bookkeeping) is roughly proportional but dominated by
the stable side.

At ~900 K canonical Bitcoin headers, expect ~100 MB stable memory and
much less heap. Stable-trie `pointer_size = 4` caps the canister at
~2.1 B headers, well beyond any plausible use.

---

## 3. What is *not* stored

- No transactions (see `block_bodies` for the txid index — but even
  there, raw transaction data is not stored).
- No UTXO data.
- Big-endian (display) hashes are computed on demand, never stored.

---

## 4. `block_explorer` public API

Update calls:

- `push_header(raw_hex : Text)` — push a single 80-byte header.
- `push_headers(headers : [Blob])` / `push_headers_hex(headers_hex : [Text])`
  — batch push, stops at first error and reports `accepted` count.
  Capped at 10 000 per call.
- `import_next(max_batch : Nat)` — pull the next N headers from the
  IC's Bitcoin canister (`ghsi2-tqaaa-aaaan-aaaca-cai`). **Restricted**
  to the hardcoded `IMPORT_OPERATOR` principal in
  [src/block_explorer/main.mo](src/block_explorer/main.mo); change the constant and redeploy to
  rotate. Headers fetched this way are attributed to the anonymous
  principal (`2vxsx-fae`).
- `set_cycles_per_call(n : Nat)` — adjusts the cycle budget for the
  Bitcoin-canister outcall. Controller-only (`Principal.isController`);
  traps on unauthorized callers.

Query calls:

- `get_view(height : ?Nat)` — tip + total + forks + canonical block at
  height + all siblings at that height. One round trip for the
  frontend.
- `get_by_hash(hash_be_hex : Text)` — single-block lookup.
- `lookup_header(hash_internal : Blob)` — compact ref for
  `block_bodies` (`dbidx` + canonical merkle root).
- `have_hashes(hashes_be_hex : [Text])` — batched membership check
  (capped at 50 000). Used by `header_fetcher`'s walkback (10 hashes
  per batch) and by client-side push pre-filters.
- `uploader_leaderboard(top : Nat)` / `blocks_by_uploader(p, offset, limit)`.
- `header_db_memory_stats()` — stable-trie byte size + node/leaf
  counts.
- `cycles_balance()` / `get_cycles_per_call()`.

HTTP routes (via `http_request`):

- `GET /metrics` — Prometheus exposition.
- `GET /api/blocks/tip/{height,hash}`
- `GET /api/blocks` / `GET /api/blocks/:height` — 10 latest descending.
- `GET /api/block-height/:height` → canonical hash.
- `GET /api/block/:hash` / `:hash/header` / `:hash/status` — Esplora
  schema, omitting tx-related fields. Full route list and "not
  implemented" routes are in [src/block_explorer/Esplora.mo](src/block_explorer/Esplora.mo).

---

## 5. `block_bodies` design

See top-of-file comment in
[src/block_bodies/block_bodies.mo](src/block_bodies/block_bodies.mo).

### 5.1 Storage layout

Two stable structures:

- **`txidTrie`** — `mo:stable-trie` `Enumeration` with 32-byte keys
  (txids, internal LE order) and 4-byte values (the owning block's
  `dbidx`, Nat32 LE). `pointer_size = 5` caps the trie at 2³⁹
  (~550 B) total txids.
- **Body region** — one fixed 8-byte slot per `dbidx`, indexed dense
  by the explorer's `dbidx`. Slot encoding (LE Nat64):

  ```
  bits  0..23 : tx_count        (24 bits, max 16_777_215)
  bits 24..63 : first_txdbidx   (40 bits, max ~1 T)
  ```

  `tx_count == 0` means the slot is unset (every real Bitcoin block
  has at least the coinbase tx).

### 5.2 The representation trick

Naively storing block bodies would mean keeping every txid keyed by
`(block, position)` — many GB of redundant `(dbidx, position) →
txid` entries. Instead:

1. On `put_body(block_hash, tx_count, hashes)`, look up the header's
   `dbidx` from `block_explorer` and verify the supplied merkle root
   against the stored one ([src/block_bodies/Merkle.mo](src/block_bodies/Merkle.mo)).
2. Insert every txid into `txidTrie` *in block order, in one
   synchronous batch*. The trie's enumeration assigns consecutive
   `txdbidx`s — they're a global flat index across all txids ever
   inserted.
3. Persist only `(tx_count, first_txdbidx)` per block — **8 bytes**.
   Position `i` of block `dbidx` is then implicit:
   `txdbidx = first_txdbidx + i`.

That's ~8 bytes per block + ~36 bytes per txid (32-byte trie key +
4-byte value + amortised trie overhead), with no per-tx-position
overhead at all.

### 5.3 Lookups

Both directions, no extra indirection:

```motoko
// Forward: (block dbidx, position i) → txid
body    = bodies.get(dbidx)
txdbidx = body.first_txdbidx + i
txid    = txidTrie.get(txdbidx)

// Inverse: txid → (block dbidx, position within block)
(dbidx_blob, txdbidx) = txidTrie.lookup(txid)
dbidx                 = decodeNat32LE(dbidx_blob)
body                  = bodies.get(dbidx)
position              = txdbidx - body.first_txdbidx
```

### 5.4 Invariant

The consecutive-`txdbidx` property is what makes (3) safe. It's
enforced on insert at every position *i ≥ 1*: the txid must land at
`firstTxdbidx + i` or `put_body` rejects the upload.

### 5.5 BIP30 historical duplicates

Bitcoin has four blocks pre-BIP30 whose coinbase txid was reused
across two heights (91722/91880 and 91812/91842). All four are
**1-tx blocks** (only the coinbase). Because the invariant check
only runs for `i ≥ 1` and these have `tx_count == 1`, it never
fires for the real BIP30 cases.

What happens instead — by accident-on-purpose:

- The second-uploaded block's `txidTrie.add(coinbase)` returns the
  **existing** `txdbidx` and overwrites the stored block-`dbidx`
  value with the later block's. The trie does not grow.
- `bodies.put` stores `(1, existing_txdbidx)` for the later block;
  the earlier block still has its own slot pointing to the same
  `txdbidx`.
- `tx_at(either_block, 0)` returns the shared coinbase txid —
  **correct**, since both blocks really do have the same coinbase.
- `lookup_txid(coinbase)` returns the **later** block; the earlier
  block is unreachable via the inverse index for that one txid.

So forward lookups stay correct (the common explorer query) and
only the inverse direction loses the earlier of the pair. The
explicit `#err` branch in `put_body` is still load-bearing for any
hypothetical future block whose coinbase collides *and* has
additional non-coinbase txs.

---

## 6. `header_fetcher` design

See top-of-file comment in
[src/header_fetcher/header_fetcher.mo](src/header_fetcher/header_fetcher.mo). Every 30 seconds (alternating providers so each is hit ~once a minute), one
provider (round-robin between blockstream.info and mempool.space):

0. Call `<api>/blocks/tip/hash` — returns just the provider's tip
   hash (~65 B, ~50.8M cycles). If it matches `lastSeenTipHash`
   from the previous successful tick, the chain hasn't moved and
   the tick exits here. ~90% of 30-second ticks short-circuit at
   this step, saving ~85M cycles each vs running the full `/blocks`
   path.
1. Otherwise call `<api>/blocks` — returns up to 10 most recent
   blocks from the provider in descending order, each with `id`,
   `height`, and the rest of the header fields.
2. Pass all 10 hashes to `block_explorer.have_hashes` in one call
   (it accepts an arbitrary-length array). The highest known hash
   is the last common ancestor; everything above is queued for the
   forward push.
3. If none of the 10 are known, page back via
   `<api>/blocks/<lowestHeight - 1>` and repeat. Bounded by
   `MAX_BATCHES = 100` — up to 1000 blocks of walkback per tick.
4. Walk *forwards* from `common + 1` using the `BlockFields`
   already collected during steps 1–3. The `/blocks` response
   carries `version`, `previousblockhash`, `merkle_root`,
   `timestamp`, `bits` and `nonce`, so we reconstruct each
   canonical 80-byte raw header locally and ship the whole batch
   in **one** `push_headers_hex` call — **no `/block/<hash>/header`
   outcall per height**, and only **one inter-canister push call
   per tick** regardless of how many headers are caught up.
   Bounded by `MAX_FORWARD = 100` per tick (well below the
   explorer's `MAX_PUSH_BATCH = 10 000`).

The fetcher never asks the explorer for its tip: the provider's
`/blocks` tells us their tip, and `have_hashes` tells us where ours
connects. Each tick's only inter-canister calls are the `have_hashes`
per `/blocks` batch and the single `push_headers_hex` at the end.

Outcalls are non-replicated (`is_replicated = ?false`) to keep cycle
cost predictable. A 50-entry ring buffer records the per-stage outcome
of each tick; expose via `recent_logs(n)` / `status()`.

The JSON parser handles the Esplora-compatible `/api/blocks` shape
(flat objects). Brace-depth tracking + per-field marker search keeps
it robust against key reordering and unknown extra fields.

---

## 7. Persistence model

All three actors are `persistent actor`s with a single
`system func preupgrade()` that snapshots heap-side bookkeeping into a
stable variable. The stable-trie and `Region` parts persist
automatically; the `share()` / `unshare()` dance only exists to carry
the heap-side trie indexes across the upgrade boundary.

`block_explorer` initialises the genesis header in `initGenesis` if no
`chainData` snapshot is present. Genesis's uploader is the canister's
own principal, so `uploaderPrincipals[0]` is always populated before
any user push.

---

## 8. Prometheus metrics (`mo:promtracker` 1.0.1)

All three Motoko canisters expose Prometheus metrics. Two design
rules apply across them:

1. **Single source of truth per metric.** If a number is already
   maintained for the canister's own operation (size of a trie,
   tip height, etc.), a `PullValue` reads it on every scrape — the
   metric and any `status()` field read the same underlying state.
2. **Counter as source of truth for diagnostics.** If a number
   exists only to be observed (per-stage success/error counts,
   timestamps of the last tick), it lives in a promtracker
   `Counter`. The `status()` query reads it back via
   `Int.abs(counter.value)`.

### Where metrics are exposed

| Canister | Endpoint | Implementation |
|---|---|---|
| `block_explorer` | `GET /metrics` (via the Esplora `http_request`) | `Esplora.handle(chain, renderer.renderExposition, req)` |
| `block_bodies`   | `GET /metrics` (via `mo:promtracker/mixins/http`) | `include Http(renderer.renderExposition, "/metrics")` |
| `header_fetcher` | `GET /metrics` (via `mo:promtracker/mixins/http`) | `include Http(renderer.renderExposition, "/metrics")` |

System metrics (`cycles_balance`, `rts_memory_size`, `rts_heap_size`,
`canister_version`, …) are added by `renderer.addValue(PT.allSystemMetrics)`
in each actor. Each canister also calls `renderer.addCanisterLabel(self)`
so every metric carries a `canister="<principal>"` label.

### `block_explorer` metrics

PullValues only (no Tracker — the canister has no diagnostic counters
of its own):

- `headers_total` — `chain.size()`
- `tip_height` — `chain.tipHeight()`
- `fork_count` — `chain.forks().size()`
- `uploader_count` — `chain.uploaderStats().size()`
- `header_db_byte_size` / `_leaf_count` / `_node_count` — from
  `chain.memoryStats()`

### `block_bodies` metrics

PullValues only:

- `indexed_txids` — `txidTrie.size()`
- `txid_trie_byte_size` / `_leaf_count` / `_node_count`
- `body_region_byte_size` — bytes of stable memory in the body region
- `body_capacity_blocks` — slot count

### `header_fetcher` metrics

A persistent `Tracker` (`pt`) owns the diagnostic counters; `status()`
reads back from it. The tracker is registered with the renderer via
`renderer.addValue(pt.toValue())`.

Cumulative event counters (added via `PT.Counter.add(c, 1)`):

- `ticks_total` — tick handler invocations actually run (skipped
  ticks are *not* counted here)
- `ticks_skipped_total` — ticks that found `tickInFlight = true`
  and bailed
- `stage_blocks_ok_total` / `stage_blocks_err_total`
- `stage_header_ok_total` / `stage_header_err_total`
- `stage_push_ok_total` / `stage_push_err_total`

"Last value" registers (set via `PT.Counter.set(c, n)` each tick):

- `last_tick_at_ns` — `Time.now()` of the most recent tick body
- `last_success_at_ns` — `Time.now()` of the last successful tick
- `last_provider_tip` — height of the provider's tip seen most recently
- `last_fetched_height` — highest height we pushed to `block_explorer`

Plus log-buffer PullValues `log_total` and `log_capacity`.

### Code references

- `.agents/skills/promtracker/SKILL.md` — upstream usage guide.
- `.agents/skills/promtracker/NOTES.md` — local learnings (dot-notation
  needs `import Tracker`, `Counter.value` is `Int`, 0.10.0→1.0.1 migration
  table, etc.).
