#!/usr/bin/env python3
"""
coinbase-backfill.py

Walks canonical heights from the canister's `coinbase_backfill_cursor` to
its canonical tip, pulls each block's raw coinbase tx (witness-stripped)
from a local Bitcoin Core node, and pushes them to the block_explorer
canister via `push_coinbases_backfill`. After the one-time catchup, polls
every POLL_INTERVAL seconds and backfills freshly-canonical blocks as the
body-uploader indexes them.

State lives entirely on the canister (cursor, region_bytes, canonical_tip
exposed by `coinbase_backfill_status`), so this script has no local state
file: on restart it re-queries the cursor and continues. Idempotent — a
crash mid-batch is harmless, the canister tracks exactly what was
accepted.

The canister verifies each coinbase against the body-side state:
  1. coinbase.size() > 64                       (depth-of-tree binding)
  2. dSHA(coinbase) == first_txid at that height (so the body-uploader
                                                   must have indexed the
                                                   block body first)
  3. startHeight == coinbase_backfill_cursor    (strict height ordering)
A per-call result `#ok({accepted = i})` tells us how many got in; if
0 accepted at a height whose body isn't indexed yet, we back off and
retry on the next poll.

Env vars (shown with defaults):
    BTC_RPC_HOST=127.0.0.1
    BTC_RPC_PORT=8332
    BTC_RPC_USER=bitcoin
    BTC_RPC_PASSWORD=changeme
    IC_URL=https://icp0.io
    CANISTER_ID=                      # required
    IDENTITY_PEM=                     # path; anonymous if unset
    BATCH_SIZE=500                    # heights per push_coinbases_backfill call
    POLL_INTERVAL=60                  # seconds between catchup iterations
    ONCE=0                            # 1 = exit after one pass (no polling)

Requirements:
    pip install python-bitcoinrpc ic-py
"""

from __future__ import annotations

import binascii
import logging
import os
import signal
import struct
import sys
import threading
import time
from typing import List, Optional, Tuple

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

from ic.agent import Agent
from ic.candid import Types, encode, decode
from ic.client import Client
from ic.identity import Identity

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BTC_RPC_HOST     = os.getenv("BTC_RPC_HOST",     "127.0.0.1")
BTC_RPC_PORT     = int(os.getenv("BTC_RPC_PORT", "8332"))
BTC_RPC_USER     = os.getenv("BTC_RPC_USER",     "bitcoin")
BTC_RPC_PASSWORD = os.getenv("BTC_RPC_PASSWORD", "changeme")

IC_URL           = os.getenv("IC_URL",      "https://icp0.io")
CANISTER_ID      = os.getenv("CANISTER_ID")
if not CANISTER_ID:
    sys.exit("CANISTER_ID env var is required")
IDENTITY_PEM     = os.getenv("IDENTITY_PEM")

BATCH_SIZE       = int(os.getenv("BATCH_SIZE",    "500"))
POLL_INTERVAL    = float(os.getenv("POLL_INTERVAL", "60"))
ONCE             = os.getenv("ONCE", "0") == "1"

# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("coinbase_backfill")

_shutdown = threading.Event()


def _handle_signal(signum, _frame):
    log.info("Signal %s received, shutting down...", signum)
    _shutdown.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Candid schemas (hand-mirrored from src/block_explorer/main.mo).
# ---------------------------------------------------------------------------

CoinbaseBackfillStatusType = Types.Record({
    "cursor":        Types.Nat,
    "canonical_tip": Types.Nat,
    "region_bytes":  Types.Nat64,
    "complete":      Types.Bool,
})

PushCoinbasesOkType = Types.Record({
    "accepted": Types.Nat,
})

PushCoinbasesReturnType = Types.Variant({
    "ok":  PushCoinbasesOkType,
    "err": Types.Text,
})


# ---------------------------------------------------------------------------
# Bitcoin RPC
# ---------------------------------------------------------------------------

def make_rpc() -> AuthServiceProxy:
    url = f"http://{BTC_RPC_USER}:{BTC_RPC_PASSWORD}@{BTC_RPC_HOST}:{BTC_RPC_PORT}"
    return AuthServiceProxy(url, timeout=60)


def fetch_raw_block(rpc: AuthServiceProxy, height: int) -> bytes:
    """getblockhash(h) + getblock(hash, 0): the full raw block (header +
    tx_count varint + concatenated raw transactions WITH witnesses)."""
    hash_hex = rpc.getblockhash(height)
    hex_blob = rpc.getblock(hash_hex, 0)
    return binascii.unhexlify(hex_blob)


# ---------------------------------------------------------------------------
# Coinbase parsing (witness-stripped first tx).
# ---------------------------------------------------------------------------
#
# Pull the first tx out of a raw block and serialize it in its "legacy"
# (pre-BIP141) form, which is what dSHA'es to the real txid. The canister
# compares the dSHA of the uploaded bytes against the body-side first
# txid, so witness bytes MUST be stripped.

def _read_varint(buf: bytes, off: int) -> Tuple[int, int]:
    first = buf[off]
    if first < 0xFD:
        return first, off + 1
    if first == 0xFD:
        return struct.unpack_from("<H", buf, off + 1)[0], off + 3
    if first == 0xFE:
        return struct.unpack_from("<I", buf, off + 1)[0], off + 5
    return struct.unpack_from("<Q", buf, off + 1)[0], off + 9


def extract_coinbase(block_bytes: bytes) -> bytes:
    """Return the first transaction's witness-stripped serialization."""
    if len(block_bytes) < 81:
        raise ValueError(f"block too short: {len(block_bytes)} bytes")
    # Skip the 80-byte header and the tx_count varint.
    _tx_count, off = _read_varint(block_bytes, 80)
    start = off

    version = block_bytes[off:off + 4]
    off += 4

    # Detect segwit marker + flag (coinbase in a segwit block carries the
    # witness commitment reserved value, so this branch is the common case).
    is_segwit = block_bytes[off] == 0x00 and block_bytes[off + 1] != 0x00
    if is_segwit:
        off += 2

    vin_start = off
    vin_count, off = _read_varint(block_bytes, off)
    for _ in range(vin_count):
        off += 32 + 4                           # prev txid + vout index
        scr_len, off = _read_varint(block_bytes, off)
        off += scr_len
        off += 4                                # sequence
    vin_bytes = block_bytes[vin_start:off]

    vout_start = off
    vout_count, off = _read_varint(block_bytes, off)
    for _ in range(vout_count):
        off += 8                                # amount
        scr_len, off = _read_varint(block_bytes, off)
        off += scr_len
    vout_bytes = block_bytes[vout_start:off]

    if is_segwit:
        for _ in range(vin_count):
            stack_size, off = _read_varint(block_bytes, off)
            for _ in range(stack_size):
                item_len, off = _read_varint(block_bytes, off)
                off += item_len

    locktime = block_bytes[off:off + 4]
    # off += 4 — remaining bytes are the rest of the block's txs,
    # which we don't care about.
    _ = start  # kept to document the parse origin; unused in output

    return version + vin_bytes + vout_bytes + locktime


# ---------------------------------------------------------------------------
# Canister client
# ---------------------------------------------------------------------------

class CanisterClient:
    def __init__(self) -> None:
        if IDENTITY_PEM:
            with open(IDENTITY_PEM, "r") as f:
                identity = Identity.from_pem(f.read())
            log.info("Identity from %s (principal=%s)",
                     IDENTITY_PEM, identity.sender().to_str())
        else:
            identity = Identity()
            log.info("Anonymous identity")
        self.agent = Agent(identity, Client(url=IC_URL))

    # ------------------------------------------------------------------
    def status(self) -> dict:
        """Query. `coinbase_backfill_status : () -> (...) query`."""
        result = self.agent.query_raw(
            CANISTER_ID, "coinbase_backfill_status", encode([]),
            return_type=CoinbaseBackfillStatusType,
        )
        if not result or "value" not in result[0]:
            raise RuntimeError(f"Unexpected status reply: {result!r}")
        v = result[0]["value"]
        return {
            "cursor":        int(v["cursor"]),
            "canonical_tip": int(v["canonical_tip"]),
            "region_bytes":  int(v["region_bytes"]),
            "complete":      bool(v["complete"]),
        }

    # ------------------------------------------------------------------
    def push_coinbases(self, start_height: int, coinbases: List[bytes]) -> int:
        """Update. `push_coinbases_backfill : (nat, vec blob) -> variant {...}`.
        Returns `accepted` from `#ok`; raises on `#err`."""
        params = [
            {"type": Types.Nat, "value": start_height},
            {"type": Types.Vec(Types.Vec(Types.Nat8)),
             "value": [list(cb) for cb in coinbases]},
        ]
        result = self.agent.update_raw(
            CANISTER_ID, "push_coinbases_backfill", encode(params),
            return_type=PushCoinbasesReturnType,
        )
        if not result or "value" not in result[0]:
            raise RuntimeError(f"Unexpected push reply: {result!r}")
        v = result[0]["value"]
        if "ok" in v:
            return int(v["ok"]["accepted"])
        if "err" in v:
            raise RuntimeError(f"Canister rejected batch: {v['err']}")
        raise RuntimeError(f"Unexpected push variant: {v!r}")


# ---------------------------------------------------------------------------
# Backfill loop
# ---------------------------------------------------------------------------

def run_once(canister: CanisterClient) -> int:
    """Pull one batch starting from the current cursor and push it.
    Returns how many heights were accepted in the push call (0 if nothing
    to do, or if the body-uploader hasn't indexed the next height yet)."""
    status = canister.status()
    cursor, tip = status["cursor"], status["canonical_tip"]
    log.info("status: cursor=%d canonical_tip=%d region_bytes=%d complete=%s",
             cursor, tip, status["region_bytes"], status["complete"])

    if status["complete"] or cursor > tip:
        return 0
    batch_end = min(cursor + BATCH_SIZE, tip + 1)
    n = batch_end - cursor
    if n <= 0:
        return 0

    rpc = make_rpc()
    coinbases: List[bytes] = []
    for h in range(cursor, batch_end):
        if _shutdown.is_set():
            break
        try:
            raw = fetch_raw_block(rpc, h)
            cb = extract_coinbase(raw)
        except Exception as e:
            log.error("height %d: failed to fetch/parse coinbase: %s", h, e)
            # Return what we have — the push will stop before this height.
            break
        if len(cb) <= 64:
            log.error("height %d: coinbase %d bytes (<= 64, depth-pin fails) — stopping",
                      h, len(cb))
            break
        coinbases.append(cb)

    if not coinbases:
        return 0

    log.info("pushing %d coinbases starting at height %d (bytes: %d..%d)",
             len(coinbases), cursor,
             min(len(c) for c in coinbases),
             max(len(c) for c in coinbases))
    accepted = canister.push_coinbases(cursor, coinbases)
    if accepted < len(coinbases):
        log.warning("canister accepted %d / %d — stopping batch at height %d",
                    accepted, len(coinbases), cursor + accepted)
    else:
        log.info("accepted %d / %d (cursor now %d)",
                 accepted, len(coinbases), cursor + accepted)
    return accepted


def main() -> None:
    log.info(
        "coinbase-backfill: bitcoind=%s:%d canister=%s batch=%d poll=%ss once=%s",
        BTC_RPC_HOST, BTC_RPC_PORT, CANISTER_ID, BATCH_SIZE, POLL_INTERVAL, ONCE,
    )
    canister = CanisterClient()
    while not _shutdown.is_set():
        try:
            accepted = run_once(canister)
        except JSONRPCException as e:
            log.error("bitcoin RPC error: %s — retrying after %ss", e, POLL_INTERVAL)
            accepted = 0
        except Exception as e:
            log.exception("iteration failed: %s — retrying after %ss", e, POLL_INTERVAL)
            accepted = 0

        if ONCE:
            return
        # When we're making progress (accepted > 0) and not caught up to
        # the canister's tip yet, loop immediately for the next batch.
        # Otherwise sleep and let bitcoind / the body-uploader catch up.
        if accepted >= BATCH_SIZE:
            continue
        _shutdown.wait(POLL_INTERVAL)


if __name__ == "__main__":
    main()
