#!/usr/bin/env python3
"""
watch-headers.py

Watches a local Bitcoin Core node for new block headers and pushes any
headers the block_explorer canister does not already have, as a single
batch, starting from the most recent common ancestor.

Flow on every trigger (ZMQ notification or poll-fallback tick):
  1. Read bitcoind tip.
  2. Walk backwards from the tip collecting the last LOOKBACK hashes.
  3. Ask the canister `have_hashes(vec text) -> vec bool` (query call,
     free).
  4. The first `true` (scanning newest -> oldest) is the common ancestor.
     Everything newer than it must be pushed.
  5. If no hash is known, double the lookback window and retry, up to
     MAX_LOOKBACK. (Protects against deep reorgs / fresh canisters.)
  6. Fetch the 80-byte headers for the missing range and send them as
     one `push_headers(vec blob) -> Result<BatchPushResult, Text>`
     update call.

Canister Candid surface used (see src/block_explorer/main.mo for full
definitions):

  type BlockInfo       = record { height : nat; ... };
  type ChainView       = record { tip : BlockInfo; ... };
  type BatchPushResult = record {
    accepted   : nat;       // headers newly stored
    tip_height : nat;
    last_error : opt text;  // first failure that stopped the batch
  };
  service : {
    have_hashes  : (vec text) -> (vec bool) query;        // BE-hex hashes
    push_headers : (vec blob) -> (variant { Ok : BatchPushResult;
                                            Err : text });
    get_view     : (opt nat) -> (ChainView) query;        // for logging
  }

Requirements:
    pip install python-bitcoinrpc pyzmq ic-py

bitcoin.conf:
    server=1
    rpcuser=<user>
    rpcpassword=<password>
    zmqpubhashblock=tcp://127.0.0.1:28332
"""

from __future__ import annotations

import binascii
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

import zmq
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

from ic.agent import Agent, sign_request
from ic.client import Client
from ic.identity import Identity
from ic.candid import encode, decode, Types
from ic.principal import Principal

# ---------------------------------------------------------------------------
# Candid schemas
#
# Hand-mirrored from src/block_explorer/main.mo. Keep these in sync with
# the canister's type declarations; if a field is added there, add it
# here and ic-py will decode it with the real name (otherwise it'd come
# back as a `_<hash>` key). Field order is irrelevant — Candid is
# name-keyed; both sides hash the field names.
# ---------------------------------------------------------------------------

BlockInfoType = Types.Record({
    "height": Types.Nat,
    "version": Types.Nat32,
    "prev_hash_be_hex": Types.Text,
    "merkle_root_be_hex": Types.Text,
    "time": Types.Nat32,
    "bits": Types.Nat32,
    "nonce": Types.Nat32,
    "hash_be_hex": Types.Text,
    "difficulty_x1e8": Types.Nat,
    "cum_work": Types.Nat,
    "is_canonical": Types.Bool,
    "first_seen": Types.Nat32,
    "uploader": Types.Principal,
})

BatchPushResultType = Types.Record({
    "accepted": Types.Nat,
    "tip_height": Types.Nat,
    "last_error": Types.Opt(Types.Text),
})

PushHeadersReturnType = Types.Variant({
    "ok": BatchPushResultType,
    "err": Types.Text,
})

HaveHashesReturnType = Types.Vec(Types.Bool)

ForkType = Types.Record({
    "tip_height": Types.Nat,
    "tip_hash_be_hex": Types.Text,
    "length": Types.Nat,
    "branch_height": Types.Nat,
    "branch_hash_be_hex": Types.Text,
})

ChainViewType = Types.Record({
    "tip": BlockInfoType,
    "total_blocks": Types.Nat,
    "forks": Types.Vec(ForkType),
    "block": Types.Opt(BlockInfoType),
    "siblings": Types.Vec(BlockInfoType),
})

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BTC_RPC_USER     = os.getenv("BTC_RPC_USER",     "bitcoin")
BTC_RPC_PASSWORD = os.getenv("BTC_RPC_PASSWORD", "changeme")
BTC_RPC_HOST     = os.getenv("BTC_RPC_HOST",     "127.0.0.1")
BTC_RPC_PORT     = int(os.getenv("BTC_RPC_PORT", "8332"))

ZMQ_ENDPOINT     = os.getenv("ZMQ_ENDPOINT",     "tcp://127.0.0.1:28332")
POLL_INTERVAL    = float(os.getenv("POLL_INTERVAL", "30"))

IC_URL           = os.getenv("IC_URL",      "https://icp0.io")
CANISTER_ID      = os.getenv("CANISTER_ID", "aaaaa-aa")
IDENTITY_PEM     = os.getenv("IDENTITY_PEM")

# How far back to look on each trigger. Doubles up to MAX_LOOKBACK if the
# canister doesn't know any of the hashes we asked about.
LOOKBACK         = int(os.getenv("LOOKBACK",     "10"))
MAX_LOOKBACK     = int(os.getenv("MAX_LOOKBACK", "2000"))

# Max headers per push_headers call. Tune to canister ingress / message limits.
BATCH_SIZE       = int(os.getenv("BATCH_SIZE", "500"))

# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("push_headers")

_shutdown = threading.Event()


def _handle_signal(signum, _frame):
    log.info("Signal %s received, shutting down...", signum)
    _shutdown.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Bitcoin RPC
# ---------------------------------------------------------------------------

def make_rpc() -> AuthServiceProxy:
    url = f"http://{BTC_RPC_USER}:{BTC_RPC_PASSWORD}@{BTC_RPC_HOST}:{BTC_RPC_PORT}"
    return AuthServiceProxy(url, timeout=30)


@dataclass
class HeaderRecord:
    height: int
    hash_hex: str           # big-endian (display) hex as bitcoind returns it.
                            # This is the form `have_hashes` expects.
    raw_header: bytes       # 80 bytes; filled on demand for push_headers


def fetch_tip_height() -> int:
    return int(make_rpc().getblockcount())


def fetch_recent_hashes(tip_height: int, count: int) -> List[HeaderRecord]:
    """Return up to `count` records ending at `tip_height`, ordered
    OLDEST -> NEWEST (ascending height). raw_header is empty until
    fetched separately."""
    rpc = make_rpc()
    start = max(0, tip_height - count + 1)
    out: List[HeaderRecord] = []
    for h in range(start, tip_height + 1):
        hash_hex = rpc.getblockhash(h)
        out.append(HeaderRecord(
            height=h,
            hash_hex=hash_hex,
            raw_header=b"",
        ))
    return out


def fetch_header_bytes(hash_hex: str) -> bytes:
    """80-byte serialized header."""
    return binascii.unhexlify(make_rpc().getblockheader(hash_hex, False))


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
        self.canister_id = CANISTER_ID

    # ------------------------------------------------------------------
    def _query(self, method_name: str, encoded_arg: bytes, return_type=None):
        """Replacement for ic-py 1.0.1's broken `agent.query_raw`,
        which uses `type(x) != dict` instead of `isinstance(x, dict)`
        and so rejects the frozendict response shape used by modern
        IC subnets (subnet-signed queries). We replicate query_raw's
        signing + endpoint call, then decode the reply ourselves with
        the supplied Candid `return_type` so field/variant names come
        back as strings rather than `_<hash>` keys."""
        cid = self.canister_id
        cid_bytes = (
            Principal.from_str(cid).bytes
            if isinstance(cid, str) else cid.bytes
        )
        req = {
            "request_type": "query",
            "sender": self.agent.identity.sender().bytes,
            "canister_id": cid_bytes,
            "method_name": method_name,
            "arg": encoded_arg,
            "ingress_expiry": self.agent.get_expiry_date(),
        }
        _, data = sign_request(req, self.agent.identity)
        result = self.agent.query_endpoint(cid, data)
        status = result.get("status") if hasattr(result, "get") else None
        if status == "replied":
            return decode(result["reply"]["arg"], return_type)
        if status == "rejected":
            raise RuntimeError(
                f"IC rejected query {method_name}: "
                f"{result.get('reject_message') or result!r}"
            )
        raise RuntimeError(f"Unexpected IC reply: {result!r}")

    # ------------------------------------------------------------------
    def have_hashes(self, hashes_be_hex: List[str]) -> List[bool]:
        """Query call. `have_hashes : (vec text) -> (vec bool) query`.
        Hashes are BE display hex (the form bitcoind / Esplora return).
        Returns one bool per input hash, same order."""
        params = [{
            "type": Types.Vec(Types.Text),
            "value": hashes_be_hex,
        }]
        result = self._query(
            "have_hashes", encode(params), return_type=HaveHashesReturnType,
        )
        if not result or "value" not in result[0]:
            raise RuntimeError(f"Unexpected have_hashes reply: {result!r}")
        return [bool(b) for b in result[0]["value"]]

    # ------------------------------------------------------------------
    def push_headers(self, records: List[HeaderRecord]) -> dict:
        """Update call. `push_headers : (vec blob) -> Result<BatchPushResult, text>`.
        Sends a flat list of 80-byte raw headers, in chain order.
        Returns the BatchPushResult dict {accepted, new_tip, last_error}
        on success; raises on canister-side #err."""
        params = [{
            "type": Types.Vec(Types.Vec(Types.Nat8)),  # vec blob
            "value": [list(r.raw_header) for r in records],
        }]
        result = self.agent.update_raw(
            self.canister_id, "push_headers", encode(params),
            return_type=PushHeadersReturnType,
        )
        if not result or "value" not in result[0]:
            raise RuntimeError(f"Unexpected push_headers reply: {result!r}")
        v = result[0]["value"]
        if "ok" in v:
            return v["ok"]
        if "err" in v:
            raise RuntimeError(f"Canister rejected batch: {v['err']!r}")
        raise RuntimeError(f"Unexpected push_headers variant: {v!r}")

    # ------------------------------------------------------------------
    def get_tip_height(self) -> Optional[int]:
        """Query the canister's canonical tip height via `get_view(null)`.
        Best-effort — used only for logging."""
        try:
            params = [{"type": Types.Opt(Types.Nat), "value": []}]
            result = self._query(
                "get_view", encode(params), return_type=ChainViewType,
            )
            if result and "value" in result[0]:
                return int(result[0]["value"]["tip"]["height"])
        except Exception as e:
            log.debug("get_view unavailable: %s", e)
        return None


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------

class HeaderPusher:
    def __init__(self, canister: CanisterClient) -> None:
        self.canister = canister
        self._lock = threading.Lock()  # serialize sync() calls

    # ------------------------------------------------------------------
    def _find_missing(self, tip_height: int) -> Optional[List[HeaderRecord]]:
        """
        Walk backwards from `tip_height` asking the canister `have_hashes`
        until we find a known hash. Return the records ABOVE the ancestor
        (ascending order) that the canister doesn't have. Return [] if
        nothing to do. Return None if even MAX_LOOKBACK didn't find an
        ancestor.
        """
        lookback = LOOKBACK
        while True:
            recent = fetch_recent_hashes(tip_height, lookback)
            if not recent:
                return []

            known = self.canister.have_hashes([r.hash_hex for r in recent])
            if len(known) != len(recent):
                raise RuntimeError(
                    f"have_hashes returned {len(known)} bools for "
                    f"{len(recent)} hashes"
                )

            # Scan newest -> oldest; first True is the common ancestor.
            ancestor_idx: Optional[int] = None
            for i in range(len(recent) - 1, -1, -1):
                if known[i]:
                    ancestor_idx = i
                    break

            if ancestor_idx is not None:
                missing = recent[ancestor_idx + 1:]
                if missing:
                    log.info(
                        "Common ancestor at height %d (%s); %d header(s) to push",
                        recent[ancestor_idx].height,
                        recent[ancestor_idx].hash_hex,
                        len(missing),
                    )
                else:
                    log.debug("Canister already has tip %d", tip_height)
                return missing

            # Window also fully contained the genesis block but canister
            # still has nothing -- treat the whole window as missing.
            if recent[0].height == 0:
                log.info("Canister appears empty; pushing from genesis")
                return recent

            if lookback >= MAX_LOOKBACK:
                return None

            log.warning(
                "Canister knows none of the last %d hashes; widening lookback",
                lookback,
            )
            lookback = min(lookback * 2, MAX_LOOKBACK)

    # ------------------------------------------------------------------
    def sync(self) -> None:
        """Bring the canister up to bitcoind's current tip."""
        if not self._lock.acquire(blocking=False):
            # Another sync is already running; it will pick up the new tip.
            return
        try:
            tip = fetch_tip_height()
            missing = self._find_missing(tip)

            if missing is None:
                log.error(
                    "Canister diverges by more than MAX_LOOKBACK=%d blocks; "
                    "manual intervention required.", MAX_LOOKBACK,
                )
                return

            if not missing:
                return

            # Fetch the 80-byte headers we actually need to send.
            for rec in missing:
                rec.raw_header = fetch_header_bytes(rec.hash_hex)

            # Send in batches. push_headers returns a BatchPushResult
            # with `accepted` and `last_error`; if last_error is set,
            # the canister stopped the batch mid-way (e.g. a header
            # with an unknown parent), so don't push the next slice.
            for i in range(0, len(missing), BATCH_SIZE):
                batch = missing[i:i + BATCH_SIZE]
                res = self.canister.push_headers(batch)
                accepted = int(res.get("accepted", 0))
                # last_error is Opt<Text>: ic-py decodes ?T as a 0/1-element
                # list ([] = null, [val] = ?val).
                last_error_opt = res.get("last_error")
                last_error = (
                    last_error_opt[0]
                    if isinstance(last_error_opt, (list, tuple)) and last_error_opt
                    else None
                )
                log.info(
                    "Pushed batch: heights %d..%d, accepted=%d/%d%s",
                    batch[0].height, batch[-1].height,
                    accepted, len(batch),
                    f", last_error={last_error}" if last_error else "",
                )
                if last_error:
                    log.error("Canister halted batch: %s", last_error)
                    return
        except JSONRPCException as e:
            log.error("bitcoind RPC error during sync: %s", e)
        except Exception as e:
            log.exception("sync() failed: %s", e)
        finally:
            self._lock.release()


# ---------------------------------------------------------------------------
# ZMQ subscriber + poll fallback
# ---------------------------------------------------------------------------

def zmq_loop(pusher: HeaderPusher) -> None:
    ctx = zmq.Context()
    socket = ctx.socket(zmq.SUB)
    socket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
    socket.setsockopt(zmq.RCVTIMEO, int(POLL_INTERVAL * 1000))
    socket.connect(ZMQ_ENDPOINT)
    log.info("Subscribed to ZMQ at %s", ZMQ_ENDPOINT)

    while not _shutdown.is_set():
        try:
            topic, body, _seq = socket.recv_multipart()
        except zmq.Again:
            # Timed out -> opportunistic poll in case we missed a notification.
            pusher.sync()
            continue
        except zmq.ZMQError as e:
            log.error("ZMQ error: %s -- reconnecting in 5s", e)
            time.sleep(5)
            continue

        if topic == b"hashblock":
            log.info("ZMQ hashblock: %s", body.hex())
            pusher.sync()

    socket.close(0)
    ctx.term()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    log.info("push_headers starting")
    log.info("bitcoind = %s:%d, canister = %s",
             BTC_RPC_HOST, BTC_RPC_PORT, CANISTER_ID)

    canister = CanisterClient()
    pusher = HeaderPusher(canister)

    # Initial sync (covers anything missed while offline, including reorgs).
    pusher.sync()

    try:
        zmq_loop(pusher)
    except Exception as e:
        log.exception("ZMQ loop crashed: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
