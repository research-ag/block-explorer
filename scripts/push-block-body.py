#!/usr/bin/env python3
"""
Parse a raw Bitcoin block from disk and submit its transaction-id list
to the `block_explorer` canister via `push_body`.

A body may be submitted only once all of the block's ancestor bodies are
known (so its first-tx serial number is determined): canonical bodies in
strict height order (query `bodies_next_height` for the next expected
height), and a fork block's body only after its parent's body. It is
verified against the block's merkle root.

Usage:
    scripts/push-block-body.py PATH [--canister NAME] [--env ENV]

Where PATH is a file containing the block in the standard p2p
serialization (80-byte header + varint tx_count + concatenated raw
transactions, including witness data if present).

The script does, locally:
  1. Read the file.
  2. Parse the 80-byte header.
  3. Compute the header hash (double-SHA256, internal LE).
  4. Walk the transactions and compute each TXID
     (double-SHA256 of the *non-witness* serialization — i.e. with
     marker/flag and witness fields stripped, per BIP141).
  5. Submit (header_hash, tx_count, concatenated_txids) to
     `block_explorer.push_body`.

No network access; segwit-aware.
"""

import argparse
import hashlib
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Bitcoin parsing primitives.
# ---------------------------------------------------------------------------

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def read_varint(buf: bytes, off: int):
    """Return (value, new_offset)."""
    first = buf[off]
    if first < 0xFD:
        return first, off + 1
    if first == 0xFD:
        return struct.unpack_from("<H", buf, off + 1)[0], off + 3
    if first == 0xFE:
        return struct.unpack_from("<I", buf, off + 1)[0], off + 5
    return struct.unpack_from("<Q", buf, off + 1)[0], off + 9


def parse_tx(buf: bytes, off: int):
    """
    Parse one transaction starting at `off`. Returns (txid, new_offset).

    `txid` is sha256d of the legacy (non-witness) serialization, in
    Bitcoin's internal little-endian byte order (32 bytes).
    """
    start = off
    version = buf[off:off + 4]
    off += 4

    # Detect segwit marker+flag.
    marker = buf[off]
    flag = buf[off + 1]
    is_segwit = marker == 0x00 and flag != 0x00
    if is_segwit:
        off += 2  # skip marker + flag

    # vin (include the count varint in the legacy serialization)
    vin_start = off
    vin_count, off = read_varint(buf, off)
    for _ in range(vin_count):
        off += 32 + 4                        # prevout (txid + vout)
        scr_len, off = read_varint(buf, off)
        off += scr_len
        off += 4                              # sequence
    vin_bytes = buf[vin_start:off]

    # vout
    vout_start = off
    vout_count, off = read_varint(buf, off)
    for _ in range(vout_count):
        off += 8                              # value
        scr_len, off = read_varint(buf, off)
        off += scr_len
    vout_bytes = buf[vout_start:off]

    # witness (skipped for txid; consumed only to advance offset)
    if is_segwit:
        for _ in range(vin_count):
            stack_size, off = read_varint(buf, off)
            for _ in range(stack_size):
                item_len, off = read_varint(buf, off)
                off += item_len

    locktime = buf[off:off + 4]
    off += 4

    # Build legacy (non-witness) serialization for the txid hash.
    legacy = version + vin_bytes + vout_bytes + locktime
    txid = sha256d(legacy)
    return txid, off


def parse_block(blob: bytes):
    """Return (header_hash_internal_le, txids_blob, tx_count)."""
    if len(blob) < 81:
        sys.exit(f"file too small: {len(blob)} bytes")
    header = blob[:80]
    header_hash = sha256d(header)  # internal LE

    tx_count, off = read_varint(blob, 80)
    if tx_count == 0:
        sys.exit("invalid block: tx_count == 0")
    txids = bytearray()
    for _ in range(tx_count):
        txid, off = parse_tx(blob, off)
        txids.extend(txid)
    if off != len(blob):
        sys.stderr.write(
            f"warning: trailing bytes after last tx ({len(blob) - off})\n"
        )
    return bytes(header_hash), bytes(txids), tx_count


# ---------------------------------------------------------------------------
# Candid encoding.
# ---------------------------------------------------------------------------

def candid_blob(b: bytes) -> str:
    """Encode bytes as a Candid `blob` literal: blob "\\xx\\xx...\""."""
    return 'blob "' + "".join(f"\\{byte:02x}" for byte in b) + '"'


def call_put_body(canister: str, env: str | None,
                  header_hash: bytes, tx_count: int, txids: bytes):
    arg = f"({candid_blob(header_hash)}, {tx_count} : nat, {candid_blob(txids)})"
    # `icp canister call` only accepts --args-file, not --args, and
    # the arg blob can be megabytes for large blocks anyway.
    with tempfile.NamedTemporaryFile("w", suffix=".did", delete=False) as f:
        f.write(arg)
        args_file = f.name
    try:
        args = ["icp", "canister", "call", canister, "push_body",
                "--args-file", args_file]
        if env:
            args += ["-e", env]
        res = subprocess.run(args, capture_output=True, text=True)
        sys.stdout.write(res.stdout)
        if res.returncode != 0:
            sys.stderr.write(res.stderr)
            sys.exit(res.returncode)
    finally:
        Path(args_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="Path to raw block file (header + txs).")
    ap.add_argument("--canister", default="block_explorer",
                    help="Canister name or id (default: block_explorer)")
    ap.add_argument("--env", default=None,
                    help="icp environment (e.g. local, ic). Defaults to icp's current env.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Parse and print summary; don't submit.")
    args = ap.parse_args()

    path = Path(args.path)
    blob = path.read_bytes()
    header_hash, txids, tx_count = parse_block(blob)

    # Display: BE hex (i.e. reversed) for header hash + first/last txid.
    header_be = header_hash[::-1].hex()
    first_txid_be = txids[:32][::-1].hex()
    last_txid_be = txids[-32:][::-1].hex()
    print(f"file:        {path} ({len(blob)} bytes)")
    print(f"header hash: {header_be}")
    print(f"tx_count:    {tx_count}")
    print(f"first txid:  {first_txid_be}")
    print(f"last txid:   {last_txid_be}")
    print(f"txids blob:  {len(txids)} bytes ({tx_count} * 32)")

    if args.dry_run:
        return
    call_put_body(args.canister, args.env, header_hash, tx_count, txids)


if __name__ == "__main__":
    main()
