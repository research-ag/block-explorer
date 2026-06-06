#!/usr/bin/env python3
"""
Push the next N block headers from an Electrum `blockchain_headers` file
to the BlockExplorer canister, in batches via `push_headers_hex`.

Usage:
    scripts/push-headers.py N [--canister NAME] [--env ENV] [--batch SIZE]
                              [--file PATH]

The script:
 1. Queries the canister for its current tip height (via `get_view`).
 2. Reads headers [tip+1 .. tip+N] (each 80 bytes) from the file.
 3. Sends them in batches of `--batch` (default 1000) to push_headers_hex.
 4. Stops if the canister rejects a header.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

HEADER_SIZE = 80
DEFAULT_BATCH = 1000
MAX_BATCH = 10_000  # must match MAX_PUSH_BATCH in src/block_explorer/main.mo


def run_icp(args, capture=True):
    """Invoke `icp` with the given argument list."""
    try:
        result = subprocess.run(
            ["icp"] + args,
            check=True,
            capture_output=capture,
            text=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        sys.stderr.write(
            f"icp {' '.join(args)} failed (exit {e.returncode})\n"
            f"stderr:\n{e.stderr}\n"
        )
        sys.exit(1)


def parse_nat(text):
    """Strip Candid `_` thousand separators and return int."""
    return int(text.replace("_", ""))


def query_tip_height(canister, env):
    """Call get_view(null) and extract tip.height from Candid output."""
    args = ["canister", "call", canister, "get_view", "(null)", "--query"]
    if env:
        args += ["-e", env]
    out = run_icp(args)
    # Output structure starts with `tip = record { height = N : nat; ... }`.
    # Match the first `height = ... : nat` after `tip = record`.
    m = re.search(
        r"tip\s*=\s*record\s*\{[^}]*?height\s*=\s*([\d_]+)\s*:\s*nat",
        out,
        re.DOTALL,
    )
    if not m:
        sys.stderr.write("Could not parse tip height from get_view output:\n")
        sys.stderr.write(out)
        sys.exit(1)
    return parse_nat(m.group(1))


def read_headers(path, start, count):
    """Read `count` 80-byte headers starting at index `start`."""
    file_size = os.path.getsize(path)
    total = file_size // HEADER_SIZE
    if start >= total:
        return []
    end = min(start + count, total)
    with open(path, "rb") as f:
        f.seek(start * HEADER_SIZE)
        data = f.read((end - start) * HEADER_SIZE)
    return [data[i * HEADER_SIZE : (i + 1) * HEADER_SIZE] for i in range(end - start)]


def push_batch(canister, env, headers_hex):
    """Send one batch via push_headers_hex; return (accepted, last_error)."""
    # Build Candid arg: (vec { "hex1"; "hex2"; ... })
    inner = "; ".join(f'"{h}"' for h in headers_hex)
    arg = f"(vec {{ {inner} }})"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".did", delete=False
    ) as tmp:
        tmp.write(arg)
        tmp_path = tmp.name
    try:
        args = [
            "canister", "call", canister, "push_headers_hex",
            "--args-file", tmp_path,
        ]
        if env:
            args += ["-e", env]
        out = run_icp(args)
    finally:
        os.unlink(tmp_path)

    # Expected output:
    #   (variant { ok = record { accepted = N : nat; ...; last_error = opt "..." or null } })
    # or:
    #   (variant { err = "..." })
    err_m = re.search(r'variant\s*\{\s*err\s*=\s*"([^"]*)"', out)
    if err_m:
        return 0, err_m.group(1)
    acc_m = re.search(r"accepted\s*=\s*([\d_]+)\s*:\s*nat", out)
    if not acc_m:
        sys.stderr.write("Could not parse push_headers_hex output:\n" + out)
        sys.exit(1)
    accepted = parse_nat(acc_m.group(1))
    last_err = None
    le_m = re.search(r'last_error\s*=\s*opt\s*"([^"]*)"', out)
    if le_m:
        last_err = le_m.group(1)
    return accepted, last_err


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("n", type=int, help="number of headers to push")
    ap.add_argument("--canister", default="block_explorer")
    ap.add_argument(
        "--env",
        default="ic",
        help="icp environment (default 'ic' = mainnet; use 'local' for replica)",
    )
    ap.add_argument(
        "--batch", type=int, default=DEFAULT_BATCH,
        help=f"batch size per push_headers_hex call (max {MAX_BATCH}, "
             f"default {DEFAULT_BATCH})",
    )
    ap.add_argument(
        "--file", default="blockchain_headers",
        help="path to Electrum blockchain_headers file",
    )
    args = ap.parse_args()

    if args.n <= 0:
        sys.exit("N must be positive")
    if args.batch <= 0 or args.batch > MAX_BATCH:
        sys.exit(f"--batch must be in 1..{MAX_BATCH}")
    if not os.path.isfile(args.file):
        sys.exit(f"file not found: {args.file}")

    file_total = os.path.getsize(args.file) // HEADER_SIZE
    print(f"File   : {args.file}  ({file_total} headers)")

    tip = query_tip_height(args.canister, args.env)
    print(f"Tip    : {tip}")

    start_idx = tip + 1                # next height to push
    target    = start_idx + args.n     # exclusive
    if start_idx >= file_total:
        print("Nothing to do: tip is already at or beyond end of file.")
        return
    if target > file_total:
        target = file_total
        print(f"Capping at end of file: pushing {target - start_idx} headers.")

    pushed = 0
    cursor = start_idx
    while cursor < target:
        n = min(args.batch, target - cursor)
        headers = read_headers(args.file, cursor, n)
        if not headers:
            break
        headers_hex = [h.hex() for h in headers]
        print(f"  pushing heights {cursor}..{cursor + len(headers) - 1} "
              f"({len(headers)} headers) ...", end=" ", flush=True)
        accepted, err = push_batch(args.canister, args.env, headers_hex)
        print(f"accepted={accepted}"
              + (f"  err={err}" if err else ""))
        pushed += accepted
        cursor += accepted
        if accepted < len(headers) or err:
            print(f"Stopping after {pushed} accepted headers.")
            sys.exit(1 if err else 0)

    print(f"Done. {pushed} headers pushed. New tip should be {cursor - 1}.")


if __name__ == "__main__":
    main()
