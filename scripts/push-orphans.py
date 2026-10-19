#!/usr/bin/env python3
"""
Push orphan/stale block headers from a flat 80-byte-per-header file
(e.g. the `stale_headers` file produced by `fetch-stale-headers.py`)
to the BlockExplorer canister via `push_headers`.

Unlike `push-headers.py`, this script does NOT seek into the file based on
the canister's tip height. Each header is independent and the canister
validates that each header's parent already exists. Headers are read
sequentially from `--offset` onward and sent in batches.

Usage:
    scripts/push-orphans.py [--file PATH] [--offset N] [--count N]
                            [--canister NAME] [--env ENV] [--batch SIZE]

The canister will reject any header whose parent it does not know. By
default the script logs such rejections, skips the offending header, and
keeps going so that out-of-order orphans whose parent shows up later in
the file can still land. Use `--stop-on-error` for the old behaviour.
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile

HEADER_SIZE = 80
DEFAULT_BATCH = 1000
MAX_BATCH = 10_000  # must match MAX_PUSH_BATCH in src/block_explorer/main.mo
ONE_YEAR_SECS = 365 * 24 * 60 * 60


def run_icp(args):
    try:
        result = subprocess.run(
            ["icp"] + args,
            check=True,
            capture_output=True,
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
    return int(text.replace("_", ""))


def header_hash_be(raw):
    """Bitcoin sha256d of an 80-byte header, returned as big-endian hex."""
    h = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return h[::-1].hex()


def header_prev_hash_be(raw):
    """Extract the 'previous block hash' field (bytes 4..36, little-endian
    in the wire format) and return it as big-endian hex — the same form
    the canister expects in get_by_hash / have_hashes."""
    return raw[4:36][::-1].hex()


def is_present(canister, env, hash_be):
    """Query get_by_hash; True if the canister already has this header."""
    args = [
        "canister", "call", canister, "get_by_hash",
        f'("{hash_be}")', "--query",
    ]
    if env:
        args += ["-e", env]
    out = run_icp(args)
    # Returns `(opt record { ... })` if present, `(null)` if not.
    return "opt record" in out


def get_tip_time(canister, env):
    """Return the canister tip's Bitcoin header timestamp (unix seconds)."""
    args = [
        "canister", "call", canister, "get_view",
        "(null)", "--query",
    ]
    if env:
        args += ["-e", env]
    out = run_icp(args)
    # Look for `tip = record { ... time = NNN : nat32 ... }`. The first
    # `time = ... : nat32` in the output belongs to the tip record.
    m = re.search(r"time\s*=\s*([\d_]+)\s*:\s*nat32", out)
    if not m:
        sys.stderr.write("Could not parse tip time from get_view output:\n" + out)
        sys.exit(1)
    return parse_nat(m.group(1))


def have_hashes(canister, env, hashes_be):
    """Batched membership check via the canister's `have_hashes` query.
    Returns a list of bools in the same order as the input."""
    if not hashes_be:
        return []
    inner = "; ".join(f'"{h}"' for h in hashes_be)
    arg = f"(vec {{ {inner} }})"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".did", delete=False
    ) as tmp:
        tmp.write(arg)
        tmp_path = tmp.name
    try:
        args = [
            "canister", "call", canister, "have_hashes",
            "--args-file", tmp_path, "--query",
        ]
        if env:
            args += ["-e", env]
        out = run_icp(args)
    finally:
        os.unlink(tmp_path)

    # Output looks like: `(vec { true; false; true; ... })`
    bools = re.findall(r"\b(true|false)\b", out)
    if len(bools) != len(hashes_be):
        sys.stderr.write(
            f"have_hashes: expected {len(hashes_be)} bools, got {len(bools)}\n"
            f"output:\n{out}\n"
        )
        sys.exit(1)
    return [b == "true" for b in bools]


def candid_blob(raw):
    """Candid text-format blob literal for raw bytes."""
    return 'blob "' + "".join(f"\\{b:02x}" for b in raw) + '"'


def push_batch(canister, env, headers_raw):
    """Send one batch via push_headers (raw blobs); return (accepted, last_error)."""
    inner = "; ".join(candid_blob(h) for h in headers_raw)
    arg = f"(vec {{ {inner} }})"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".did", delete=False
    ) as tmp:
        tmp.write(arg)
        tmp_path = tmp.name
    try:
        args = [
            "canister", "call", canister, "push_headers",
            "--args-file", tmp_path,
        ]
        if env:
            args += ["-e", env]
        out = run_icp(args)
    finally:
        os.unlink(tmp_path)

    err_m = re.search(r'variant\s*\{\s*err\s*=\s*"([^"]*)"', out)
    if err_m:
        return 0, err_m.group(1)
    acc_m = re.search(r"accepted\s*=\s*([\d_]+)\s*:\s*nat", out)
    if not acc_m:
        sys.stderr.write("Could not parse push_headers output:\n" + out)
        sys.exit(1)
    accepted = parse_nat(acc_m.group(1))
    last_err = None
    le_m = re.search(r'last_error\s*=\s*opt\s*"([^"]*)"', out)
    if le_m:
        last_err = le_m.group(1)
    return accepted, last_err


def header_timestamp(raw):
    """Bitcoin header timestamp (bytes 68..72, little-endian uint32)."""
    return int.from_bytes(raw[68:72], "little")


def describe_header(raw, file_index=None):
    ts = header_timestamp(raw)
    return (
        f"file_index={file_index}"
        f" hash={header_hash_be(raw)}"
        f" prev={header_prev_hash_be(raw)}"
        f" timestamp={ts}"
        f" raw_hex={raw.hex()}"
    )


def read_headers(path, start, count):
    """Read up to `count` 80-byte headers starting at index `start`."""
    file_size = os.path.getsize(path)
    total = file_size // HEADER_SIZE
    if start >= total:
        return []
    end = min(start + count, total)
    with open(path, "rb") as f:
        f.seek(start * HEADER_SIZE)
        data = f.read((end - start) * HEADER_SIZE)
    return [data[i * HEADER_SIZE : (i + 1) * HEADER_SIZE] for i in range(end - start)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", default="stale_headers",
                    help="path to flat 80-byte-per-header file")
    ap.add_argument("--offset", type=int, default=0,
                    help="header index to start from (default 0)")
    ap.add_argument("--count", type=int, default=None,
                    help="max headers to push (default: until end of file)")
    ap.add_argument("--canister", default="block_explorer")
    ap.add_argument("--env", default="ic",
                    help="icp environment (default 'ic'; use 'local' for replica)")
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH,
                    help=f"batch size per call (max {MAX_BATCH}, default {DEFAULT_BATCH})")
    ap.add_argument("--stop-on-error", action="store_true",
                    help="stop on first rejected header instead of skipping")
    ap.add_argument("--no-prefilter", action="store_true",
                    help="skip the have_hashes pre-filter and just push everything")
    args = ap.parse_args()

    if args.batch <= 0 or args.batch > MAX_BATCH:
        sys.exit(f"--batch must be in 1..{MAX_BATCH}")
    if args.offset < 0:
        sys.exit("--offset must be >= 0")
    if not os.path.isfile(args.file):
        sys.exit(f"file not found: {args.file}")

    file_total = os.path.getsize(args.file) // HEADER_SIZE
    print(f"File   : {args.file}  ({file_total} headers)")

    if args.offset >= file_total:
        sys.exit(f"--offset {args.offset} is at or beyond end of file ({file_total})")

    tip_time = get_tip_time(args.canister, args.env)
    cutoff = tip_time - ONE_YEAR_SECS
    print(f"Tip    : timestamp={tip_time}  cutoff={cutoff} (1 year before tip)")

    remaining = file_total - args.offset
    if args.count is not None:
        remaining = min(remaining, args.count)
    target = args.offset + remaining
    print(f"Range  : [{args.offset}..{target - 1}]  ({remaining} headers)")

    grand_accepted = 0
    grand_rejected = 0
    grand_dups = 0
    grand_orphans = 0
    grand_validation_errors = 0
    grand_too_old = 0
    cursor = args.offset
    while cursor < target:
        n = min(args.batch, target - cursor)
        headers = read_headers(args.file, cursor, n)
        if not headers:
            break
        batch_lo, batch_hi = cursor, cursor + len(headers) - 1
        # Map each header in this batch back to its position in the file
        # so error messages can name a specific file_index. Drop any
        # header older than 1 year before the canister's current tip.
        indexed = []
        too_old = 0
        for i, raw in enumerate(headers, start=batch_lo):
            if header_timestamp(raw) < cutoff:
                too_old += 1
                continue
            indexed.append((i, raw))
        grand_too_old += too_old
        print(f"  [{batch_lo}..{batch_hi}] ({len(headers)} headers,"
              f" {len(indexed)} within 1y, {too_old} skipped as too old)")
        if not indexed:
            cursor = batch_hi + 1
            continue

        accepted, rejected, dups, orphans, validation_errs = drain_batch(
            args, indexed,
        )
        grand_accepted += accepted
        grand_rejected += rejected
        grand_dups += dups
        grand_orphans += orphans
        grand_validation_errors += validation_errs

        cursor = batch_hi + 1

    print(f"Done. accepted={grand_accepted}"
          f" rejected={grand_rejected}"
          f" skipped_duplicates={grand_dups}"
          f" skipped_orphans={grand_orphans}"
          f" skipped_too_old={grand_too_old}"
          f" validation_errors={grand_validation_errors}")


def drain_batch(args, indexed):
    """Iteratively push everything pushable in this batch.

    `indexed` is a list of (file_index, raw_header) tuples.

    Each iteration:
      1. Query have_hashes for every (still-pending header + its prev).
      2. Split into duplicates / orphans / pushable.
      3. push_headers the pushable subset.
      4. If push errors out partway, print full details for the
         offending header (so the user can isolate it), then drop it
         from pending so the iteration can make progress.
      5. Loop again. Orphans whose parents were just pushed will be
         picked up; orphans whose parents are *not* in this batch
         eventually stop shrinking and are reported as skipped.

    Returns (accepted, rejected, dups, final_orphans, validation_errors).
    """
    accepted_total = 0
    rejected_total = 0
    dup_total = 0
    validation_errs = 0

    pending = list(indexed)
    iter_no = 0
    while pending:
        iter_no += 1
        if args.no_prefilter:
            to_push = pending
            local_dups = 0
            orphans = []
        else:
            self_hashes = [header_hash_be(raw) for _, raw in pending]
            prev_hashes = [header_prev_hash_be(raw) for _, raw in pending]
            present = have_hashes(
                args.canister, args.env, self_hashes + prev_hashes,
            )
            self_present = present[: len(pending)]
            prev_present = present[len(pending) :]

            known = set(
                self_hashes[i] for i in range(len(pending)) if self_present[i]
            )
            for i, ok in enumerate(prev_present):
                if ok:
                    known.add(prev_hashes[i])

            to_push = []
            local_dups = 0
            orphans = []
            for i, item in enumerate(pending):
                if self_present[i]:
                    local_dups += 1
                    continue
                if prev_hashes[i] not in known:
                    orphans.append(item)
                    continue
                to_push.append(item)
                known.add(self_hashes[i])

            dup_total += local_dups

        # Stop conditions for this batch's retry loop.
        if not to_push:
            # Either everything left is a true orphan, or all dups.
            if orphans:
                print(f"    iter {iter_no}: nothing pushable "
                      f"(dup={local_dups} orphan={len(orphans)}); giving up")
            return (accepted_total, rejected_total, dup_total,
                    len(orphans), validation_errs)

        accepted, err = push_batch(args.canister, args.env, [raw for _, raw in to_push])
        accepted_total += accepted
        suffix = (f"iter {iter_no}: pushed={len(to_push)} accepted={accepted}"
                  f" dup={local_dups} orphan={len(orphans)}")
        if err:
            suffix += f"  err={err}"
        print(f"    {suffix}")

        if err is None and accepted == len(to_push):
            # All accepted. Retry orphans (their parents may have just landed).
            pending = orphans
            continue

        if err and err.startswith("heap limit reached"):
            # Retryable: the canister paused the batch to bound heap growth;
            # to_push[accepted] was NOT rejected. Re-queue everything
            # unprocessed and go around again.
            pending = list(to_push[accepted:]) + orphans
            continue

        # Partial / total failure. The canister stops at the first bad
        # header in the batch, so to_push[accepted] is the offender.
        offender_idx, offender_raw = to_push[accepted]
        rejected_total += 1
        validation_errs += 1
        print(f"    REJECTED  err={err}")
        print(f"      {describe_header(offender_raw, offender_idx)}")
        if "median-time-past" in (err or "") or "timestamp" in (err or "").lower():
            print(f"      hint: extract this single header for inspection with:")
            print(f"        dd if={args.file} bs={HEADER_SIZE} "
                  f"skip={offender_idx} count=1 of=bad_header.bin")

        if args.stop_on_error:
            print(f"Stopping after {accepted_total} accepted.")
            sys.exit(1)

        # Drop the offender; keep the rest of to_push that the canister
        # didn't reach (they're still candidates), plus the orphans.
        pending = list(to_push[accepted + 1 :]) + orphans

    return accepted_total, rejected_total, dup_total, 0, validation_errs


if __name__ == "__main__":
    main()
