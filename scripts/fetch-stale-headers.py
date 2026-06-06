#!/usr/bin/env python3
"""
Scrape stale-block headers from https://bitcoin-data.github.io/stale-blocks/
and write them to a flat binary file in the same format as Electrum's
`blockchain_headers` (concatenated 80-byte raw block headers).

Each row on the page has a "details" dropdown that contains, among other
fields, a `hex` field with the 80-byte raw header serialised as 160 hex
characters. We extract the hex of every row that has one, verify it matches
the displayed hash (`dSHA256(header)` reversed == hash), and append the raw
80 bytes to the output file.

Usage:
    scripts/fetch-stale-headers.py [--out PATH] [--url URL]

Default output: `stale_headers` in the current working directory (does not
overwrite the existing `blockchain_headers` file).
"""

import argparse
import hashlib
import re
import sys
import urllib.request

URL = "https://bitcoin-data.github.io/stale-blocks/"
HEADER_HEX_LEN = 160  # 80 bytes


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "stale-headers/1.0"})
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode("utf-8")


def extract_entries(html):
    """Yield (hash_hex_be, hex_header) tuples for every detail block.

    Each detail block looks roughly like:

        <span class="text-gray-500">hash</span>  <span ...>HASH</span>
        ... other fields ...
        <span class="text-gray-500">hex</span>   <span ...>HEX</span>
    """
    # Split on each "hash" label so we process one detail block at a time.
    # The first chunk is the header of the page; skip it.
    chunks = re.split(r'<span[^>]*>\s*hash\s*</span>', html)
    hash_re = re.compile(r'>\s*([0-9a-fA-F]{64})\s*<', re.DOTALL)
    hex_re = re.compile(
        r'<span[^>]*>\s*hex\s*</span>\s*<span[^>]*>\s*([0-9a-fA-F]{' +
        str(HEADER_HEX_LEN) + r'})\s*</span>',
        re.DOTALL,
    )

    for chunk in chunks[1:]:
        h = hash_re.search(chunk)
        x = hex_re.search(chunk)
        if not h or not x:
            continue
        yield h.group(1).lower(), x.group(1).lower()


def dsha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="stale_headers",
                    help="output file path (default: stale_headers)")
    ap.add_argument("--url", default=URL, help="source URL")
    ap.add_argument("--manifest", default=None,
                    help="optional CSV (index,hash) manifest path")
    args = ap.parse_args()

    print(f"Fetching {args.url} ...", flush=True)
    html = fetch(args.url)

    raw_headers = []
    bad = 0
    for hash_be, hex_header in extract_entries(html):
        raw = bytes.fromhex(hex_header)
        if len(raw) != 80:
            bad += 1
            continue
        # Verify: dSHA256(header) reversed == displayed hash
        computed = dsha256(raw)[::-1].hex()
        if computed != hash_be:
            sys.stderr.write(
                f"warning: hash mismatch for entry {len(raw_headers)}: "
                f"page={hash_be} computed={computed}\n"
            )
            bad += 1
            continue
        raw_headers.append((hash_be, raw))

    if not raw_headers:
        sys.exit("no headers extracted")

    with open(args.out, "wb") as f:
        for _, raw in raw_headers:
            f.write(raw)

    print(f"Wrote {len(raw_headers)} headers ({len(raw_headers) * 80} bytes) "
          f"to {args.out}")
    if bad:
        print(f"Skipped {bad} malformed entries.")

    if args.manifest:
        with open(args.manifest, "w") as f:
            f.write("index,hash\n")
            for i, (h, _) in enumerate(raw_headers):
                f.write(f"{i},{h}\n")
        print(f"Wrote manifest to {args.manifest}")


if __name__ == "__main__":
    main()
