#!/usr/bin/env bash
# Fetch blocks 101..91840 from mempool.space one at a time and push
# each to the `block_bodies` canister via scripts/push-block-body.py.
# Aborts on the first failure.
#
# Usage:
#   scripts/backfill-block-bodies.sh [START] [END] [--env ENV] [--keep]
#
# Defaults: START=101, END=91840 (the block before the first BIP30
# duplicate-coinbase pair at heights 91842/91880; the consecutive-
# txdbidx invariant in block_bodies would refuse those).
#
# Files are written to ./blocks/N.raw and removed after a successful
# push unless --keep is given.

set -euo pipefail

START=101
END=91840
ENV_ARG=()
KEEP=0

POS=()
while (( $# > 0 )); do
  case "$1" in
    --env)  ENV_ARG=(--env "$2"); shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help)
      echo "usage: $0 [START] [END] [--env ENV] [--keep]" >&2
      exit 0 ;;
    --) shift; while (( $# > 0 )); do POS+=("$1"); shift; done ;;
    -*) echo "unknown arg: $1" >&2; exit 2 ;;
    *)  POS+=("$1"); shift ;;
  esac
done

if (( ${#POS[@]} >= 1 )); then START=${POS[0]}; fi
if (( ${#POS[@]} >= 2 )); then END=${POS[1]}; fi

mkdir -p blocks
CURSOR=blocks/.cursor

# Resume: if a cursor exists and the user didn't override START on
# the command line, pick up at cursor+1.
if (( ${#POS[@]} == 0 )) && [[ -f $CURSOR ]]; then
  LAST=$(<"$CURSOR")
  if [[ $LAST =~ ^[0-9]+$ ]] && (( LAST + 1 > START )); then
    START=$(( LAST + 1 ))
    echo "resuming from block $START (cursor at $LAST)"
  fi
fi

fetch_block() {
  local N=$1
  local HASH
  HASH=$(curl -fsSL "https://mempool.space/api/block-height/$N")
  if [[ -z "$HASH" ]]; then
    echo "fetch_block($N): empty hash from mempool.space" >&2
    return 1
  fi
  curl -fsSL "https://mempool.space/api/block/$HASH/raw" -o "blocks/$N.raw"
}

push_block() {
  local N=$1
  scripts/push-block-body.py "blocks/$N.raw" ${ENV_ARG[@]+"${ENV_ARG[@]}"}
}

for (( N=START; N<=END; N++ )); do
  echo "=== block $N ==="
  fetch_block "$N"
  push_block "$N"
  echo "$N" > "$CURSOR"
  if (( ! KEEP )); then
    rm -f "blocks/$N.raw"
  fi
done

echo "done: pushed blocks $START..$END"
