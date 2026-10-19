# Deployed snapshot (IC mainnet)

Record of what is **currently live**, so a future `Memory-incompatible program
upgrade` trap can be diagnosed by diffing the stable signature. Update this on
every deploy (the git history of this directory is the deploy log).

| field | value |
|---|---|
| commit | `571ddf7f27ef8ac795100651affa7df8ad50f8cd` (`571ddf7`) |
| date | 2026-06-15 |
| moc | 1.7.0 |
| moc flags | `--max-stable-pages 2097152` (128 GiB) — block_explorer only |
| block_explorer | `5alk6-kyaaa-aaaag-ay2sq-cai` |
| header_fetcher | `5hkmk-haaaa-aaaag-ay2sa-cai` |
| frontend (assets) | `5jibc-4qaaa-aaaag-ay2ta-cai` |

> Stable layout is **unchanged** from the previous deploy (`a1bc103`): both
> `.most` files are byte-identical. The only difference is the
> `--max-stable-pages` flag (a runtime growth cap, not a stable type), which
> raised the txid trie's ceiling from 4 GiB to 128 GiB.

## Dependency versions baked into the stable layout

- `sha2` — vendored fork `./packages/sha2` (0.2.1 + reset-fix + word-level
  primitives). `sha` is `transient`, so this does NOT affect stable memory.
- **`stable-trie` — `#main`, resolved to v0.1.4. ⚠️ FLOATING.** This is the one
  that matters: the two tries (`headerTrie`, `txTrie`) persist *as* this
  package's stable type. `#main` is a moving ref with NO pinned commit in
  mops.lock — a previous deploy ran an older stable-trie, and bumping to 0.1.4
  changed the trie's on-disk layout, which is what caused the
  `Memory-incompatible program upgrade` trap before this snapshot. **Pin
  stable-trie to a fixed commit and bump it only with a migration plan.**

## Files

- `block_explorer.most` — stable signature of the deployed block_explorer build.
- `header_fetcher.most` — stable signature of the deployed header_fetcher build.

## Using these on a future upgrade trap

Build the new candidate's `.most` and diff it against the deployed one — moc
names the exact incompatible field/type:

```sh
export PATH="$(dirname "$(mops toolchain bin moc)"):$PATH"   # ensure node v22 for mops
MOC=$(mops toolchain bin moc); SRC=$(mops sources)
$MOC ${SRC} --stable-types -o /tmp/new.wasm src/block_explorer/main.mo   # -> /tmp/new.most
$MOC --stable-compatible deployed/block_explorer.most /tmp/new.most       # exit 0 = upgrade is safe
```

If incompatible: either make the new code compatible (e.g. re-pin stable-trie
to the deployed commit), write a migration, or reinstall + re-sync (the
explorer's state is fully derivable from Bitcoin — headers via push-headers.py,
bodies via the body-uploader after resetting its local state file).
