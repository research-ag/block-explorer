# Deployed snapshot (IC mainnet)

Record of what is **currently live**, so a future `Memory-incompatible program
upgrade` trap can be diagnosed by diffing the stable signature. Update this on
every deploy (the git history of this directory is the deploy log).

| field | value |
|---|---|
| commit | `b9019905ee17e98e5fc734a91ab6d0977959cef8` (`b901990`, PR #14) |
| date | 2026-11-23 |
| canister upgraded | block_explorer only (header_fetcher and frontend unchanged) |
| module hash | `0x4132d2fb2be7e1995bab4694e7ff53727e0a37a671dd760b4f8537f21bf07052` |
| moc | 2.2.4 (core 2.7.0) |
| moc flags | `--max-stable-pages 2097152` (128 GiB) — block_explorer only |
| block_explorer | `5alk6-kyaaa-aaaag-ay2sq-cai` |
| header_fetcher | `5hkmk-haaaa-aaaag-ay2sa-cai` |
| frontend (assets) | `5jibc-4qaaa-aaaag-ay2ta-cai` |

> Stable layout is **unchanged** from the previous deploy (`7e21ac0`, the
> same day, module hash `0x717dc835…661a`): `block_explorer.most` is
> byte-identical, no migration. That deploy ran a one-off migration
> (`Migration.mo`, removed since): `chunkHashers` became
> `chunkTree : Peaks.Peaks`, and the verifier of a chunked upload in
> progress became a `Chunks.Verifier` on that tree.

## Dependency versions baked into the stable layout

- `stable-trie` 0.2.0: the two tries (`headerTrie`, `txTrie`) persist *as*
  this package's stable type. An earlier bump of it changed the trie's
  on-disk layout and caused a `Memory-incompatible program upgrade` trap.
  Bump it only with a migration plan.
- `mmr` (GitHub, pinned commit): `chunkTree` is a `Peaks.Peaks` and the
  verifier of an upload in progress a `Chunks.Verifier`. mmr declares these
  shapes part of its interface and lists a change to one as "Breaking (stored
  state)" in its CHANGELOG: check that before bumping it.
- `sha2` 0.3.3: its `Hasher` (`[var Nat16]` of length 16) sits inside
  `Peaks.Peaks`, so its representation is part of the stable layout too.
- `heaviest-chain` (`./packages/heaviest-chain`): `forks` persists as its
  `ForkStore`.

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
