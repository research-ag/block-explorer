# heaviest-chain

Fork-choice for heaviest-chain protocols, over an ABSTRACT canonical chain.
The algorithm knows about heights, tips, forks and weights — never about
storage or block representation. Works for any chain whose blocks are
identified by hashes (Blob) and ordered by cumulative weight (most work,
most stake, ...).

## Modules

### `ForkStore`

Generic store of non-canonical blocks: `ForkStore<B>` keeps `id -> B` plus a
`height -> [id]` sibling index. `B` is fully opaque — callers pass id and
height explicitly (`add(store, id, height, b)`), so the record is plain
stable data with zero embedded functions.

### `Reorg`

`maybeReorg(forks, accessors, canonical, hooks, newTipId, newWeight, tipWeight)`

The caller's world in two small records:

- `Accessors<B>` — `id`, `parent`, `height`: the only three things the
  algorithm knows about a block. Any payload riding on `B` flows through
  demotion and promotion untouched.
- `Canonical<B>` — the abstract canonical chain: `tipHeight`, `idAt(h)`,
  `append(b)` (make a fork block canonical: persist, update caches, ...),
  `demoteTip()` (remove the tip and return it as a `B`, carrying whatever
  should survive into the fork set).

Procedure: weigh (`newWeight <= tipWeight` -> null) -> find the common
ancestor (walking the branch tip-down; a branch block's parent is canonical
iff the canonical id at `height - 1` matches — an index compare, no search)
-> `hooks.beforeRollback(commonHeight)` (doomed canonical blocks still
readable) -> demote each canonical block above the ancestor into the fork
store -> `hooks.afterRollback()` -> promote the branch ancestor-first
(remove from forks, append). Returns
`{ commonHeight; displaced; promoted }`.

## Embedding pattern

Keep the common fast path (new block extends the canonical tip) outside the
package; call `maybeReorg` only when a fork branch may have become heavier.
Hang storage-specific work on the callbacks: payload extraction in
`beforeRollback`, cache rebuilds in `afterRollback`, encode/persist in
`append`, decode/carry in `demoteTip`.
