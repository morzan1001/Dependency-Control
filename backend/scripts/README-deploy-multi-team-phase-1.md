# Deploy runbook — multi-team projects Phase 1

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

## 1. Build the index before the deploy

`create_indexes` runs in the startup path, so a build there stalls the rollout. Build it by hand
first; the startup call then finds it and is a no-op.

### 1a. Check for pre-existing indexes

```js
db.projects.getIndexes()
```

If an index on `team_ids` already exists under a non-default name (anything other than
`team_ids_1`), **drop it** first:

```js
db.projects.dropIndex("old_index_name")
```

Startup cannot fix this for you and will not stop for it. MongoDB refuses to redefine an index that
already exists under that name, answers `IndexKeySpecsConflict` (code 86), and the guard in
`create_indexes` logs the skip and continues. The wrong index survives and the deployment succeeds,
but team-scoped queries will collection-scan 742 projects instead of using the index.

### 1b. Build the index

Do **not** pass a `name`. Omitting it gives the index the same default name `create_index` would
generate (`team_ids_1`). Under a custom name the key exists twice as far as MongoDB is concerned:
startup's build answers `IndexOptionsConflict` (code 85) and logs a skip on every pod start — a
permanent alarm over a healthy index.

```js
db.projects.createIndex({ team_ids: 1 })
```

Verify the resulting index name is `team_ids_1`:

```js
db.projects.getIndexes() | grep -i team_ids
```

The output must show `team_ids_1` exactly, with no custom name or options. The first pod of the
rollout logs no index skip.

## 2. Deploy Phase 1-4 code

Deploy the revision that includes:
- The `team_ids` field on projects (Phase 1)
- The multikey index (this step)
- The backfill migration script (Phase 2)
- Analytics and queries using `team_ids` (Phases 3-4)

## 3. Run the dry-run backfill

From an `exec` pod shell (or equivalent pod access):

```bash
python -m scripts.backfill_project_team_ids
```

Record the `projects planned` count. This run does not write anything — it only reports how many
projects would be updated from the scalar `team_id` to the derived list `team_ids`.

## 4. Execute the backfill

```bash
python -m scripts.backfill_project_team_ids --execute
```

Record the `projects matched` count.

## 5. Verify completion

```js
db.projects.countDocuments({ team_ids: { $exists: false } })
```

This must return 0, confirming every project now carries a `team_ids` list. Projects without a
team carry an empty list `[]`.

## 6. Migration is idempotent

The backfill derives `team_ids` from the scalar `team_id` every run. It is safe to re-run for
verification, but once writers own the list (Phase 5 removes the scalar field), the migration must
not be re-run — the derivation assumes the scalar is authoritative.

## 7. Phase 5 removes the scalar

When `team_id` is dropped, the `team_id` index is also dropped. The `team_ids` index remains
permanent, as the multikey index enables team-scoped queries for all team-membership feature.
