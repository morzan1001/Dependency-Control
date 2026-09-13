# Deploy runbook — team binding for GitLab as well as GitHub

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

`PUT /teams/{id}/gitlab-binding` is a second writer of `(gitlab_instance_id, gitlab_group_id)`, the
pair GitLab team sync has written on its own until now. Two teams holding one pair make a project's
owner ambiguous, so the pair has to be unique before the endpoint is reachable.

## 1. Verify the unique index — it is not new

`teams.(gitlab_instance_id, gitlab_group_id)` has been part of `create_indexes` since 2026-06-01,
so an installation that has started a pod since then already has it. Confirm rather than assume:
the build is guarded, and a failed build only logs.

```js
db.teams.getIndexes()
```

Expect `gitlab_instance_id_1_gitlab_group_id_1`, `unique: true`, and exactly

```js
partialFilterExpression: {
  gitlab_instance_id: { $type: "string" },
  gitlab_group_id:    { $type: "int" }
}
```

If it is listed that way, there is nothing to do — skip to section 2.

### 1a. If it is missing, or carries a different filter

A different `partialFilterExpression` under that name cannot be fixed by a restart: MongoDB refuses
to redefine an existing index name, answers `IndexOptionsConflict` (code 85), and the guard in
`create_indexes` logs the skip and carries on. Drop it first.

```js
db.teams.dropIndex("gitlab_instance_id_1_gitlab_group_id_1")
```

Then check for duplicates, because the build fails on any. This must return nothing:

```js
db.teams.aggregate([
  { $match: { gitlab_group_id: { $type: "int" } } },
  { $group: { _id: { i: "$gitlab_instance_id", g: "$gitlab_group_id" }, n: { $sum: 1 } } },
  { $match: { n: { $gt: 1 } } }
])
```

Build it **without a `name`**. Omitting it reproduces the default name `create_index` generates; under
a custom name the key exists twice as far as MongoDB is concerned and every pod start logs a skip for
a healthy index.

```js
db.teams.createIndex(
  { gitlab_instance_id: 1, gitlab_group_id: 1 },
  { unique: true,
    partialFilterExpression: {
      gitlab_instance_id: { $type: "string" },
      gitlab_group_id:    { $type: "int" }
    } }
)
```

`$type` rather than `$exists`: every team document carries an explicit `gitlab_group_id: null`, which
`$exists: true` matches, so the second manual team would fail with
`E11000 … dup key: { gitlab_instance_id: null, gitlab_group_id: null }`.

Verify with `db.teams.getIndexes()` and confirm the first pod of the rollout logs no index skip.

## 2. No backfill

`gitlab_group_path` is written by the binding endpoint and restamped by every team sync, so synced
teams fill it in on their next ingest. Until then the dialog shows the group by its number, which is
what the binding is stored on either way.

## 3. Bind in the UI

Teams → the team's link button (needs `system:manage`) → **Provider: GitLab** → pick the instance,
then the group. Groups come from the instance's own listing, which is capped; the search box above
the picker reaches a group beyond the cap. The instance supplies the path, so a group the token
cannot see cannot be bound, and a second team cannot take a group another team holds (HTTP 409).

The same dialog holds the GitHub binding. A team can hold one of each; binding or clearing one
leaves the other alone.
