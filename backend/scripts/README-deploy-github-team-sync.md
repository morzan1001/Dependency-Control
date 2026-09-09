# Deploy runbook — GitHub team sync

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

## 1. Build the index before the deploy

`create_indexes` runs in the startup path, so a build there stalls the rollout. Build it by hand
first; the startup call then finds it and is a no-op.

### 1a. Look at what is already there

```js
db.teams.getIndexes()
```

If `github_instance_id_1_github_team_id_1` already exists with a `partialFilterExpression` other
than the one below — an earlier attempt using `$exists: true`, or `$type: "int"` — **drop it**:

```js
db.teams.dropIndex("github_instance_id_1_github_team_id_1")
```

Startup cannot fix this for you and will not stop for it. MongoDB refuses to redefine an index that
already exists under that name, answers `IndexKeySpecsConflict` (code 86), and the guard in
`create_indexes` logs the skip and continues. The wrong index survives, and with an `$exists`
filter the next manual team creation fails in production with
`E11000 … dup key: { github_instance_id: null, github_team_id: null }` — measured, not inferred.

### 1b. Check for pre-existing duplicates

The build in 1c fails on any, so run this first. It must return nothing:

```js
db.teams.aggregate([
  { $match: { github_team_id: { $type: "number" } } },
  { $group: { _id: { i: "$github_instance_id", t: "$github_team_id" }, n: { $sum: 1 } } },
  { $match: { n: { $gt: 1 } } }
])
```

### 1c. Build it

Do **not** pass a `name`. Omitting it gives the index the same default name `create_index` would
generate (`github_instance_id_1_github_team_id_1`). Under a custom name the key exists twice as far
as MongoDB is concerned: startup's build answers `IndexOptionsConflict` (code 85) and logs a skip on
every pod start — a permanent alarm over a healthy index.

```js
db.teams.createIndex(
  { github_instance_id: 1, github_team_id: 1 },
  { unique: true,
    partialFilterExpression: {
      github_instance_id: { $type: "string" },
      github_team_id: { $type: "number" }
    } }
)
```

Both halves of the filter are load-bearing:

- `$type` rather than `$exists`, because every team document carries an explicit
  `github_team_id: null`, which `$exists: true` matches — the second manual team would fail with
  `E11000 … dup key: { github_instance_id: null, github_team_id: null }`.
- `"number"` rather than `"int"`, because `"int"` is BSON int32 only and the driver encodes any id
  at or beyond 2³¹ as BSON `long`. Such a team would sit outside the unique scope and could be
  created twice.

Verify: `db.teams.getIndexes()` lists `github_instance_id_1_github_team_id_1` with exactly the
`partialFilterExpression` above, and the first pod of the rollout logs no index skip.

## 2. Enable the feature per instance

`sync_teams` stays off until the index exists. Turn it on in Settings → CI/CD Instances, on a
GitHub instance whose token has `read:org` and whose identity is a member of the organisation.
A token that is not an org member sees a subset of teams and members and produces a
partially-populated team with no error.

## 3. No backfill

Existing GitHub-linked projects gain a team on their next ingest, not retroactively.
