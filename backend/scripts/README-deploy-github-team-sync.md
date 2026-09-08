# Deploy runbook — GitHub team sync

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

## 1. Build the index before the deploy

`create_indexes` runs in the startup path, so a build there stalls the rollout. Build it by hand
first; the startup call then finds it and is a no-op.

Do **not** pass a `name`. Omitting it gives the index the same default name `create_index` would
generate (`github_instance_id_1_github_team_id_1`). Under a custom name startup tries to create a
second index with the same key, MongoDB answers `IndexOptionsConflict` (code 85), and the guard
logs `Skipping unique teams (github_instance_id, github_team_id) index: build failed (likely a
pre-existing duplicate)` on every pod start — a permanent false alarm over a healthy index.

```js
db.teams.createIndex(
  { github_instance_id: 1, github_team_id: 1 },
  { unique: true,
    partialFilterExpression: {
      github_instance_id: { $type: "string" },
      github_team_id: { $type: "int" }
    } }
)
```

The `$type` filter is load-bearing: every team document carries an explicit
`github_team_id: null`, which `$exists: true` would match, making the second manual team a
duplicate key.

Check for pre-existing duplicates first; the build fails on any:

```js
db.teams.aggregate([
  { $match: { github_team_id: { $type: "int" } } },
  { $group: { _id: { i: "$github_instance_id", t: "$github_team_id" }, n: { $sum: 1 } } },
  { $match: { n: { $gt: 1 } } }
])
```

## 2. Enable the feature per instance

`sync_teams` stays off until the index exists. Turn it on in Settings → CI/CD Instances, on a
GitHub instance whose token has `read:org` and whose identity is a member of the organisation.
A token that is not an org member sees a subset of teams and members and produces a
partially-populated team with no error.

## 3. No backfill

Existing GitHub-linked projects gain a team on their next ingest, not retroactively.
