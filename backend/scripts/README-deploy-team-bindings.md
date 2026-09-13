# Deploy runbook — a team binding per instance

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

A team used to carry one GitLab binding and one GitHub binding, as four scalars. It now carries
`bindings`: one entry per **instance**, of either provider, in any number. Each entry holds the
provider, the instance, the external id, the display fields that provider needs, and a composite
key `<provider>:<instance id>:<external id>` that a unique index keeps to a single team.

This installation runs **two GitLab instances**. Until now a team could be bound to only one of
them; the other one's groups could not be represented at all.

## 0. What ships, and in what order

**Expand, roll, contract.** The image cannot go first and the migration cannot go alone — §2 is
the measurement behind that, and it is the difference from `README-deploy-team-source-instances.md`,
where the image did go first.

| Step | What | Reversible on its own? |
| --- | --- | --- |
| 1 | Build the unique index by hand | Yes — `dropIndex` |
| 2 | Measure the estate | n/a — read-only |
| 3 | **Expand**: `--execute` (writes `bindings`, keeps the scalars) | Yes — see §8 |
| 4 | Roll the backend image | Yes, freely |
| 5 | Roll the frontend image | Yes — no behaviour change in it |
| 6 | **Contract**: `--execute --drop-scalars` | Yes, at a cost — see §8 |
| 7 | **Gate**: `--verify` exits 0 | n/a |
| 8 | Drop the two superseded indexes | Only after the release is accepted |

`VERSION` stays `1.9.34` — the UI that reads `bindings` ships with it.

### Why not image first, and why not migration first

Neither single-step order is safe, because each image reads only its own shape and **writes teams
it does not find**.

- **Migrate and drop in one step, then roll**: for the length of the rollout the old pods read no
  binding at all. GitLab's sync then creates a second "GitLab Group: …" team for every group it
  ingests, and the ownership write retires the real team — users lose access to their projects
  until the teams are merged by hand. Measured shape:
  `tests/integration/test_team_two_instances_live.py::test_one_instance_resolves_only_through_its_own_binding`
  is the same read returning nothing.
- **Image first, migrate after**: the new pods read no binding either, with the same consequence in
  the other direction. GitHub's adoption-by-name repairs the teams whose generated name still
  matches, but a team renamed by hand is duplicated instead.

The expand pass removes both windows: a team carrying **both** shapes is read correctly by both
images. Only the writes drift, for the minutes of the rollout, and §6 re-derives from whatever the
scalars ended up holding before it unsets them.

## 1. Build the unique index before the deploy

`create_indexes` runs in the startup path, so a build there stalls the rollout. Build it by hand
first; the startup call then finds it and is a no-op.

### 1a. Look at what is already there

```js
db.teams.getIndexes()
```

### 1b. Build it

Do **not** pass a `name`. Omitting it gives the index the same default name `create_index` would
generate (`bindings.key_1`). Under a custom name the key exists twice as far as MongoDB is
concerned: startup's build answers `IndexOptionsConflict` (code 85) and logs a skip on every pod
start — a permanent alarm over a healthy index. The same hazard is written up in
`README-deploy-github-team-sync.md` §1, and it has bitten this installation before.

```js
db.teams.createIndex(
  { "bindings.key": 1 },
  { unique: true,
    partialFilterExpression: { "bindings.key": { $type: "string" } } }
)
```

Both halves are load-bearing, and both were measured against
`percona/percona-server-mongodb:8.0.17-6`:

- **The partial filter**, because a unique index over a path inside a **missing** array indexes the
  document under the key `null`. Without it the second team holding no binding fails with
  `E11000 … dup key: { bindings.key: null }`. `sparse: true` is not the same thing and is not used
  anywhere else here; the `$type` filter matches the spelling of the indexes it replaces.
- **A single key field rather than three compounded ones**, because a `teams` document always
  carries the `members` array, and MongoDB refuses any write to a document indexed across two
  arrays: `cannot index parallel arrays [members] [bindings]`, code 171. One string also keeps the
  resolution read a single-field equality.

Building it now is free: no team carries a binding yet, so the index is empty and cannot fail on a
pre-existing duplicate. Uniqueness up to this point was enforced by the two scalar indexes, so the
entries §3 derives from them cannot collide either.

Verify: `db.teams.getIndexes()` lists `bindings.key_1` with exactly that
`partialFilterExpression`, and the first pod of the rollout logs no index skip.

## 2. Measure the estate

```js
db.teams.countDocuments({})
db.teams.countDocuments({ github_team_id: { $type: "number" } })
db.teams.countDocuments({ gitlab_group_id: { $type: "number" } })
db.gitlab_instances.find({}, { name: 1, sync_teams: 1 })
db.github_instances.find({}, { name: 1, sync_teams: 1 })
```

When this runbook was written: **29** teams, **15** with a GitHub binding, **3** with a GitLab one.
The first two counts are what §3's `teams planned` must equal; the third count is the whole team
collection, which is what §6's `teams planned` must equal, because every team document carries all
seven scalars as an explicit null.

## 3. Expand — write the bindings, keep the scalars

Run it as a Kubernetes **Job**, not `kubectl exec` — the autoscaler evicts backend pods and takes a
long `exec` with them. Use the Job and NetworkPolicy manifest from `README-deploy-waves-2-3.md` §2,
with:

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_team_bindings"]
```

`/app` is required — the script is invoked as a module and resolves `app.*` from there. Name the
Job `dc-migration`, as the sibling runbooks do.

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

Wait for the Job **before** reading the logs: a log read against a still-running Job prints no
count line at all, which reads like a clean run.

The dry-run reports `teams planned`; it must equal the 15 + 3 of §2. Then, having deleted the Job
(a Job's pod template is immutable):

```bash
kubectl delete job dc-migration -n dependency-control
```

```yaml
command: ["python", "-m", "scripts.backfill_team_bindings", "--execute"]
```

`teams matched` must equal `teams planned`. A second dry-run reports `planned 0` — a team that
already holds an entry for an instance keeps the one it holds.

**What a user sees at this point: nothing.** The running image reads the scalars, which are
unchanged, and ignores the array it does not declare.

### 3a. If it aborts

```
backfill_team_bindings: ERROR — E11000 duplicate key error … index: bindings.key_1
```

Exit code **1**. Two teams describe the same (instance, group), which the scalar indexes should
have made impossible — check whether one of them was built under a different name and is therefore
not enforcing anything (§1a). Reconcile the pair by hand, then re-run: the teams already written
are left exactly as they are.

## 4. Roll the backend image

```bash
kubectl rollout status deployment/dependency-control-backend -n dependency-control
```

Old and new pods serve together for a few minutes and both read correctly. What differs is what
they **write**: a binding a new pod creates is invisible to the old pods, and one an old pod writes
(a slug that GitHub renamed, a team it adopted) lands only in the scalars. The first costs at most
one ingest that resolves nothing and therefore leaves its owners untouched; the second is repaired
by §6, which re-derives before it unsets.

## 5. Roll the frontend image

```bash
kubectl rollout status deployment/dependency-control-frontend -n dependency-control
```

**Between §4 and §5 the Teams page shows no binding**, because the response now carries `bindings`
where the UI still reads the scalars. Nothing is lost and nothing is wrong; the link button's Save
answers **404** in that window, since the per-provider routes it calls are gone. Keep the two rolls
in one window.

## 6. Contract — unset the scalars

Only once `kubectl get pods` shows no pod on the previous image.

```bash
kubectl delete job dc-migration -n dependency-control
```

```yaml
command: ["python", "-m", "scripts.backfill_team_bindings", "--execute", "--drop-scalars"]
```

`teams planned` here is the **whole** team collection — 29 — because every document carries the
seven fields as explicit nulls and all of them have to go. `teams matched` must equal it.

This pass derives the entries again before unsetting, so a binding an old pod wrote during §4 is
carried over rather than lost.

## 7. The gate

```bash
kubectl delete job dc-migration -n dependency-control
```

```yaml
command: ["python", "-m", "scripts.backfill_team_bindings", "--verify"]
```

It prints `teams with a scalar binding:` and exits **0** only when that count is zero, **2**
otherwise.

### 7b. The same check from mongosh

`--verify` runs exactly this filter. Presence, not truth: a field left behind as `null` is still a
field the model no longer declares, and still something an old writer could fill.

```js
db.teams.countDocuments({
  "$or": [
    { "gitlab_instance_id": { "$exists": true } },
    { "gitlab_group_id": { "$exists": true } },
    { "gitlab_group_path": { "$exists": true } },
    { "github_instance_id": { "$exists": true } },
    { "github_org": { "$exists": true } },
    { "github_team_id": { "$exists": true } },
    { "github_team_slug": { "$exists": true } }
  ]
})
```

To see which teams it selects rather than how many, pass the same filter to
`db.teams.find(…, {name: 1, bindings: 1})`.

## 8. Drop the superseded indexes

Only after the release is accepted, because they are what protects a rolled-back image:

```js
db.teams.dropIndex("gitlab_instance_id_1_gitlab_group_id_1")
db.teams.dropIndex("github_instance_id_1_github_team_id_1")
```

Startup no longer creates them, so they will not come back. Left in place they index nothing after
§6 — the partial filters select on type and every value is now absent — but every write to the
collection still maintains them.

## 9. Rollback

**Before §3** there is nothing to undo beyond `db.teams.dropIndex("bindings.key_1")`.

**Between §3 and §6** the scalars are still authoritative and untouched. `kubectl rollout undo` on
either deployment is enough; the `bindings` array the previous image ignores can stay, and a later
re-run of §3 is a no-op over it.

**After §6** the previous image reads no binding on any team, which is the outage §0 describes.
Put the scalars back before rolling back — the array carries everything they held:

```js
db.teams.find({ "bindings.0": { $exists: true } }).forEach(function (team) {
  var set = {};
  team.bindings.forEach(function (b) {
    if (b.provider === "gitlab") {
      set.gitlab_instance_id = b.instance_id;
      set.gitlab_group_id = b.external_id;
      set.gitlab_group_path = b.path || null;
    } else if (b.provider === "github") {
      set.github_instance_id = b.instance_id;
      set.github_org = b.org;
      set.github_team_id = b.external_id;
      set.github_team_slug = b.slug || null;
    }
  });
  db.teams.updateOne({ _id: team._id }, { $set: set });
});
```

Run it **before** `kubectl rollout undo`, rebuild the two indexes of §8, and accept what it costs:
a team bound to more than one instance of a provider keeps only the last entry the loop visited,
and every other instance's binding is gone. That is the limitation this release removes, and it is
the state a rollback returns to. Write down which teams hold more than one binding before you run
it:

```js
db.teams.find({ "bindings.1": { $exists: true } }, { name: 1, bindings: 1 })
```

## 10. What changes for an operator

- **Bind per instance.** Teams → the team's link button (needs `system:manage`) → pick the
  instance, then the group or organisation team. The same team can be bound on as many instances as
  exist, one binding each.
- The API is `PUT /api/v1/teams/{id}/bindings` with `{provider, instance_id, external_id[, org]}`
  and `DELETE /api/v1/teams/{id}/bindings/{instance_id}`. A group another team already holds
  answers **409** naming that team. Re-binding the same instance replaces that entry; it never adds
  a second one.
- **Turning `sync_teams` on for the second GitLab instance is now safe** in both halves: phase A
  made each instance retire only its own owners, and this release lets one team answer for both.
- A team bound to instance A is adopted by name for instance B when B's sync meets a group of that
  name. A team already bound to the instance at hand is never adopted.
- Everything else is unchanged: creation still follows the instance's `sync_teams`, a hand-renamed
  team keeps its name, an unanswered question still leaves owners untouched rather than reading as
  "nobody holds it", the 16-owner cap still counts every owner, and `manual` owners are retired by
  no sync.

## 11. What this does not do

`teams.members[].source` still records a provider alone. A team bound to two instances **of the
same provider** has both syncs replacing the same member subset, so its member list follows
whichever instance ingested last. Binding one team to two instances of *different* providers is
unaffected. Two instances of one provider are safe for ownership — which is what this release is
about — and not yet for membership.
