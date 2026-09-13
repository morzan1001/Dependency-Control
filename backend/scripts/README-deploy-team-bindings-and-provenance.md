# Deploy runbook — a binding per instance, and provenance that names one

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

This is **one maintenance window with two migrations**, and it is the only authority for it. Running
either migration by the order that suits it alone breaks the other one; §0 is the order that holds
for both, and every step below was executed against `percona/percona-server-mongodb:8.0.17-6` on an
estate shaped like production before it was written.

Two things change together:

- **`teams.bindings`.** A team used to carry one GitLab binding and one GitHub binding, as seven
  scalars. It now carries one entry per **instance**, of either provider, in any number, each with a
  composite key `<provider>:<instance id>:<external id>` that a unique index keeps to one team.
- **`projects.team_sources`.** A provenance entry used to name a provider — `gitlab`, `github`,
  `manual`. A provider entry now names the instance too: `gitlab:<instance id>`. `manual` is
  unchanged.

This installation runs **two GitLab instances**, only one of which syncs teams today. That is the
sole reason the two have not already been deleting each other's owners on alternating CI runs.

`VERSION` is `1.9.34`. Production was running `1.9.32` when this runbook was written.

## 0. What ships, and in what order

Neither migration's own order survives contact with the other one:

- The bindings migration must **expand before the image**, because the new model reads a
  scalars-only team as unbound. Measured: `Team(**doc).bindings == []` on a team carrying
  `github_instance_id`/`github_org`/`github_team_id`, and all **29 of 29** teams answering
  `find_raw_unbound_for_instance`. Every GitLab ingest in that window would create a second
  `GitLab Group: …` team and the ownership write would retire the real one.
- The provenance migration must **follow the image**, because the previous model declares the value
  as `Literal["gitlab", "github", "manual"]`. Measured: `Project(**doc)` on a migrated project
  raises `pydantic.ValidationError`, so every read served by a not-yet-replaced pod answers **500**.

So the image goes **between** them, and the whole sequence is one window:

| Step | What | Rollback |
| --- | --- | --- |
| 1 | Measure the estate | n/a — read-only |
| 2 | Build the `bindings.key` index by hand | §11a |
| 3 | **Expand**: `--execute` (writes `bindings`, keeps the scalars) | §11b |
| 4 | **Roll the backend image** | §11c |
| 5 | Roll the frontend image | §11c |
| 6 | **Provenance**: `--execute` | §11d |
| 7 | **Contract**: `--execute --drop-scalars` | §11e |
| 8 | Gate: bindings `--verify` exits 0 | n/a |
| 9 | Gate: provenance `--verify` exits 0 | n/a |

**Do not drop the two superseded indexes in this window** — §10. They are what makes §11e possible.

Every migration pass runs as a Kubernetes **Job**, not `kubectl exec`: the autoscaler evicts backend
pods and takes a long `exec` with them. Use the Job and NetworkPolicy manifest from
`README-deploy-waves-2-3.md` §2, with `workingDir: /app` — the scripts are invoked as modules and
resolve `app.*` from there. Name the Job `dc-migration`. A Job's pod template is immutable, so
`kubectl delete job dc-migration -n dependency-control` between every pass.

After each pass, wait for the Job **before** reading its logs: a log read against a still-running
Job prints no count line at all, which reads like a clean run.

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

## 1. Measure the estate

```js
db.projects.countDocuments({})
db.teams.countDocuments({})
db.teams.countDocuments({ github_team_id: { $type: "number" } })
db.teams.countDocuments({ gitlab_group_id: { $type: "int" } })
db.gitlab_instances.find({}, { name: 1, sync_teams: 1 })
db.github_instances.find({}, { name: 1, sync_teams: 1 })
db.teams.getIndexes()
```

Three things have to hold before anything is written.

**Exactly one instance per provider has `sync_teams: true`.** A bare `gitlab` value can only have
been written by the one GitLab instance that syncs, and that is the instance §6 attributes it to.
With two, §6 **aborts** rather than guessing — see §6a. Check this now and not at §6: by then the
image is rolled and the window is half spent.

**The two superseded indexes are listed.** `gitlab_instance_id_1_gitlab_group_id_1` and
`github_instance_id_1_github_team_id_1` are what §11e relies on, and startup no longer builds them.
If either is missing, build it from §10 before going on.

**The counts.** The GitHub and GitLab scalar counts added together are what §3's `teams planned`
must equal; the whole team count is what §7's `teams planned` must equal, because every team
document carries all seven scalars as an explicit null. When this runbook was written against a
production-shaped estate: **750** projects, **29** teams, **15** with a GitHub binding, **3** with a
GitLab one.

Take the count of what §6 will migrate in the same session, with §9a's query. It is the expectation
for §6's `projects planned` — and expect it to come out **lower**, by however many projects ingested
between §4 and §6, because the new image repairs those as it goes (§11c).

## 2. Build the `bindings.key` index by hand

`create_indexes` runs in the startup path, so a build there stalls the rollout. Build it first; the
startup call then finds it and is a no-op. Building it now is free: no team carries a binding yet, so
the index is empty and cannot fail on a pre-existing duplicate. Uniqueness up to this point was
enforced by the two scalar indexes, so the entries §3 derives from them cannot collide either.

Do **not** pass a `name`.

```js
db.teams.createIndex(
  { "bindings.key": 1 },
  { unique: true,
    partialFilterExpression: { "bindings.key": { $type: "string" } } }
)
```

It must return `bindings.key_1`. Three things about that command are load-bearing, and all three were
measured against `percona/percona-server-mongodb:8.0.17-6`:

- **No custom name.** Omitting it gives the index the same default name `create_index` generates.
  Under a custom name the key exists twice as far as MongoDB is concerned, and startup's build
  answers `IndexOptionsConflict` (code 85) — *Index already exists with a different name*. The build
  is guarded, so the pod does **not** crash; it logs the skip at ERROR on every pod start, a
  permanent alarm over a healthy index, and the guard's message claims the key is unenforced when it
  is not. The same hazard has bitten this installation before.
- **The partial filter**, because a unique index over a path inside a **missing** array indexes the
  document under the key `null`, so the second team holding no binding fails with
  `E11000 … dup key: { bindings.key: null }`. `sparse: true` is not the same thing; the `$type`
  filter matches the spelling of the indexes it replaces.
- **A single key field rather than three compounded ones**, because a `teams` document always
  carries the `members` array, and MongoDB refuses any write to a document indexed across two
  arrays: `cannot index parallel arrays [members] [bindings]`, code 171. One string also keeps the
  resolution read a single-field equality.

Verify: `db.teams.getIndexes()` lists `bindings.key_1` with exactly that `partialFilterExpression`.

## 3. Expand — write the bindings, keep the scalars

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_team_bindings"]
```

The dry-run reports `teams planned`; it must equal §1's GitHub plus GitLab scalar counts — **18** on
the measured estate. The `batched=` line counts the whole collection, because every team carries the
scalars as explicit nulls; only the planned number is the one to check.

Then, after deleting the Job:

```yaml
command: ["python", "-m", "scripts.backfill_team_bindings", "--execute"]
```

`teams matched` must equal `teams planned` — measured `planned=18 matched=18`. A second dry-run
reports `planned 0`: a team that already holds an entry for an instance keeps the one it holds.

**What a user sees at this point: nothing.** The running image reads the scalars, which are
unchanged field for field, and ignores the array it does not declare.

### 3a. If it aborts

```
backfill_team_bindings: ERROR — E11000 duplicate key error … index: bindings.key_1
```

Exit code **1**. Two teams describe the same (instance, group), which the scalar indexes should have
made impossible — check whether one of them was built under a different name and is therefore not
enforcing anything (§1). Reconcile the pair by hand, then re-run: the teams already written are left
exactly as they are.

## 4. Roll the backend image

```bash
kubectl rollout status deployment/dependency-control-backend -n dependency-control
```

Old and new pods serve together for a few minutes and, because §3 left every team carrying **both**
shapes, both read correctly. What differs is what they **write**: a binding a new pod creates is
invisible to the old pods, and one an old pod writes (a slug that GitHub renamed, a team it adopted)
lands only in the scalars. The first costs at most one ingest that resolves nothing and therefore
leaves its owners untouched; the second is repaired by §7, which re-derives before it unsets.

Two things start happening the moment the first new pod serves, and both matter later:

- Startup's provenance backfill stamps the instance on owner entries that are **absent or null**,
  reading the bindings §3 wrote. Had the image gone first it would have found no GitLab binding on
  any team and stamped nothing. Measured on the seeded estate: `0 project(s) stamped across 3 synced
  team(s)`, because every owner there already carried a bare value, which is not an absent one.
- Every ingest **repairs** the bare values it still resolves, writing `gitlab:<instance id>` itself.
  That is why a rollback from §4 onward needs the provenance strip even though §6 has not run
  (§11c).

Wait for `kubectl get pods` to show no pod on the previous image before §7.

## 5. Roll the frontend image

```bash
kubectl rollout status deployment/dependency-control-frontend -n dependency-control
```

**Between §4 and §5 the Teams page shows no binding**, because the response now carries `bindings`
where the UI still reads the scalars, and the link dialog's Save answers **404** — the per-provider
routes it calls are gone, replaced by `PUT /api/v1/teams/{id}/bindings`. Nothing is lost and nothing
is wrong, but keep the two rolls minutes apart, not hours.

## 6. Stamp the provenance

Only once §4 is complete. This is the pass the previous image cannot survive.

```yaml
command: ["python", "-m", "scripts.backfill_team_source_instances"]
```

The run prints the instance it attributes each provider's bare values to, then `projects planned`:

```
[github] bare values attributed to instance gh-cloud
[gitlab] bare values attributed to instance gl-prod
```

**Check each id against §1's instance list before executing.** It is the single decision the
migration makes and the one a re-run cannot undo. `projects planned` must equal what §9a's query
returns at the same moment — that is the check, not a fixed number.

Then, after deleting the Job:

```yaml
command: ["python", "-m", "scripts.backfill_team_source_instances", "--execute"]
```

`projects matched` must equal the `projects planned` of the same run — measured `planned=670
matched=670` over 750 projects. A second dry-run reports `planned 0`: a value already naming an
instance is left exactly as stored.

### 6a. If it aborts

```
backfill_team_source_instances: ERROR — gitlab: 2 instance(s) have team sync enabled
(['gl-legacy', 'gl-prod']); exactly one is required to attribute the bare values. Resolve them by hand.
```

Exit code **1**, nothing written — measured: 670 bare values still bare afterwards. Two instances
with team sync on means a bare `gitlab` value could have come from either, and attributing it to the
wrong one hands that owner to the wrong instance's next ingest to delete. Decide per project which
instance established the owner, set the value by hand, then re-run.

## 7. Contract — unset the scalars

Only once `kubectl get pods` shows no pod on the previous image.

```yaml
command: ["python", "-m", "scripts.backfill_team_bindings", "--execute", "--drop-scalars"]
```

`teams planned` here is the **whole** team collection — **29** — because every document carries the
seven fields as explicit nulls and all of them have to go. `teams matched` must equal it; measured
`planned=29 matched=29`.

This pass derives the entries again before unsetting, so a binding an old pod wrote during §4 is
carried over rather than lost.

## 8. The bindings gate

```yaml
command: ["python", "-m", "scripts.backfill_team_bindings", "--verify"]
```

It prints `teams with a scalar binding:` and exits **0** only when that count is zero, **2**
otherwise.

### 8a. The same check from mongosh

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

## 9. The provenance gate

```yaml
command: ["python", "-m", "scripts.backfill_team_source_instances", "--verify"]
```

It prints `projects with a bare source:` and exits **0** only when that count is zero, **2**
otherwise. This one does not release a deploy — the deploy already happened. It releases the *claim*
that no owner is left un-retirable, which is the point of the change: re-run it a day later and it
must still read 0.

### 9a. The same check from mongosh

`--verify` runs exactly this filter. It counts a project whenever any `team_sources` value, or the
legacy `team_source` scalar, is a provider with no instance after it. `manual` matches neither
clause, and neither does a value that already carries an instance:

```js
db.projects.countDocuments({
  "$or": [
    { "$expr": { "$gt": [ { "$size": { "$filter": {
        "input": { "$objectToArray": { "$ifNull": ["$team_sources", {}] } },
        "as": "entry",
        "cond": { "$in": ["$$entry.v", { "$literal": ["gitlab", "github"] }] } } } }, 0 ] } },
    { "team_source": { "$in": ["gitlab", "github"] } }
  ]
})
```

To see which projects it selects rather than how many, pass the same filter to
`db.projects.find(…, {name: 1, team_ids: 1, team_sources: 1, team_source: 1})`.

## 10. Leave the superseded indexes alone

`gitlab_instance_id_1_gitlab_group_id_1` and `github_instance_id_1_github_team_id_1` index nothing
once §7 has run — their partial filters select on type and every value is now absent — and startup
no longer creates them. Dropping them is still **not** part of this window: restoring the scalars is
how §11e gets the estate back to something the previous image can read, and without these two
indexes that restore can hand one group to two teams.

Drop them only after the release is accepted and a rollback is off the table:

```js
db.teams.dropIndex("gitlab_instance_id_1_gitlab_group_id_1")
db.teams.dropIndex("github_instance_id_1_github_team_id_1")
```

If either is already missing at §1, or has to come back for a rollback, these are the two
definitions — note that GitHub's uses `$type: "number"` where GitLab's uses `"int"`, and that a
mismatch here silently indexes nothing:

```js
db.teams.createIndex(
  { gitlab_instance_id: 1, gitlab_group_id: 1 },
  { unique: true,
    partialFilterExpression: {
      gitlab_instance_id: { $type: "string" },
      gitlab_group_id:    { $type: "int" }
    } }
)

db.teams.createIndex(
  { github_instance_id: 1, github_team_id: 1 },
  { unique: true,
    partialFilterExpression: {
      github_instance_id: { $type: "string" },
      github_team_id:     { $type: "number" }
    } }
)
```

Both were verified to build under exactly the names the `dropIndex` calls above use. Build them
**before** restoring any scalars, so a duplicate is refused rather than written.

## 11. Rollback

Rolling the backend back to `1.9.32`/`1.9.33` is safe only from a state that image can read. There
are two separate ways it cannot, and after §7 **both** apply — running one repair and not the other
is the mistake this section exists to prevent. Measured on a 750-project, 29-team estate taken all
the way through §7:

| Repair run | Old `Project()` | Old `Team()` |
| --- | --- | --- |
| Scalars restored only | **710 of 750 raise `ValidationError`** | 29 of 29 load, 18 bound |
| Provenance stripped only | 750 of 750 load | **0 of 29 bound** |
| Both | 750 of 750 load | 29 of 29 load, 18 bound |

710 projects raising `ValidationError` is 710 reads answering 500. Nought of 29 teams bound is every
`GitLab Group: …` team duplicated on the next ingest and the real one retired.

### 11a. After §2, before §3

Nothing has been written.

```js
db.teams.dropIndex("bindings.key_1")
```

### 11b. After §3, before §4

The scalars are untouched and authoritative, and the previous image ignores the `bindings` array —
measured: it reads 18 of 29 teams as bound, exactly as before §3. `kubectl rollout undo` is enough
and the array can stay; a later re-run of §3 is a no-op over it. To leave nothing behind:

```js
db.teams.updateMany({}, { $unset: { bindings: "" } })
db.teams.dropIndex("bindings.key_1")
```

### 11c. After §4 or §5, before §6

The scalars are still authoritative, but the new image has been **repairing** bare provenance values
as it ingests, so some projects already carry `gitlab:<instance id>` even though §6 has not run.
Strip them before rolling back — this is the step the per-migration runbooks both missed, because
each one read the other's phase as "nothing has changed yet":

```js
db.projects.updateMany(
  { "$expr": { "$gt": [ { "$size": { "$filter": {
      "input": { "$objectToArray": { "$ifNull": ["$team_sources", {}] } },
      "as": "entry",
      "cond": { "$gt": [ { "$indexOfCP": ["$$entry.v", ":"] }, -1 ] } } } }, 0 ] } },
  [
    { "$set": { "team_sources": { "$arrayToObject": { "$map": {
        "input": { "$objectToArray": { "$ifNull": ["$team_sources", {}] } },
        "as": "entry",
        "in": { "k": "$$entry.k",
                "v": { "$arrayElemAt": [ { "$split": ["$$entry.v", ":"] }, 0 ] } } } } } } },
    { "$set": { "team_source": { "$arrayElemAt": [ { "$split": ["$team_source", ":"] }, 0 ] } } }
  ]
)
```

Confirm with `db.projects.countDocuments({ team_source: /:/ })` — it must return 0 — then
`kubectl rollout undo` both deployments, then §11b.

### 11d. After §6, before §7

Same as §11c, and now it is the whole migrated set rather than a handful: measured `matched=710
modified=710`, and the old model then loads 750 of 750. Run it **before** `kubectl rollout undo`.

### 11e. After §7

Both repairs, and the scalar restore first so the indexes of §10 can refuse a duplicate before any
provenance is touched.

Write down which teams hold more than one binding before you start — the restore is a loop over one
`$set` per team, so a team bound to several instances of a provider keeps only the last entry the
loop visits and every other instance's binding is gone:

```js
db.teams.find({ "bindings.1": { $exists: true } }, { name: 1, bindings: 1 })
```

Then restore the scalars:

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

Confirm the two counts of §1 come back — measured 15 and 3:

```js
db.teams.countDocuments({ github_team_id: { $type: "number" } })
db.teams.countDocuments({ gitlab_group_id: { $type: "int" } })
```

Then run §11c's provenance strip, and only then `kubectl rollout undo` on both deployments.

Accept what the pair costs: the instance is gone from every provenance value, so a provider's next
sync again treats every instance's owners as its own, and a team bound to more than one instance
keeps one binding. Those two limitations are what this release removes, and they are the state a
rollback returns to.

## 12. What changes for an operator

- **Bind per instance.** Teams → the team's link button (needs `system:manage`) → pick the instance,
  then the group or organisation team. The same team can be bound on as many instances as exist, one
  binding each.
- The API is `PUT /api/v1/teams/{id}/bindings` with `{provider, instance_id, external_id[, org]}` and
  `DELETE /api/v1/teams/{id}/bindings/{instance_id}`. A group another team already holds answers
  **409** naming that team. Re-binding the same instance replaces that entry; it never adds a second.
- A sync retires only the owners its **own instance** established. A hand assignment is untouched by
  every sync, as before, and so is an owner carrying no `team_sources` entry at all — it reads as
  hand-assigned.
- **Turning `sync_teams` on for the second GitLab instance is now safe for ownership**, in both
  halves: provenance makes each instance retire only its own owners, and the array lets one team
  answer for both. It is **not** safe for membership — see §13 before turning it on.
- A team bound to instance A is adopted by name for instance B when B's sync meets a group of that
  name. A team already bound to the instance at hand is never adopted.
- Startup's provenance backfill **skips a synced team bound to more than one GitLab instance**, where
  it used to stamp a bare `gitlab`. Such an owner stays unstamped, which reads as hand-assigned: kept,
  and retired by no sync. Grep the first pod for `named no instance and were left unstamped` and
  reconcile those teams if their owners should follow a sync.
- The 16-owner cap is unchanged and still counts every owner across providers, instances and hand
  assignments.

## 13. What this window does not do

`teams.members[].source` still records a provider alone. A team bound to two instances **of the same
provider** has both syncs replacing the same member subset, so its member list follows whichever
instance ingested last, and a team bound to both providers has each sync relabel the other's members
as hand-added. Two instances of one provider are safe for **ownership** — which is what this release
is about — and not for membership until `README-deploy-member-provenance.md` has been run.

Neither migration touches `team_ids`, project membership, `teams` other than the binding fields, or
`Project.gitlab_instance_id` / `Project.github_instance_id` — those record which instance the
*project* came from and are a different field with a different meaning.
