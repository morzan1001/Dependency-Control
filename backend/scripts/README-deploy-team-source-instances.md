# Deploy runbook — ownership provenance names the instance

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

`projects.team_sources` records who established each owning team. It used to record a provider —
`gitlab`, `github` or `manual`. From this release a provider entry names the instance too:
`gitlab:<instance id>`, `github:<instance id>`. `manual` is unchanged.

A sync replaces exactly the owners whose provenance names **its own instance**. With a provider
alone, the two configured GitLab instances each read the other's owners as their own: instance A's
ingest retires the team instance B established, B's next ingest retires A's, and the project
alternates owners on every CI run. Only one GitLab instance has team sync on today, which is the
sole reason this has not happened yet.

## 0. What ships, and in what order

**The image goes first and the migration follows it.** This is the opposite of the usual order
here, and §2 explains why in full.

| Step | What | Reversible on its own? |
| --- | --- | --- |
| 1 | Measure the estate | n/a — read-only |
| 2 | **Roll the backend image** | Yes, freely, until step 5 |
| 3 | Roll the frontend image | Yes — no behaviour change in it |
| 4 | Dry-run the migration | n/a — writes nothing |
| 5 | `--execute` the migration | Yes, at a cost — see §8 |
| 6 | **Gate**: `--verify` exits 0 | n/a |

Steps 2 and 5 belong to the same maintenance window, but they are not welded together the way a
format cutover usually is: §2a is what buys the slack. Do not leave the migration for another day
all the same — §2a also says what it costs.

`VERSION` is `1.9.34` in this change. Production was running `1.9.32` when this runbook was
written.

## 1. Measure the estate

```js
db.projects.countDocuments({})
db.gitlab_instances.find({}, { name: 1, sync_teams: 1 })
db.github_instances.find({}, { name: 1, sync_teams: 1 })
```

Exactly **one** GitLab instance and **one** GitHub instance must have `sync_teams: true`. That is
the assumption the migration rests on: a bare `gitlab` value can only have been written by the one
GitLab instance that syncs, so that is the instance it is attributed to. If the count is anything
other than one for a provider that has bare values, the migration **aborts** rather than guessing —
see §5a.

Count what is to be migrated with §6b's query. Take the number in the same session as the deploy —
it is the expectation for §4's `projects planned`.

## 2. Roll the backend image — first, and here is why

```bash
kubectl rollout status deployment/dependency-control-backend -n dependency-control
```

**Migrating first would be a self-inflicted outage.** A rolling update serves old and new pods
simultaneously for several minutes. The old image declares the provenance value as one of three
literals, so `gitlab:<instance id>` fails validation and `Project(**data)` raises — measured:
`pydantic.ValidationError`. Every read of a migrated project served by a not-yet-replaced pod
answers **500**, across the whole estate, for the length of the rollout. That is certain, not a
risk.

The reverse order has no such window, because the new code tolerates unmigrated data and repairs
most of it as it goes.

### 2a. What the new image does to an unmigrated project

Measured against a real server — `tests/integration/test_project_ownership_live.py::
test_an_ingest_repairs_the_unmigrated_owners_it_still_resolves_on_real_mongo`. Seeded with
`{gl-still-held: "gitlab", gl-group-left: "gitlab", by-hand: "manual"}` and one GitLab ingest that
resolves `gl-still-held`:

| Owner | Before | After the ingest |
| --- | --- | --- |
| `gl-still-held` | `gitlab` | `gitlab:gl-inst-a` — **repaired** |
| `gl-group-left` | `gitlab` | `gitlab` — kept, not retired |
| `by-hand` | `manual` | `manual` |

A bare value names no instance, so the sync reads those owners as somebody else's and adds beside
them: **access is never narrowed**. The owner it resolves again comes back carrying the instance,
because `$setUnion` dedupes on the team id and `$mergeObjects` overwrites that team's entry.

**What a user sees in the intermediate state: nothing.** No error, no changed team list, no lost
access.

**What it costs to leave it there:** the owner a sync no longer resolves keeps its bare value and
is therefore retired by nobody. A repository that moved between groups keeps the group it left, in
addition to the one it moved to, until the migration runs. Access widens, silently, one transfer at
a time. A project that does not sync at all is never repaired. That is the migration's remaining
work, and why §5 belongs in the same window and not next month.

## 3. Roll the frontend image

```bash
kubectl rollout status deployment/dependency-control-frontend -n dependency-control
```

It carries a type change only; nothing in the UI reads a provenance value today. Build it from the
same commit as usual.

## 4. Dry-run the migration

Run it as a Kubernetes **Job**, not `kubectl exec` — the autoscaler evicts backend pods and takes a
long `exec` with them. Use the Job and NetworkPolicy manifest from `README-deploy-waves-2-3.md` §2,
with:

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_team_source_instances"]
```

`/app` is required — the script is invoked as a module and resolves `app.*` from there. Name the
Job `dc-migration`, as the sibling runbooks do.

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

Wait for the Job **before** reading the logs: a log read against a still-running Job prints no
count line at all, which reads like a clean run.

The run prints the instance it attributes each provider's bare values to, then `projects planned`.
`projects planned` must equal the count §6b's query returns at the same time — that is the check,
not a fixed number. Expect it to be **lower** than the number §1 recorded, by however many projects
ingested between the rollout and now: §2a repaired those. The run writes nothing.

### 4a. Read the attribution line

```
[gitlab] bare values attributed to instance <id>
```

Check that id against §1's instance list before executing. It is the single decision the migration
makes, and it is the one that cannot be undone by re-running the script.

## 5. Execute the migration

A Job's pod template is immutable, so delete the dry-run Job before reusing the name:

```bash
kubectl delete job dc-migration -n dependency-control
```

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_team_source_instances", "--execute"]
```

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

`projects matched` must equal the `projects planned` of the same run. The script is idempotent — a
second dry-run immediately after reports `planned 0`, because a value already naming an instance is
left exactly as stored.

From this point the estate carries values the previous image cannot read: §8 applies.

### 5a. If it aborts

```
backfill_team_source_instances: ERROR — gitlab: 2 instance(s) have team sync enabled (...)
```

Exit code **1**, nothing written. Two instances with team sync on means a bare `gitlab` value could
have come from either, and attributing it to the wrong one hands that owner to the wrong instance's
next ingest to delete. Resolve it by hand — decide per project which instance established the
owner and set the value — then re-run.

## 6. The gate

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_team_source_instances", "--verify"]
```

It prints `projects with a bare source:` and exits **0** only when that count is zero, **2**
otherwise. Unlike the usual gate here this one does not release a deploy — the deploy already
happened. It releases the *claim* that no owner is left un-retirable, which is the whole point of
the change: re-run it a day later and it must still read 0.

### 6b. The same check from mongosh

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

## 7. What changes for an operator

- A sync retires only the owners its **own instance** established. Turning team sync on for the
  second GitLab instance is now safe: the two instances add and retire disjoint owner sets on the
  same project.
- A hand assignment is untouched by every sync, exactly as before. So is an owner carrying no
  `team_sources` entry at all — it is read as hand-assigned.
- Startup's provenance backfill now stamps `gitlab:<instance id>` and **skips a synced team that
  carries no `gitlab_instance_id`**, where it used to stamp a bare `gitlab`. Such an owner stays
  unstamped, which reads as hand-assigned: kept, and retired by no sync. Grep the first pod for
  `named no instance and were left unstamped` and reconcile those teams by binding them to an
  instance if their owners should follow a sync.
- The 16-owner cap is unchanged and still counts every owner across providers, instances and hand
  assignments.

## 8. Rollback

**Before §5** there is nothing to undo: no stored value has changed, and `kubectl rollout undo` on
either deployment is enough. This is the second reason the image goes first.

**After §5**, rolling the backend back to `1.9.32`/`1.9.33` breaks every migrated project — the old
model rejects `gitlab:<instance id>` and each read answers 500. Strip the instances first:

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

Run it **before** `kubectl rollout undo`, and accept what it costs: with the instance gone, a
provider's next sync again treats every instance's owners as its own. That is the bug this release
removes, and it is the state a rollback returns to.

## 9. What the migration does not do

It does not touch `team_ids`, project membership, `teams`, or `Project.gitlab_instance_id` /
`Project.github_instance_id` — those record which instance the *project* came from and are a
different field with a different meaning. It only rewrites provenance values.

It also does not touch `teams.members[].source`, which still records a provider alone. Team
membership sync has the same two-instance exposure and is not addressed here.
