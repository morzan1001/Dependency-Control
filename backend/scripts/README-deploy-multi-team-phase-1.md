# Deploy runbook — multi-team projects Phase 1

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

## 1. Build the index before the deploy

**If in doubt, skip this section.** Startup builds this index in milliseconds on 742 documents;
everything below only matters if you choose to build it by hand.

`create_indexes` runs in the startup path. Building it by hand first keeps that call a no-op — at
the cost of the naming hazard described below, which only exists on the hand-built path.

### 1a. Check for pre-existing indexes

```js
db.projects.getIndexes()
```

If an index on `team_ids` already exists under a non-default name (anything other than
`team_ids_1`), **drop it** first:

```js
db.projects.dropIndex("old_index_name")
```

**This is critical**: if a hand-built index exists under a custom name, the startup call to
`create_index` fails with `IndexOptionsConflict` (code 85). This call is unguarded — there is no
try/catch around it in `init_db.py:234` — so the exception aborts `startup_event`, and every
backend pod crashes on startup. The rolling update stalls at the first pod.

### 1b. Build the index

Do **not** pass a `name`. Omitting it gives the index the same default name `create_index` would
generate (`team_ids_1`). Under a custom name the key exists twice as far as MongoDB is concerned,
triggering the unguarded startup crash described above.

```js
db.projects.createIndex({ team_ids: 1 })
```

Verify the resulting index name is `team_ids_1`:

```js
db.projects.getIndexes().map(i => i.name)
```

Or, to filter to just the team_ids indexes:

```js
db.projects.getIndexes().filter(i => i.name.includes("team_ids"))
```

The output must show `team_ids_1` exactly, with no custom name or options.

## 2. Deploy the revision that adds the multikey index

Deploy the code that includes:
- The `team_ids` and `team_sources` fields on projects (new in this deploy)
- The multikey index on `team_ids` (built by hand in step 1, where it becomes a no-op on startup)
- The backfill migration script (will be invoked in step 3)

Later deploys will add analytics and queries using `team_ids`.

### 2a. Watch the rollout

Once the deploy starts, verify the index name did not cause a startup crash:

```bash
kubectl rollout status deployment/dependency-control-backend -n dependency-control
```

If any pod crashes with an index error, stop the rollout immediately — the index name is wrong and
must be dropped and rebuilt before you continue.

## 3. Run the dry-run backfill

Create a Kubernetes Job to run the backfill. Use the same Job manifest pattern as
`README-deploy-waves-2-3.md`, with:

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_project_team_ids"]
```

The working directory `/app` is required — the script's usage line and all invocations depend on it.
Name the Job `dc-migration` (the conventional name used by the sibling migration runbook).

Wait for the Job, then view the logs — logs read against a still-running Job print no count line at
all, which reads as a clean run:

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

Record the `projects planned` count. Expected: **742** (229 with a team, 513 without).
This run does not write anything — it only reports how many projects would be updated from the
scalar `team_id` to the derived list `team_ids`.

## 4. Execute the backfill

A Job's pod template is immutable, so the dry-run Job must be deleted before applying the execute
run under the same name:

```bash
kubectl delete job dc-migration -n dependency-control
```

Create a new backfill Job with `--execute`:

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_project_team_ids", "--execute"]
```

Wait for the Job, then view the logs:

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

Record the `projects matched` count. Expected: **742**.

## 5. Verify completion

Verify both fields are present on every project:

```js
db.projects.countDocuments({ team_ids: { $exists: false } })
```

This must return **0**, confirming every project now carries a `team_ids` list. Projects without a
team carry an empty list `[]`.

Also check that the provenance field was populated:

```js
db.projects.countDocuments({ team_sources: { $exists: false } })
```

This must also return **0**, confirming every project now carries a `team_sources` dict. Projects
without a team carry an empty dict `{}`.

## 6. Re-runs while the scalar is authoritative

The backfill derives `team_ids` from the scalar `team_id` every run. It is safe to re-run for
verification **only while the scalar `team_id` is still authoritative** — i.e., before the write
paths begin writing `team_ids` directly. Once writers own the list, the migration must never be
re-run, because it would overwrite writer-added teams with a re-derivation from the single scalar
and silently truncate every multi-team project back to one team.

From this backfill onward the stored `team_ids` goes stale: every team transfer writes only the
scalar `team_id`. The deploy that first makes the application **read** `team_ids` must therefore be
preceded by a final `--execute` run of this backfill, in the same maintenance window, before the new
image rolls. Without it, every project transferred since the last run keeps its old team's access
and attribution — and §5 cannot detect this, because the field is present, merely stale.

## 7. When the write paths take over

In a later deploy, the write paths will begin writing `team_ids` directly instead of through the
scalar. From that deploy onward, this backfill migration **must not be re-run**. At that point,
the `team_id` field and its index are scheduled for removal in a subsequent deploy. The
`team_ids` index remains permanent, as it enables team-scoped queries for all team-membership
features.
