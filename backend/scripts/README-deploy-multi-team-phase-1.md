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

A present map is not a complete one: an owner listed in `team_ids` that the map does not name
belongs to no provider, so no sync can ever retire it. §6b's second query counts those and must
also return **0**.

## 6. HARD GATE — the final backfill and the deploy that stops deriving

Read this section before scheduling the deploy that removes `Project._derive_team_ids`.

Between this backfill and that deploy, the stored `team_ids` goes stale on every team change: the
writers set the scalar `team_id` only, and the model quietly re-derives the list from it on every
read, so the drift is invisible. A measured example — stored `team_id='T_new'`,
`team_ids=['T_old']`, `team_sources={'T_old':'github','M1':'manual'}` — reads back today as
`team_ids=['T_new']`, `team_sources={'T_new':'github'}`. The moment the derivation goes, that same
document grants `T_old` access to a project it no longer owns and denies it to `T_new`.

**The gate, in order, inside one maintenance window:**

1. Run this backfill with `--execute` (§4).
2. Run `--verify` and confirm it reports **0** (below). Do not skip it: §5 checks only that the
   fields exist, and a stale field exists.
3. Roll the image that stops deriving. If the deploy is postponed past this window, start again
   at step 1 — anything that changed a team in between has re-armed the drift.

Do not roll that image on its own. Once the derivation is gone, the stored list is what readers
act on, and nothing maintains it until the deploy that converts the write paths. The two ship
together.

### 6a. Run the verification

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_project_team_ids", "--verify"]
```

It prints `projects disagreeing:` and `owners with no provenance:`, and exits **0** only when both
counts are zero, **2** otherwise. Expected: **0** and **0**.

### 6b. The same two checks from mongosh

`--verify` runs exactly these filters, in this order. The first counts a document whenever its
stored `team_ids` or `team_sources` says anything other than the scalar does — including a document
that never received the backfill, and one whose `team_ids` is `null`, which is the one shape that no
longer loads into the model at all. A count of `0` means a re-run of the backfill would plan nothing:

```js
db.projects.countDocuments({
  "$expr": { "$or": [
    { "$ne": ["$team_ids",
        { "$cond": [ { "$in": [ { "$ifNull": ["$team_id", null] }, [null, ""] ] }, [], ["$team_id"] ] } ] },
    { "$ne": [ { "$objectToArray": "$team_sources" },
        { "$cond": [
            { "$in": [ { "$ifNull": ["$team_id", null] }, [null, ""] ] },
            [],
            [ { "k": "$team_id",
                "v": { "$cond": [ { "$in": [ { "$ifNull": ["$team_source", null] }, [null, ""] ] },
                                  "manual", "$team_source" ] } } ] ] } ] }
  ] }
})
```

The second counts the projects holding an owner that `team_sources` does not name. That owner
belongs to no provider, so no sync can ever retire it: the repository moves between groups and the
group it left keeps its access for good. The backfill writes `manual` for a scalar owner whose
`team_source` is absent — the 503 production projects in that state — precisely so this count
reaches zero; unlike the first check it stays meaningful after the cutover, because no writer from
that deploy on can produce the shape.

```js
db.projects.countDocuments({
  "$expr": { "$ne": [
    { "$setDifference": [
        { "$ifNull": ["$team_ids", []] },
        { "$map": { "input": { "$objectToArray": { "$ifNull": ["$team_sources", {}] } },
                    "as": "entry", "in": "$$entry.k" } } ] },
    [] ] }
})
```

To see which projects either query selects rather than how many, pass the same filter to
`db.projects.find(…, {team_id: 1, team_ids: 1, team_source: 1, team_sources: 1})`.

## 7. When the write paths take over

From the deploy that converts the write paths onward, this backfill **must not be re-run**: it
re-derives the list from the single scalar and would truncate every multi-team project back to one
team. `--verify` shares that fate — after the cutover a co-owned project disagrees with its scalar
by design, so the gate is meaningful only up to and including the deploy in §6.

At that point the `team_id` field and its index are scheduled for removal in a subsequent deploy.
The `team_ids` index remains permanent, as it enables team-scoped queries for all team-membership
features.

### 7a. What changes for an operator on that deploy

- Every ownership write keeps `team_id` / `team_source` pointing at one of the stored owners, so
  the queries still reading the scalar — the project list, the team filter, analytics — keep
  working. A co-owned project appears under **one** of its owners there until those queries move
  to `team_ids` in the next deploy; access itself already reads the list.
- A GitHub or GitLab sync replaces only the owners it set itself. A team assigned by hand survives
  every ingest, and a repository that moved between groups loses the group it left.
- **Unbinding a GitHub team now takes effect.** With no bound team left holding a repository, the
  next ingest retires that repository's GitHub-sourced owners. Removing a binding is therefore a
  change of ownership, not only of resolution.
- `POST /api/v1/projects/{id}/teams` and `DELETE /api/v1/projects/{id}/teams/{team_id}` add and
  remove one owner. `PUT /api/v1/projects/{id}` with `team_id` still works and now means "the team
  this project is assigned to by hand": it replaces the manually-assigned owners and leaves a
  provider's entry alone. Posting a team that already owns the project answers with the project
  unchanged — it does not reclaim a provider's entry as a hand assignment.
- Both `PUT` with `team_id` and `DELETE …/teams/{team_id}` refuse with **400** when the change
  would leave the project with nobody able to administer it. Only a write superuser may.
- A project may have at most 16 owning teams, counted across every provider and every hand
  assignment. A sync whose result would exceed it leaves the project's owners untouched and logs
  `past the cap`; grep for it after the deploy.
- An owner stored without a `team_sources` entry is read as a hand assignment, so no sync retires
  it and `PUT` with `team_id` replaces it along with the rest of the manual set. §6b's second
  query lists them; the backfill stamps them `manual` so none are left.

## 8. The deploy that moves the reads onto the list

Nothing reads the scalar `team_id` from that deploy on. It is still written, and its index still
exists, so this deploy is reversible; both go in the cutover deploy.

### 8a. Numbers that change, and by how much

A project counts **in full at every team that owns it**. Per-team figures therefore stop adding up
to the estate's — summing them exceeds it by one project per extra owner. That is the intended
result, not drift; a check that reconciles the two is now checking for the wrong thing.

### 8b. Startup normalises the owner shape — nothing to run by hand

`create_indexes` now sets `team_ids: []` on any project whose field is absent or null. Both shapes
answer no ownership filter and no `$size` test, so such a project was in no team view at all. It is
idempotent. Grep the first pod's log for:

```
Owner normalisation: gave N project(s) with no team_ids an empty owner list
```

Expect **N = 0**: §5's check already reported zero projects without the field. A non-zero N means
something wrote a bare document after the backfill — worth a look, not a rollback. Confirm after
the rollout:

```js
db.projects.countDocuments({ team_ids: { $in: [null] } })   // must be 0
db.projects.countDocuments({ team_ids: { $size: 0 } })      // the projects no team owns
```

### 8c. Stored numbers that need recomputing

| What | Stale? | Recompute path |
| --- | --- | --- |
| `scan_update_deltas`, `scan_outdated_sets` | No — keyed by scan and branch, no team dimension. The team enters only when the comparison is read. | — |
| `projects.stats` | No — per project, no team dimension. | — |
| Team-scoped `compliance_reports` | **Yes.** Each stored `summary` covers the projects the team owned when the report ran, which under the scalar excluded every project attributed to a co-owner. | **None exists.** Reports are point-in-time artifacts and nothing rewrites one. Re-request the affected reports: `db.compliance_reports.find({scope: "team"}, {_id: 1, scope_id: 1, requested_at: 1})`. |
| Redis `update_freq_cmp:*` and `update_frequency:*` | **Yes**, for up to 30 minutes. The cached row carries the retired `team_name` key, which deserialises into a row with an empty team list. | Self-healing on TTL. To avoid serving it: `redis-cli --scan --pattern 'update_freq*' \| xargs -r redis-cli del`. |

### 8d. API contract

`team_name: string \| null` is gone from the project list and from the update-frequency comparison
row. Both now carry `teams: [{id, name}]`, ordered by name, empty when no team owns the project. The
chat `list_projects` tool carries the same field instead of a bare `team_id`. The frontend consumes
this in the next phase; until then the team column renders blank.

### 8e. Metabase

A knowing hard cut. No card or saved query is defined in this repository, so the list below is by
field rather than by card — find the cards with Metabase's own "usage" view on the `projects` table.

- Anything reading `projects.team_id` still resolves, and to one arbitrary owner: the answers stay
  plausible and undercount every co-owned project. This is the dangerous class.
- Anything grouping by `projects.team_ids` buckets by the **whole array**, so `["A","B"]` and
  `["B","A"]` are two different groups and neither is team A. A per-team card must `$unwind` first.
- Anything that unwinds and then totals double-counts co-owned projects. An estate total must not
  unwind; a per-team breakdown must.
- "No team" is `team_ids: {$size: 0}` once §8b has run. `team_ids: null` matches nothing and
  `team_id: null` will stop matching anything at the cutover.
