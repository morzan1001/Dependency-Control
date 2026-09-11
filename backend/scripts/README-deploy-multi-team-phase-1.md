# Deploy runbook — multi-team projects Phase 1

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

A project stops belonging to one team and starts belonging to several. `team_ids` is the one
ownership field — every entry grants that team's members access **and** attributes the project to
them — and `team_sources` records which provider established each owner.

## 0. What ships, and in what order

**Two images, one change.** The backend image carries every behaviour change below at once; the
frontend image is the UI for it. There is no intermediate release, and nothing here can be
scheduled for "the next phase".

| Step | What | Reversible on its own? |
| --- | --- | --- |
| 1 | Confirm what 1.9.26 already put in production | n/a — read-only |
| 2 | Re-measure the estate | n/a — read-only |
| 3–5 | Backfill `team_ids` / `team_sources` from the scalars | Yes, the fields are additive |
| 6 | **Gate**: `--verify` exits 0 | n/a |
| 7 | **Roll the backend image** — stops deriving, converts the writes, moves the reads | See §10 |
| 8 | **Roll the frontend image** — after §7, never before | Yes |
| 9 | Flush the cache, re-request team compliance reports, fix Metabase | n/a |

Steps 6 and 7 belong to **one maintenance window**; §6 explains why. Step 8 follows in the same
window. Steps 3–5 may run ahead of the window, but §6 makes you repeat step 4 if they did.

Both images are built from the same commit and carry the same tag. `VERSION` still read `1.9.26`
— the version production is already running — when this runbook was written, so bump it in the
feature PR before the release build, or there is no new tag to roll to.

The one behaviour that is genuinely staged is the scalar `team_id`: this deploy still writes it and
keeps its index, so the queries that have not moved yet keep working. Dropping it is a later
migration, and `backend/app/core/init_db.py` carries the `TODO(phase 8)` that pairs with it.

## 1. What 1.9.26 already put in production — verify, do not build

v1.9.26 already carries the `team_ids` / `team_sources` fields, the model that derives them on
read, the `team_ids` index, and the backfill script. **Nothing in this section is work**; it is
four checks that the ground you are standing on is the ground this runbook assumes.

### 1a. The running image

```bash
kubectl get pod -n dependency-control -l app.kubernetes.io/component=backend \
  -o jsonpath='{.items[0].spec.containers[0].image}{"\n"}'
```

Measured 2026-09-11: `ghcr.io/morzan1001/dependency-control:1.9.26`. If it is older than 1.9.26 the
fields do not exist yet and the rest of this runbook does not apply.

### 1b. The `team_ids` index

```js
db.projects.getIndexes().filter(i => i.name.includes("team_ids"))
```

Measured 2026-09-11: `team_ids_1` is **present**, with the default name and no options. That is
what startup would create, so the startup call is already a no-op. Nothing to do.

If it is ever missing, let startup create it — it builds in milliseconds at this collection size.
Build it by hand only if you have a reason to, and then **do not pass a `name`**:

```js
db.projects.createIndex({ team_ids: 1 })   // yields team_ids_1
```

An index on `team_ids` under any *other* name makes the startup `create_index` fail with
`IndexOptionsConflict` (code 85). That call is unguarded — no try/except around
`backend/app/core/init_db.py:259` — so the exception aborts `startup_event`, every backend pod
crashes, and the rolling update stalls at the first pod. Drop a wrongly-named index before
deploying:

```js
db.projects.dropIndex("old_index_name")
```

### 1c. The derivation is already live, and already materialising fields

1.9.26's model rewrites `team_ids` / `team_sources` from the scalar on **every read**, so any
document the code writes back in full comes out carrying them. Measured 2026-09-11: 20 of 750
projects had them for that reason alone, and one of those 20 had already drifted from its scalar.
This is the drift §6 is a gate against, and it is running now.

### 1d. The backfill script is in the image

```bash
kubectl exec -n dependency-control <backend-pod> -- \
  sh -c 'cd /app && python -m scripts.backfill_project_team_ids --help'
```

## 2. Re-measure the estate before you start

**Do not trust the numbers printed below.** The estate grows continuously — the count moved
between two of the measurements taken while this runbook was written. Take your own, in the same
session as the deploy, and use them as the expectations for §3–§5.

```js
db.projects.countDocuments({})                                              // estate
db.projects.countDocuments({ team_id: { $nin: [null, ""] } })               // has a scalar owner
db.projects.countDocuments({ team_id: { $in: [null, ""] } })                // has none
db.projects.countDocuments({ team_id: { $nin: [null, ""] },
                             team_source: { $in: [null, ""] } })            // owner, no provenance
db.projects.countDocuments({ team_ids: { $exists: true } })                 // already materialised
```

Measured 2026-09-11 against production, for orientation only:

| | Count |
| --- | --- |
| Projects | 750 |
| Teams | 29 |
| Findings | 18,119,561 |
| Projects with a scalar owner | 439 |
| Projects with no scalar owner | 311 |
| …of the 439, holding no `team_source` | 218 |
| Projects already carrying `team_ids` | 20 |
| Projects with more than one owner | 0 |

The 218 are the hand-assignments made before provenance was recorded. They are why §6b's second
query exists and why the backfill stamps a source-less scalar owner `manual`: an owner no provider
claims is an owner no sync can ever retire.

## 3. Dry-run the backfill

Run it as a Kubernetes **Job**, not `kubectl exec` — the autoscaler evicts backend pods and takes a
long `exec` with them. Use the Job and NetworkPolicy manifest from `README-deploy-waves-2-3.md` §2
(the volume, label and NetworkPolicy notes there all apply unchanged), with:

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_project_team_ids"]
```

`/app` is required — the script is invoked as a module and resolves `app.*` from there. Name the
Job `dc-migration`, as the sibling runbook does.

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

Wait for the Job **before** reading the logs: a log read against a still-running Job prints no
count line at all, which reads like a clean run.

Record `projects planned`. It must equal the drift count from §6b's first query taken at the same
time — that is the check, not a fixed number. Measured 2026-09-11 against production: **731 of
750** (planned 731; the other 19 already agree with their scalar). The run writes nothing.

## 4. Execute the backfill

A Job's pod template is immutable, so delete the dry-run Job before reusing the name:

```bash
kubectl delete job dc-migration -n dependency-control
```

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_project_team_ids", "--execute"]
```

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

Record `projects matched`. It must equal the `projects planned` from the same run. The script is
idempotent — a second dry-run immediately after reports `planned 0`.

## 5. Verify the fields exist

```js
db.projects.countDocuments({ team_ids: { $exists: false } })      // must be 0
db.projects.countDocuments({ team_sources: { $exists: false } })  // must be 0
```

Projects with no team carry an empty list `[]` and an empty dict `{}`.

A present map is not a complete one: an owner listed in `team_ids` that the map does not name
belongs to no provider, so no sync can ever retire it. §6b's second query counts those and must
also return **0**.

## 6. HARD GATE — the final backfill and the backend deploy, in one window

Read this before scheduling the backend deploy.

Between the backfill and that deploy, the stored `team_ids` goes stale on every team change: the
1.9.26 writers set the scalar `team_id` only, and the model quietly re-derives the list from it on
every read, so the drift is invisible. A measured example — stored `team_id='T_new'`,
`team_ids=['T_old']`, `team_sources={'T_old':'github','M1':'manual'}` — reads back today as
`team_ids=['T_new']`, `team_sources={'T_new':'github'}`. The moment the derivation goes, that same
document grants `T_old` access to a project it no longer owns and denies it to `T_new`.

**The gate, in order, inside one maintenance window:**

1. Run the backfill with `--execute` (§4).
2. Run `--verify` and confirm it exits **0** (§6a). Do not skip it: §5 checks only that the fields
   exist, and a stale field exists.
3. Roll the backend image (§7), then the frontend image (§8).

If the deploy slips past the window, start again at step 1 — anything that changed a team in
between has re-armed the drift.

Do not roll the backend image on its own schedule. Once the derivation is gone, the stored list is
what every reader acts on, and nothing maintains it until that same image converts the write paths.
They are the same image; §7 is not a separate release.

### 6a. Run the verification

```yaml
workingDir: /app
command: ["python", "-m", "scripts.backfill_project_team_ids", "--verify"]
```

It prints `projects disagreeing:` and `owners with no provenance:`, and exits **0** only when both
are zero, **2** otherwise. Both must read **0**.

Measured 2026-09-11 against production, before any backfill: disagreeing **731**, no-provenance
**0**, exit **2** — the expected pre-backfill state, and proof the gate detects it.

### 6b. The same two checks from mongosh

`--verify` runs exactly these filters, in this order. The first counts a document whenever its
stored `team_ids` or `team_sources` says anything other than the scalar does — including a document
that never received the backfill, and one whose `team_ids` is `null`, which is the one shape that no
longer loads into the model at all. A count of `0` means a re-run of the backfill would plan
nothing:

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
`team_source` is absent — 218 production projects were in that state on 2026-09-11 — precisely so
this count reaches zero. Unlike the first check it stays meaningful after the cutover, because no
writer from that image on can produce the shape.

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

## 7. Roll the backend image

```bash
kubectl rollout status deployment/dependency-control-backend -n dependency-control
```

If a pod crashes with an index error, stop — see §1b.

This one image stops deriving the fields, converts the write paths, and moves the reads onto the
list. From it on the backfill **must not be re-run**: it re-derives the list from the single scalar
and would truncate every multi-team project back to one team. `--verify` shares that fate — after
the cutover a co-owned project disagrees with its scalar by design, so §6's gate is meaningful only
up to and including this deploy.

### 7a. What changes for an operator

- Every ownership write keeps `team_id` / `team_source` pointing at one of the stored owners, so
  the queries still reading the scalar — the project list, the team filter, analytics — keep
  working. A co-owned project appears under **one** of its owners there until those queries move
  to `team_ids` in a later deploy; access itself already reads the list.
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
- **At 16 owners, `PUT` with a new `team_id` is refused too**, even though it replaces the manual
  subset and would therefore leave the project at or under the cap. Deliberate: both routes read
  the cap off the stored list, so the refusal never depends on who established an owner. The way
  out is to remove an owner first, or to `PUT` a team that already owns the project — an incumbent
  is exempt, so narrowing a capped project down to one of its own owners still works.
- An owner stored without a `team_sources` entry is read as a hand assignment, so no sync retires
  it and `PUT` with `team_id` replaces it along with the rest of the manual set. §6b's second query
  lists them; the backfill stamps them `manual` so none are left.

### 7b. Numbers that change, and by how much

A project counts **in full at every team that owns it**. Per-team figures therefore stop adding up
to the estate's — summing them exceeds it by one project per extra owner. That is the intended
result, not drift; a check that reconciles the two is now checking for the wrong thing.

### 7c. Startup normalises the owner shape — nothing to run by hand

`create_indexes` now sets `team_ids: []` on any project whose field is absent or null. Both shapes
answer no ownership filter and no `$size` test, so such a project was in no team view at all. It is
idempotent. Grep the first pod's log for:

```
Owner normalisation: gave N project(s) with no team_ids an empty owner list
```

Expect **N = 0**, or the small number of projects ingest created between §4 and this rollout: §5's
check already reported zero without the field. A large N means the backfill did not run — go back
to §4. Confirm after the rollout:

```js
db.projects.countDocuments({ team_ids: { $in: [null] } })   // must be 0
db.projects.countDocuments({ team_ids: { $size: 0 } })      // the projects no team owns
```

### 7d. API contract

`team_name: string | null` is gone from the project list and from the update-frequency comparison
row. Both now carry `teams: [{id, name}]`, ordered by name, empty when no team owns the project.
The chat `list_projects` tool carries the same field instead of a bare `team_id`.

Between this rollout and §8 the **old** frontend is reading the new contract: it looks for
`team_name`, does not find it, and renders a dash in the team column of the dashboard's project
table and the update-frequency comparison. Nothing else degrades, and §8 ends it. Keep the gap
short, but a missing team name is an honest blank — do not roll §8 first to close it.

## 8. Roll the frontend image — after §7, never before

A frontend image ships with this change and must roll **after** the backend.

```bash
kubectl rollout status deployment/dependency-control-frontend -n dependency-control
```

Against a 1.9.26 backend the new UI is broken in two ways, neither of which announces itself:

- `POST /projects/{id}/teams` and `DELETE /projects/{id}/teams/{team_id}` do not exist yet, so
  adding or removing an owning team fails with **404**.
- The dashboard's project table and the update-frequency comparison read `teams`, and a 1.9.26
  backend sends `team_name`. The owning-teams cell falls back to its empty state and prints
  **"Unassigned"** on every row — a positive claim that nothing owns the project, for 439 projects
  that have an owner.

The new UI adds the owning-teams editor to the project settings page, and the owning-teams cell
(first name, plus a `+N` badge carrying the rest in its tooltip) to the dashboard's project table
and the update-frequency comparison.

## 9. After the rollout

### 9a. Flush the update-frequency cache — required

**Not optional.** A cached row carries the retired `team_name` key, which deserialises into a row
with an empty team list, which the new UI renders as **"Unassigned"** — a false statement about
ownership, where the old UI showed a neutral dash. The entries live up to 30 minutes; do not serve
them for 30 minutes.

Dragonfly requires TLS on its client port, so a bare `redis-cli` fails with
`ERR Bad TLS header`. Use the no-TLS admin port, and target the **master** — a delete on the
replica does not propagate:

```bash
MASTER=$(kubectl get pod -n dependency-control -l app=dependency-control-dragonfly,role=master \
  -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n dependency-control "$MASTER" -- sh -c \
  'redis-cli -p 9999 --scan --pattern "update_freq*" | xargs -r redis-cli -p 9999 del'
```

The glob covers both affected key families, `update_freq_cmp:<scope>:<team>` and
`update_freq:<project>`. Confirm it is empty:

```bash
kubectl exec -n dependency-control "$MASTER" -- \
  sh -c 'redis-cli -p 9999 --scan --pattern "update_freq*" | wc -l'   # 0
```

### 9b. Stored numbers that need recomputing

| What | Stale? | Recompute path |
| --- | --- | --- |
| `scan_update_deltas`, `scan_outdated_sets` | No — keyed by scan and branch, no team dimension. The team enters only when the comparison is read. | — |
| `projects.stats` | No — per project, no team dimension. | — |
| Team-scoped `compliance_reports` | **Yes.** Each stored `summary` covers the projects the team owned when the report ran, which under the scalar excluded every project attributed to a co-owner. | **None exists.** Reports are point-in-time artifacts and nothing rewrites one. Re-request the affected reports: `db.compliance_reports.find({scope: "team"}, {_id: 1, scope_id: 1, requested_at: 1})`. Measured 2026-09-11: the collection holds **0** documents, so there is nothing to re-request today — run the query anyway, it costs nothing and the collection fills up over time. |
| Redis `update_freq_cmp:*` and `update_freq:*` | **Yes**, for up to 30 minutes. | §9a — required, not self-healing on an acceptable timescale. |

### 9c. Metabase

A knowing hard cut. No card or saved query is defined in this repository, so the list below is by
field rather than by card — find the cards with Metabase's own "usage" view on the `projects` table.

- Anything reading `projects.team_id` still resolves, and to one arbitrary owner: the answers stay
  plausible and undercount every co-owned project. This is the dangerous class.
- Anything grouping by `projects.team_ids` buckets by the **whole array**, so `["A","B"]` and
  `["B","A"]` are two different groups and neither is team A. A per-team card must `$unwind` first.
- Anything that unwinds and then totals double-counts co-owned projects. An estate total must not
  unwind; a per-team breakdown must.
- "No team" is `team_ids: {$size: 0}` once §7c has run. `team_ids: null` matches nothing, and
  `team_id: null` will stop matching anything when the scalar is dropped.

## 10. Rollback

Rolling back is possible and it is **lossy**. Decide with the numbers, not the adjective.

### 10a. What it costs

Reverting the backend to 1.9.26 restores the model that derives `team_ids` from the scalar on every
read. For every project with more than one owner, that means:

- **Every co-owner's access silently disappears.** The list reads back as the single mirrored
  scalar owner. No error, no log line, no UI difference — the members of the dropped teams simply
  stop seeing the project.
- The truncation becomes permanent for any project the old code writes back in full, because the
  derived value is what gets stored.
- Drift is re-armed immediately: the 1.9.26 write paths set only the scalar again.
- Rolling forward a second time therefore needs a fresh `--execute` + `--verify`. But the backfill
  derives the list **from the scalar**, so it cannot restore what was dropped — it re-creates
  single-owner projects. Co-ownerships added during the forward window are gone and must be
  re-entered by hand.

What survives: the mirrored scalar always names a team that genuinely owns the project (the
incumbent while it is still an owner, otherwise the first of the sorted list), so every project
keeps exactly one working owner. Nothing loses all of its access.

### 10b. Price the rollback before you take it

```js
db.projects.countDocuments({ "team_ids.1": { $exists: true } })   // projects that lose an owner
db.projects.aggregate([
  { $match: { "team_ids.1": { $exists: true } } },
  { $group: { _id: null, n: { $sum: { $subtract: [ { $size: "$team_ids" }, 1 ] } } } }
])                                                                 // owner grants dropped
```

Measured 2026-09-11: **0** and **0** — no project had a second owner yet. That is the number that
makes an immediate rollback free, and it stops being true the moment the new UI is in anyone's
hands. Take it before rolling back, not from this page.

Capture the list first, so the co-ownerships can be re-entered:

```js
db.projects.find({ "team_ids.1": { $exists: true } },
                 { name: 1, team_id: 1, team_ids: 1, team_sources: 1 })
```

### 10c. The procedure

1. **Frontend first**, the reverse of the forward order — the new UI against a rolled-back backend
   404s on the add/remove routes and prints "Unassigned" everywhere (§8).
   ```bash
   kubectl rollout undo deployment/dependency-control-frontend -n dependency-control
   kubectl rollout status deployment/dependency-control-frontend -n dependency-control
   ```
2. Capture the co-ownership list (§10b) — after the backend rolls back, the reads no longer show
   it.
3. **Backend.**
   ```bash
   kubectl rollout undo deployment/dependency-control-backend -n dependency-control
   kubectl rollout status deployment/dependency-control-backend -n dependency-control
   ```
4. Flush the cache again (§9a). The rows cached by the new backend carry `teams` and no
   `team_name`, and the old UI renders them with an empty team column.
5. Leave `team_ids`, `team_sources` and the `team_ids_1` index in place. They are additive, 1.9.26
   overwrites them harmlessly on read, and dropping them only makes the roll-forward slower.

To roll forward again, restart at §4 — not §7. The window's `--execute` is stale by exactly the
team changes made since.
