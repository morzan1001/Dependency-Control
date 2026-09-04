# Deploy runbook — release flag and the historical tag-build backfill

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

Run the backfill as a Kubernetes **Job**, never via `kubectl exec`: the autoscaler evicts backend
pods and a long exec dies with them. The Job manifest, its labels and its NetworkPolicy are in
`README-deploy-waves-2-3.md` section 2 — nothing about them changes here.

Order: indexes, then the rescan brake, then deploy, then the lineage collapse, then dry run,
then execute.

---

## 1. Build the indexes before the deploy

`create_indexes` runs in the startup path, so a build there stalls the rollout. Build them by hand
first; the startup call then finds them and is a no-op.

Two of the three are on `releases`, which does not exist yet, so they are instant. The third is a
partial index over `is_release: true`, and every production scan predates the field — so it is
empty **now** and expensive **after** the backfill. Build it before, not after.

```js
db.releases.createIndex(
  { project_id: 1, environment: 1, released_at: -1 },
  { name: "releases_latest_lookup" }
)
db.releases.createIndex(
  { project_id: 1, environment: 1, scan_id: 1 },
  { name: "releases_upsert_key", unique: true }
)
db.scans.createIndex(
  { project_id: 1, is_release: 1, created_at: -1 },
  { name: "scans_released_list", partialFilterExpression: { is_release: true } }
)
```

Verify: `db.releases.getIndexes()` lists both, `db.scans.getIndexes()` lists `scans_released_list`.

`releases_upsert_key` is what makes the backfill safe to re-run: the release upsert is keyed on
`(project_id, environment, scan_id)`, and without the unique index a retry can insert a second row
for one deployment.

---

## 2. Decide the scheduled-rescan burst before you deploy

**This section is not optional.** The rescan due-clock moved from the project onto the source scan
in this release, and the brake that used to throttle it is gone. Read the live settings — the
model defaults (`global_rescan_enabled: false`, `global_rescan_interval: 24`) are *not* what
production runs, and reading them instead of the document understates the wave by a lot:

```js
db.system_settings.findOne({}, { global_rescan_enabled: 1, global_rescan_interval: 1, rescan_mode: 1 })
```

As measured: `global_rescan_enabled: true`, `global_rescan_interval: 730` (hours, ~30 days),
`rescan_mode: "global"`, across 730 projects.

### Why there is a wave

The due decision reads `last_rescanned_at` on the source scan and falls back to that scan's
`created_at`. No production scan has ever been stamped, so on the first housekeeping pass after
the deploy every project whose newest usable scan is older than 730 h is due at once.

### Why it does not repeat

`last_rescanned_at` is stamped on the source at creation time, before the job is handed to the
worker. Each source therefore enqueues once per interval; the wave does not come back on the next
300 s main-loop pass. Worst case is one job per project inside a single main-loop interval, which
stays under the worker's 1000-job startup recovery cap.

### Count the real population — do not estimate it

Run this in the deploy window, against production, before deciding:

```js
const INTERVAL_MS = 730 * 60 * 60 * 1000;
db.scans.aggregate([
  { $match: { status: { $in: ["completed", "completed_with_errors"] },
              is_rescan: { $ne: true },
              sbom_refs: { $exists: true, $ne: [] } } },
  { $sort: { project_id: 1, created_at: -1 } },
  { $group: { _id: "$project_id", tip: { $first: "$$ROOT" } } },
  { $match: { $expr: { $lt: [ { $ifNull: ["$tip.last_rescanned_at", "$tip.created_at"] },
                              { $subtract: ["$$NOW", INTERVAL_MS] } ] } } },
  { $count: "due_projects" }
])
```

That is one rescan per project listed. Subtract the projects that opt out:

```js
db.projects.countDocuments({ rescan_enabled: false })
db.projects.countDocuments({ last_scan_at: null })   // never scanned; housekeeping skips them
```

### Option A — brake, seed, release (preferred)

1. Before the deploy, switch the scheduler off:

   ```js
   db.system_settings.updateOne({}, { $set: { global_rescan_enabled: false } })
   ```

2. Deploy (section 3), collapse the rescan lineage pointers (section 4) and run the backfill
   (sections 5–6).

3. Seed `last_rescanned_at`, one tranche per **cohort day**. The seed is not a delay switch: it
   backdates the clock, and cohort `k` is stamped so that it comes due `k` days from now. You are
   choosing the day each cohort fires. Stamping every tranche at `$$NOW` instead — the obvious
   thing — moves the whole fleet's due date to one moment 730 h out and hands the unattended burst
   to whoever is on duty then.

   Run this once per cohort, raising `COHORT_DAY` by one each time, until a run selects nothing.
   Nothing fires yet: the scheduler is still off.

   ```js
   const INTERVAL_MS = 730 * 60 * 60 * 1000;   // global_rescan_interval, as read in this section
   const ONE_DAY_MS  = 24 * 60 * 60 * 1000;
   const TRANCHE     = 100;
   const COHORT_DAY  = 1;                      // this cohort becomes due in COHORT_DAY days

   const tips = db.scans.aggregate([
     { $match: { status: { $in: ["completed", "completed_with_errors"] },
                 is_rescan: { $ne: true },
                 sbom_refs: { $exists: true, $ne: [] } } },
     { $sort: { project_id: 1, created_at: -1 } },
     { $group: { _id: "$project_id", tip_id: { $first: "$_id" },
                 tip_stamp: { $first: "$last_rescanned_at" } } },
     { $match: { tip_stamp: null } },
     { $limit: TRANCHE }
   ]).toArray().map(r => r.tip_id);

   db.scans.updateMany({ _id: { $in: tips } }, [
     { $set: { last_rescanned_at: { $subtract: ["$$NOW", INTERVAL_MS - COHORT_DAY * ONE_DAY_MS] } } }
   ]);
   ```

   The stamp filter sits after the `$group` because only the group's `$first` — the newest usable
   original — is a document the scheduler reads. Filtering unstamped scans before the group would
   re-select a project already seeded by an earlier cohort and stamp its next-newest scan instead,
   leaving the project itself due immediately.

   Each cohort therefore takes `TRANCHE` projects that no cohort has touched: with `TRANCHE = 100`
   and 730 projects, at most eight cohorts over eight days, the last of them short. The run after
   the last one selects nothing, which is how you know the fleet is seeded. Every cohort then
   repeats on its own day, 730 h apart, so the fleet stays spread for good instead of re-converging.

   Sanity-check the spread before re-enabling the scheduler — one row per day, none in the past:

   ```js
   const INTERVAL_MS = 730 * 60 * 60 * 1000;
   db.scans.aggregate([
     { $match: { last_rescanned_at: { $ne: null } } },
     { $project: { due: { $add: ["$last_rescanned_at", INTERVAL_MS] } } },
     { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$due" } }, n: { $sum: 1 } } },
     { $sort: { _id: 1 } }
   ])
   ```

4. The backfill adds a second rescan target per project: a marked release is re-evaluated in its
   own right, and the tag builds it marks are old and unstamped, so they are due immediately. Seed
   them the same way, and give them their own cohort days after the ones used in step 3 so the two
   populations do not land together:

   ```js
   const INTERVAL_MS = 730 * 60 * 60 * 1000;
   const ONE_DAY_MS  = 24 * 60 * 60 * 1000;
   const COHORT_DAY  = 9;

   db.scans.updateMany({ is_release: true, last_rescanned_at: null }, [
     { $set: { last_rescanned_at: { $subtract: ["$$NOW", INTERVAL_MS - COHORT_DAY * ONE_DAY_MS] } } }
   ]);
   ```

   That stamps the whole release population onto one day. If `releases to record` from section 6 is
   more than a day's worth of work, split it across successive cohort days the same way step 3
   does — select a `$limit`ed batch of ids first, then update only those.

5. Confirm the due count is zero — every source is now stamped for a future day — confirm
   section 4 reports no pointers left to rewrite, and switch the scheduler back on:

   ```js
   // "Count the real population" above must return no due_projects, and this must return 0
   db.scans.countDocuments({ is_release: true, last_rescanned_at: null })
   db.system_settings.updateOne({}, { $set: { global_rescan_enabled: true } })
   ```

   From here the first cohort fires on day 1 and the rest follow one per day. Watch the first
   cohort land before trusting the rest.

### Option B — take the burst deliberately

Skip the brake, and watch it land. Acceptable when the count from the aggregation is small enough
for the worker pool and the window is quiet. Take the brake for the rollout itself even so: the
scans section 4 collapses are the ones the burst rescans, and a rescan that lands first is
discarded on a project whose chain is deeper than the walk's bound.

### What to watch either way

* `worker_queue_size` — the queue depth gauge. It should rise once and drain, not step up again
  every 300 s. A second step means the clock is not being stamped and the wave is repeating.
* Backend logs for `Recovery limit (1000) reached` on a pod restart: the backlog outgrew what a
  restarting pod will re-queue, and the remainder waits for housekeeping's stuck-scan sweep.
* `db.scans.countDocuments({ status: "pending" })` before and an hour after the first cycle.
* **Branch census query cost.** The census `distinct` now carries `$expr: { $ne: ["$branch",
  "$commit_tag"] }`, which no index can serve, so the per-project scan on `project_id` is followed
  by a filter over its matches. It runs once per project every 6 h. Measure it on prod once — pick
  the project with the most scans and time the `distinct` — rather than assuming either way:

  ```js
  const worst = db.scans.aggregate([{ $sortByCount: "$project_id" }, { $limit: 1 }]).toArray()[0];
  db.scans.explain("executionStats").distinct(
    "branch", { project_id: worst._id, $expr: { $ne: ["$branch", "$commit_tag"] } })
  ```
* **Scans on branch `unknown`.** When a tag pipeline runs and neither provider yields a default
  branch, the scanner falls back to the literal branch `unknown`. Its `commit_tag` differs from it,
  so the census counts `unknown`, the VCS has no such branch, and it is filed as deleted — hiding
  that scan behind the same filters the tag names used to hide behind. It fails visibly and only
  where the provider gave nothing back. Check for it after the first tag pipelines land:

  ```js
  db.scans.countDocuments({ branch: "unknown", commit_tag: { $nin: [null, ""] } })
  ```

---

## 3. Deploy

```
kubectl rollout status deployment/dependency-control-backend -n dependency-control
kubectl get pods -n dependency-control     # no old ReplicaSet pods left
```

Nothing changes for existing data at this point: every scan has `is_release` absent, which the
resolver, the retention cursors and the rescan target query all read as "not a release".

Two other behaviour changes ship with this deploy and are visible without any release being marked:

* **The scan delta now excludes waived findings.** Counts on the delta screen fall wherever a
  waiver applies. That is the delta agreeing with stats, impact, hotspots and crypto trends.
* **The branch census skips scans whose branch is their own commit tag.** The 6-hourly branch sync
  rebuilds `deleted_branches` from the distinct branches in `db.scans`, so without this the sync
  would put every historical tag name straight back after the backfill pruned it.

  This lands on **every project with a VCS connection at its first sync after the deploy**, whether
  or not the backfill has run, and `deleted_branches` shrinking has five visible consequences:

  1. Projects show fewer deleted branches.
  2. **Historical tag names flip from deleted to active in the branch selector.** The selector's
     list comes from an unfiltered `distinct` over `scans.branch`, so the tag names stay in it; only
     their status changes. They disappear from the list only if their scans are deleted.
  3. **A tag name can win the branch view's default.** `resolve_default_branch` keeps the
     configured default only while it is *active*, and otherwise picks the active branch with the
     newest usable scan. For a project whose configured default was never itself scanned, the tag
     names are now candidates and a recent one can win. This moves which branch the project view
     opens on; the stored `Project.default_branch` is untouched.
  4. **A project's representative scan for all analytics can settle on a tag build.** Two writers
     of `latest_scan_id` meet here. `get_latest_active_scan_ids` takes the stored pointer as its
     fast path as soon as `deleted_branches` is empty, instead of recomputing with `$nin`. And
     `sync_project_branches` repoints a pointer whose scan sits on a branch it has just filed as
     deleted — a tag name is no longer such a branch, so the 6-hourly sync leaves a tag build in
     the slot rather than moving the project onto its newest non-tag scan within a sync window.
  5. **`Project.stats` and `Project.last_scan_at` follow the pointer.** That same repoint writes
     all three fields together, so wherever it no longer fires these two keep the tag build's
     numbers and date. Project lists, tiles and dashboards read them straight off the project
     document without going through `get_latest_active_scan_ids`, so they follow a tag build even
     where consequence 4's fast path is not involved.

  Measured against `sync_project_branches` on one project with a tag build as its newest scan and
  its stored pointer, plus an older `main` scan, varying only whether the census counts the tag as
  a branch:

  ```
  census counts the tag: deleted_branches=['v1.2.3'] latest_scan_id=mainbuild last_scan_at=2026-07-01
  census skips the tag : deleted_branches=[]         latest_scan_id=tagbuild  last_scan_at=2026-08-01
  ```

  `stats` moves with `last_scan_at` in both rows.

  Consequences 3 to 5 all resolve to a real, usable scan: they change *which* scan a project speaks
  for, not whether it has one, and a tag build holds the slot only while it is the genuinely newest
  ingested scan.

  Before the deploy, list the projects where 4 and 5 will bite. Do not ask which pointers name a
  tag build today: while the sync still repoints, a settled project's pointer names the branch scan
  it was moved to, so that question only returns tag builds ingested inside the last 6 h. Ask
  instead which projects have a tag build as their newest usable scan:

  ```js
  db.projects.aggregate([
    { $match: { $or: [ { gitlab_instance_id: { $exists: true, $ne: null } },
                       { github_instance_id: { $exists: true, $ne: null } } ] } },
    { $lookup: {
        from: "scans",
        let: { pid: "$_id" },
        pipeline: [
          { $match: { $expr: { $eq: ["$project_id", "$$pid"] },
                      status: { $in: ["completed", "completed_with_errors"] } } },
          { $sort: { created_at: -1 } },
          { $limit: 1 },
          { $project: { branch: 1, commit_tag: 1, created_at: 1 } } ],
        as: "newest" } },
    { $set: { newest: { $first: "$newest" } } },
    { $match: { "newest.commit_tag": { $nin: [null, ""] },
                $expr: { $eq: ["$newest.branch", "$newest.commit_tag"] } } },
    { $project: { name: 1, pointer: "$latest_scan_id", newest_scan_id: "$newest._id",
                  tag: "$newest.branch", newest_at: "$newest.created_at" } }
  ])
  ```

  Where `pointer` already equals `newest_scan_id`, the project reports the tag build from its first
  sync after the deploy. Where they differ, the pointer is sitting on the older branch scan the
  sync moved it to and stays there until the project's next ingest repoints it. The VCS filter is
  the sync's own: a project without one has nothing recomputing its census either way.

  For 3, call `GET /api/v1/projects/{project_id}/branches` on a couple of those projects before and
  after the first sync and compare which entry carries `is_default`.

---

## 4. Collapse the rescan lineage pointers

**Run this before the scheduler is allowed to fire again** — Option A step 5, or the rollout under
Option B.

`Scan.original_scan_id` names the scan a rescan lineage descends from, and every reader treats it
as the root: the latest-scan guard compares it against the incoming rescan's root, the scan-history
endpoint collects a family by it, and retention exempts whatever it names. Production carries
chains whose links name their immediate parent instead — `head → r1 → r2`, each pointing one step
up.

The guard walks such a chain rather than trusting the one hop, so a project on a short chain keeps
working. The walk is bounded at ten hops, so a project that has taken more than ten scheduled
rescans does not: its walk stops mid-chain, the roots never match, and its `latest_scan_id`,
`stats` and `last_scan_at` hold their pre-deploy values through every rescan that follows.

Size it first. Projects whose pointer names a rescan whose own pointer names a rescan — the shape
the guard has to walk at all:

```js
db.projects.aggregate([
  { $match: { latest_scan_id: { $ne: null } } },
  { $lookup: { from: "scans", localField: "latest_scan_id", foreignField: "_id", as: "cur" } },
  { $set: { cur: { $first: "$cur" } } },
  { $match: { "cur.is_rescan": true, "cur.original_scan_id": { $ne: null } } },
  { $lookup: { from: "scans", localField: "cur.original_scan_id", foreignField: "_id", as: "parent" } },
  { $set: { parent: { $first: "$parent" } } },
  { $match: { "parent.is_rescan": true } },
  { $count: "frozen_projects" }
])
```

And the pointers the run rewrites — this one is also the verification, so note the number:

```js
db.scans.aggregate([
  { $match: { is_rescan: true, original_scan_id: { $ne: null } } },
  { $lookup: { from: "scans", localField: "original_scan_id", foreignField: "_id", as: "parent" } },
  { $set: { parent: { $first: "$parent" } } },
  { $match: { "parent.is_rescan": true } },
  { $count: "pointers_to_rewrite" }
])
```

Then:

```
python -m scripts.backfill_rescan_lineage
python -m scripts.backfill_rescan_lineage --limit 20 --execute    # smoke test
python -m scripts.backfill_rescan_lineage --execute
```

The dry run computes the plan and stops; `--execute` applies that same plan, so the report is the
change list. `pointers to rewrite` matches `pointers_to_rewrite` above, less anything the run
reports as unresolved.

`unresolved, past the bound` counts rescans still more than ten links above their root, and the run
names each one. Re-run it: every pass shortens the chain beneath them, so the count falls to zero.
A count that stops falling is a pointer cycle, and the ids it names need a human.

Verify by re-running the second query: it must return no rows.

Retention exempts a scan named by an `original_scan_id`, so the intermediate links lose that
exemption and age out on their normal retention date. Lineage does not go with them: every rescan
names the root directly, which is where the scan-history endpoint collects the family from.

---

## 5. Dry run the backfill

```
python -m scripts.backfill_release_flags
```

Read the report. `releases to record` is the number of historical tag builds; `projects to prune`
is how many projects carry the tag name of a released tag build in `deleted_branches`. The dry run
computes the plan and stops; `--execute` applies that same plan, so the report is the change list.

Cross-check the population independently:

```js
db.scans.countDocuments({
  status: { $in: ["completed", "completed_with_errors"] },
  is_rescan: { $ne: true },
  $expr: { $and: [ { $ne: ["$commit_tag", null] }, { $eq: ["$branch", "$commit_tag"] } ] }
})
```

The two numbers agree unless a scan is already released (reported as `already released`) or has no
`created_at` (reported as `skipped, no created_at` — a release has to be dated, so those are left
for a human).

---

## 6. Execute

```
python -m scripts.backfill_release_flags --limit 20 --execute    # smoke test
python -m scripts.backfill_release_flags --execute
```

`--batch-size` and `--sleep-ms` throttle both the walk and the writes. Defaults are 500 and 50 ms.

Re-running is safe, from any point a run can be killed at. A scan that already has a release row is
skipped rather than marked again; one left holding only its row — a run killed between its two
writes — has just its flag set, counted on the `of those, flags to repair` line; and a run killed
before its prunes leaves tag names in `deleted_branches` that the next run plans and drops, because
the prune is planned from every released tag build the walk sees, not only from this run's.

A consequence of that: the run also drops the tag name of a tag build released through the API
before the backfill, which is the same name the branch census would drop on its next pass anyway.

---

## 7. Verify

```js
db.releases.countDocuments({ environment: "production" })   // == "releases to record"
db.releases.distinct("scan_id").length                       // == the next line
db.scans.countDocuments({ is_release: true })
```

The last two must be equal, and stay equal: a scan whose flag is set but whose row is missing
resolves to nothing in `latest_release_scan` and the release list, and a scan with a row but no
flag is missing from the `scans_released_list` index the released-only scan list reads.

```js
db.releases.find({}, { project_id: 1, scan_id: 1, version: 1, released_at: 1 }).limit(5)
```

Every row the backfill wrote must name a `version` equal to the scan's `commit_tag` and a
`released_at` equal to that scan's `created_at`. A row marked through the API can legitimately have
no `version` at all — a deploy job that named neither a version nor a tag — but never a blank one:

```js
db.releases.countDocuments({ version: "" })   // must be 0
```

Then confirm no project still hides a marked tag name:

```js
db.projects.find({ deleted_branches: { $exists: true, $ne: [] } }, { name: 1, deleted_branches: 1 })
```

Finally, open a project that gained a release and check the Releases list renders it, and that the
Pipelines table's release filter returns the same scan.

---

## 8. After the backfill

**No new release will be marked until consumer pipelines act.** The backend accepts the mark, but
nothing sends one: a pipeline has to pin scanner **1.2.0 or newer** *and* set
`DEP_CONTROL_IS_RELEASE=true` on its deploy job. Until both are true for a project, its release list
stops at whatever the backfill wrote and looks frozen. This is the single most likely reason
someone reports the feature as broken. `ci-cd/gitlab-ci.example.yaml` and
`ci-cd/github-workflow.example.yaml` show the variables; `scanner.sh help` lists all three.

The same applies to the tag-versus-branch fix: only a pipeline running 1.2.0 stops recording the
tag as the scan's branch. Older pinned scanners keep producing tag builds that look like the ones
the backfill just cleaned up.

Watch the first project that adopts it:

```js
db.releases.find({ released_at: { $gt: new Date(Date.now() - 24*60*60*1000) } })
```

Release scans are exempt from retention and refuse to archive. A release that should age out has
to be withdrawn first: `DELETE /api/v1/projects/{project_id}/scans/{scan_id}/release`.

## Rollback

The backfill is reversible without a second script. Drop the rows it created, then recompute the
flag from what is left:

```js
db.releases.deleteMany({ environment: "production" })
const stillReleased = db.releases.distinct("scan_id");
db.scans.updateMany({ is_release: true, _id: { $nin: stillReleased } }, { $set: { is_release: false } })
```

Delete the `production` rows only if no deployment has marked one through the API since the
backfill; otherwise restrict the delete to the scan ids the run reported.

Pruned `deleted_branches` entries are not restored by that, and cannot be restored by waiting: the
6-hourly branch sync now leaves tag builds out of the census, so it recomputes the same pruned
list. Reverting that needs the image rolled back, not a database write.
