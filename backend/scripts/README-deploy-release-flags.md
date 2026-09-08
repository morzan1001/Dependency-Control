# Deploy runbook — release flag, the historical tag-build backfill, and the ad-hoc analyze endpoint

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

Run every backfill as a Kubernetes **Job**, never via `kubectl exec`: the autoscaler evicts backend
pods and a long exec dies with them. The Job manifest, its labels and its NetworkPolicy are in
`README-deploy-waves-2-3.md` section 2 — nothing about them changes here.

---

## 0. The order to work in

Every step is here, in the order it has to run. Sections 1–9 explain each one; this list is what you
tick off. Nothing below is optional, and steps 8 and 9 have no script behind them.

1. **Pause the scheduled rescanner** for the whole window (§2, Option A step 1), so the wave cannot
   fire in the middle of a backfill.
2. **Build the four indexes by hand** (§1) before rolling the image, so startup's `create_indexes`
   finds them and is a no-op.
3. **Size the change on production, before deciding anything** (§2 and §3). Five numbers:
   the due-project count **plus the release-row count** against the worker's 1000-job recovery cap;
   the dangling-pointer count; the no-pointer count; the `pointer_off_default_branch` count; and the
   `head_moves_to_a_rescan` count. The last two are the populations whose headline numbers move
   most, and neither is visible in the first two.
4. **Deploy** (§3).
5. **`backfill_rescan_lineage`** (§4) — dry run, `--execute`, then a **second `--execute`**. Chains
   deeper than `MAX_RESCAN_HOPS = 10` need the second pass, because each pass shortens the chain
   beneath them. Read the script's own exit code, not `tail`'s: `cmd | tail -8; echo $?` reports
   tail's status and has already produced one wrong reading.
6. **`backfill_release_flags`** (§5, §6) — dry run, `--execute`, then re-run and confirm a clean
   `0 / 0 / 0` no-op.
7. **Verify** (§7), including the two flag/row mismatch queries.
8. **Re-stamp the waiver flags on released builds** (§8). One in-pod pass; without it a build in
   production keeps answering through the waiver set of the day it was analysed.
9. **Grant `analyze:adhoc`** (§9). Until someone does, **no user, including the platform admin,
   can mint an ad-hoc key** — the permission is new and nothing backfills it onto existing users.
10. **Re-enable the scheduler** (§2, Option A step 5) and watch the first two 300 s passes for
    `Recovery limit (1000) reached`.

---

## 1. Build the indexes before the deploy

`create_indexes` runs in the startup path, so a build there stalls the rollout. Build them by hand
first; the startup call then finds them and is a no-op.

Two of the four are on `releases`, which does not exist yet, so they are instant. The third is a
partial index over `is_release: true`, and every production scan predates the field — so it is
empty **now** and expensive **after** the backfill. Build it before, not after. The fourth replaces
an index on the largest collection in production and is the one that actually takes time.

```js
db.releases.createIndex(
  { project_id: 1, environment: 1, released_at: -1, _id: 1 },
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
db.scans.createIndex({ project_id: 1, status: 1, created_at: -1, _id: 1 })
```

Verify: `db.releases.getIndexes()` lists both, `db.scans.getIndexes()` lists `scans_released_list`.

The date-ordered picks tie-break on `_id`, so the trailing `_id: 1` is load-bearing: without it the
scheduled-rescan tip pick becomes a blocking sort over every usable scan of the project, ~211k
times a day. Confirm the plan before you deploy:

```js
db.scans.find(
  { project_id: "<any project>", status: { $in: ["completed", "completed_with_errors"] },
    sbom_refs: { $exists: true, $ne: [] }, is_rescan: { $ne: true } }
).sort({ created_at: -1, _id: 1 }).limit(1).explain("executionStats")
```

What to accept:

* `topStage` is `LIMIT`, and **no `SORT` stage appears in the winning plan**. That is the property
  the index buys. `SORT_MERGE` under the `FETCH` is *not* a blocking sort — it is the two branches
  of the `status: {$in: [...]}` bound read in index order and interleaved — so a plan of
  `LIMIT → FETCH → SORT_MERGE` is the healthy one.
* `docsExamined` is **the number of rescans newer than the tip, plus one** — not 1. `is_rescan` and
  `sbom_refs` are not in the index and a rescan carries `created_at = now`, so every rescan sitting
  above the tip in index order is fetched and rejected before the tip is reached. Measured on a
  project with one rescan of its tip: `topStage: LIMIT`, no `SORT`, `docsExamined: 2`,
  `nReturned: 1`. Only a project that has never been rescanned reads 1, so testing against one is
  how you get a criterion that fails on healthy data.

Then drop the superseded 3-key index, `db.scans.dropIndex("project_id_1_status_1_created_at_-1")`.
Startup does this itself, but doing it by hand keeps the rollout off the largest collection.

`releases_upsert_key` is what makes the backfill safe to re-run: the release upsert is keyed on
`(project_id, environment, scan_id)`, and without the unique index a retry can insert a second row
for one deployment.

Build it before anything writes to `releases`, not after. Over a collection that already holds two
rows with one `(project_id, environment, scan_id)`, the build fails with `Index build failed …
E11000` and leaves the collection unindexed — and a backfill or a deploy that ran without the index
is exactly what produces such a pair. If the build fails, list the offenders, keep the newest row of
each group, delete the rest and build again:

```js
db.releases.aggregate([
  { $group: {
      _id: { project_id: "$project_id", environment: "$environment", scan_id: "$scan_id" },
      ids: { $push: "$_id" },
      n: { $sum: 1 }
  } },
  { $match: { n: { $gt: 1 } } }
])
```

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
300 s main-loop pass.

### How big the worst case actually is

**Not one job per project.** `_rescan_targets` returns the branch tip **plus one target per release
environment the project has**, and after the backfill every historical tag build is a release with
an unstamped clock. The worst case inside a single main-loop interval is therefore

```
due_projects  +  release rows whose scan has no last_rescanned_at
```

against the worker's 1000-job startup recovery cap (`worker.py`). Step 4 of Option A already seeds
the release population for this reason; the sum is what decides whether Option A is merely
preferred or required. Count both halves in the same window — the second number is the one the
per-project query below cannot see:

```js
db.scans.countDocuments({
  _id: { $in: db.releases.distinct("scan_id") },
  last_rescanned_at: null,
  status: { $in: ["completed", "completed_with_errors"] },
  sbom_refs: { $exists: true, $ne: [] }
})
```

If `due_projects + that number` approaches 1000, Option A is required, not preferred.

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
* **Crypto assets uploaded through the CBOM endpoint, on any project the wave rescans.** A rescan
  re-derives crypto assets from the SBOM it copies, so assets embedded in an SBOM survive. Assets
  posted separately to `/cbom` have no such source: they are keyed to the scan they were posted
  against, every reader looks them up by scan id, and the carry-over that copies external analyzer
  results onto a rescan excludes the crypto analyzers. A rescan therefore leaves them behind, and
  the project's crypto tab, hotspots and compliance report empty out for it.

  This is not new, but a fleet-wide rescan wave turns a per-project loss into a single event, and
  releases add a second population that gets rescanned. Check the blast radius in the deploy window
  before choosing Option A or B — if this is zero, there is nothing to weigh:

  ```js
  db.crypto_assets.countDocuments({})
  ```

  If it is not zero, find which projects would lose assets — those whose current representative
  scan is about to be rescanned — and either withhold them from the wave with
  `rescan_enabled: false` or re-post their CBOMs after it lands.

---

## 3. Deploy

```
kubectl rollout status deployment/dependency-control-backend -n dependency-control
kubectl get pods -n dependency-control     # no old ReplicaSet pods left
```

No release exists yet: every scan has `is_release` absent, which the resolver, the retention cursors
and the rescan target query all read as "not a release". Existing data is nonetheless read
differently from the first request after the rollout, in four ways, none of which needs a release
to be marked.

* **Every project's representative scan is now derived from one stated rule, and the stored pointer
  is only a cache of it.** The rule lives in `app/repositories/scans.py`: *head is the freshest
  readable analysis of the tip commit of the project's head branch*. Two steps. The head branch is
  the default branch while the VCS still has one, else any branch it has not deleted; the tip commit
  is the newest **build** on it, so a rescan — which carries `created_at = now` over an older commit
  — never moves head onto another commit. Then that build's rescan lineage is followed to its newest
  usable analysis, so the rescanner's fresh enrichment is what head reports about the commit the
  builds chose. `Project.latest_scan_id` is that answer cached by ingest and is trusted only while
  it names a readable scan on the head branch — and it goes through the lineage step like any other
  candidate, so it cannot answer differently from the derived path.

  Before this release `get_latest_active_scan_ids` took `Project.latest_scan_id` on trust, skipped a
  project that had none, and sorted its fallback on `created_at` alone. All of that changes *which*
  scan a project speaks for, fleet wide and at once: analytics summary, top dependencies, hotspots,
  search, impact, risk, compliance reports, the project page's branch tiles, and every chat and MCP
  tool. The numbers move because they were wrong, but they move.

  Four populations move, and the first two queries cannot see the last two. Size all four before
  deploying:

  ```js
  // 1. pointers naming a scan that is gone or unreadable, on projects that took the trusted fast path
  db.projects.aggregate([
    { $match: { latest_scan_id: { $ne: null }, deleted_branches: { $in: [null, []] } } },
    { $lookup: { from: "scans", localField: "latest_scan_id", foreignField: "_id", as: "cur" } },
    { $set: { cur: { $first: "$cur" } } },
    { $match: { $or: [ { cur: null },
                       { "cur.status": { $nin: ["completed", "completed_with_errors"] } } ] } },
    { $count: "dangling_pointers" }
  ])

  // 2. projects with no pointer that do have a usable scan — these appear in rollups for the first time
  db.projects.aggregate([
    { $match: { latest_scan_id: null } },
    { $lookup: {
        from: "scans",
        let: { pid: "$_id" },
        pipeline: [
          { $match: { $expr: { $eq: ["$project_id", "$$pid"] },
                      status: { $in: ["completed", "completed_with_errors"] } } },
          { $limit: 1 },
          { $project: { _id: 1 } } ],
        as: "usable" } },
    { $match: { usable: { $ne: [] } } },
    { $count: "projects_gaining_a_scan" }
  ])
  ```

  **3. Pointers sitting on a branch that is not the default one.** Neither query above can see this
  population, and it is the larger of the two pointer defects: the pointer is perfectly readable, so
  the old fast path kept it, and the project has been reporting a feature branch's findings as its
  own. Production carries it — `rewe/cicd/security-executor` has `default_branch: "main"`, an empty
  `deleted_branches`, and `Project.stats` matching a `feature/DSM-959_…` scan at 5 critical /
  49 findings / risk 58.2, while the newest `main` build that morning reads 6 / 63 / risk 63.2.

  ```js
  db.projects.aggregate([
    { $match: { latest_scan_id: { $ne: null }, default_branch: { $ne: null } } },
    { $lookup: { from: "scans", localField: "latest_scan_id", foreignField: "_id", as: "cur" } },
    { $set: { cur: { $first: "$cur" } } },
    // cur.branch rather than cur: a $first over an empty array is missing, not null, so an $expr
    // guard on cur alone lets the dangling pointers of query 1 back in and double-counts them.
    { $match: { "cur.branch": { $exists: true },
                $expr: { $ne: ["$cur.branch", "$default_branch"] } } },
    { $count: "pointer_off_default_branch" }
  ])
  ```

  **4. Projects whose tip build has been rescanned since.** These are the ones the lineage step
  moves: head stops reporting the original analysis and starts reporting the rescan of the same
  commit, so newly published CVEs and newly listed KEV entries against unchanged dependencies reach
  the dashboard for the first time. Counted here only where the answer actually changes — where the
  stored pointer already names the rescan, nothing moves. `deleted_branches` is ignored, so on a
  project whose default branch the VCS has deleted this is an over-count by one:

  ```js
  db.projects.aggregate([
    { $lookup: {
        from: "scans",
        let: { pid: "$_id", def: "$default_branch" },
        pipeline: [
          { $match: { status: { $in: ["completed", "completed_with_errors"] },
                      $expr: { $and: [ { $eq: ["$project_id", "$$pid"] },
                                       { $ne: ["$is_rescan", true] },
                                       { $or: [ { $eq: ["$$def", null] },
                                                { $eq: ["$branch", "$$def"] } ] } ] } } },
          { $sort: { created_at: -1, _id: 1 } },
          { $limit: 1 },
          { $project: { latest_rescan_id: 1 } } ],
        as: "tip" } },
    { $set: { tip: { $first: "$tip" } } },
    { $match: { "tip.latest_rescan_id": { $ne: null } } },
    { $lookup: { from: "scans", localField: "tip.latest_rescan_id", foreignField: "_id", as: "rescan" } },
    { $set: { rescan: { $first: "$rescan" } } },
    { $match: { "rescan.status": { $in: ["completed", "completed_with_errors"] },
                $expr: { $ne: ["$rescan._id", "$latest_scan_id"] } } },
    { $count: "head_moves_to_a_rescan" }
  ])
  ```

* **Compliance reports, chat and crypto hotspots pick their scans through the same resolver.** They
  used to take each project's newest usable scan outright; they now obey the head rule above.
  **Report content changes for any project with a deleted branch**, where a scan on that branch
  could previously represent the project and now cannot. Size it:

  ```js
  db.projects.countDocuments({ deleted_branches: { $exists: true, $ne: [] } })
  ```

  Generate one report for such a project before and after the deploy and diff the finding counts.

* **The scan delta now excludes waived findings.** Counts on the delta screen fall wherever a
  waiver applies. That is the delta agreeing with stats, impact, hotspots and crypto trends. The
  same function backs the **MCP `compare_scans` tool**, so its counts fall by the same amount.
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
  4. **A project with no known default branch can settle on a tag build as its representative
     scan.** Two writers of `latest_scan_id` meet here. `sync_project_branches` repoints a pointer
     whose scan sits on a branch it has just filed as deleted — a tag name is no longer such a
     branch, so the 6-hourly sync leaves a tag build in the slot rather than moving the project
     onto its newest non-tag scan within a sync window. Head resolution then keeps that pointer,
     because with no default branch every branch the VCS has not deleted is a head branch and a tag
     name now counts as one.

     Where `default_branch` **is** known this stops at the resolver: the pointer names a scan whose
     branch is the tag rather than the default, so it is rejected and head is re-derived from the
     default branch's tip. That is population 3 above, and it is the reason the same rollout that
     creates this consequence also bounds it to projects the VCS integration never gave a default
     branch for.
  5. **`Project.stats` and `Project.last_scan_at` follow the pointer.** That same repoint writes
     all three fields together, so wherever it no longer fires these two keep the tag build's
     numbers and date. Project lists, tiles and dashboards read them straight off the project
     document without going through the resolver, so they follow a tag build even on a project
     where consequence 4 does not apply. They are corrected by the project's next ingest, not by a
     read.

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

You do not have to notice that number. An `--execute` pass that finishes with anything unresolved
exits **2**, so run `--execute` until it exits 0 — as a Job, that is a failed pod per pass, and each
failed pass still applied its own plan, so the next one starts from a shorter chain. The smoke test
exits 0 whatever it leaves behind: `--limit` makes a pass partial by request. Exit 1 is a connection
or runtime error and means nothing was completed.

Verify by re-running the second query once the unresolved count is zero: it must return no rows.

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

Write down the release count as it stands now — §7's first check needs it, and it cannot be
recovered afterwards:

```js
db.releases.countDocuments({ environment: "production" })   // the "before" number for section 7
```

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
`--limit` bounds the releases recorded, not the flag repairs: those come from a sweep over
`db.releases` and are applied in full on every run, smoke test included.

Re-running is safe, from any point a run can be killed at. A scan that already has a release row is
skipped rather than marked again; every scan left holding only its row has its flag set, counted on
the `release rows missing the flag` line, whether the row came from a tag build, from a branch build
marked with `DEP_CONTROL_IS_RELEASE=true`, or from a run killed between its two writes; and a run
killed before its prunes leaves tag names in `deleted_branches` that the next run plans and drops,
because the prune is planned from every released tag build the walk sees, not only from this run's.

A consequence of that: the run also drops the tag name of a tag build released through the API
before the backfill, which is the same name the branch census would drop on its next pass anyway.

---

## 7. Verify

```js
db.releases.countDocuments({ environment: "production" })
db.releases.distinct("scan_id").length                       // == the next line
db.scans.countDocuments({ is_release: true })
```

The first is **not** equal to `releases to record`: a deploy job can mark a release through the API
at any time, including four lines further down this runbook where that is explicitly allowed for. It
must equal `production rows counted before the --execute pass` **plus** `releases to record`. Take
the "before" number in the same window as the dry run and write it down; without it this line
asserts nothing.

The last two must be equal, and stay equal: a scan whose flag is set but whose row is missing sits
in the `scans_released_list` partial index answering the released-only filter with a release nobody
made, and a scan with a row but no flag is missing from that index and from the "Releases only"
filter. Retention and archiving read `db.releases` and neither direction changes what they keep.

A count is not a diagnosis, so name the offenders on both sides rather than inferring them from the
difference — the two directions can cancel out.

```js
const flagged = new Set(db.scans.distinct("_id", { is_release: true }));
const rows = new Set(db.releases.distinct("scan_id"));
db.releases.distinct("scan_id").filter(id => !flagged.has(id))          // rows with no flag
db.scans.distinct("_id", { is_release: true }).filter(id => !rows.has(id))  // flags with no row
```

Both lists must be `[]`. Each housekeeping pass reconciles both directions from `db.releases`, and
re-running the backfill repairs the row-with-no-flag direction immediately; a non-empty list here
before the first pass is expected rather than an incident. A flag with no row is a scan whose
release was withdrawn while the second write was lost, or a run killed between its two writes — if
one of them *should* be a release, write the row through
`POST /api/v1/projects/{project_id}/releases` rather than setting the flag, or the next reconcile
clears it again.

```js
db.releases.find({}, { project_id: 1, scan_id: 1, version: 1, released_at: 1 }).limit(5)
```

Every row the backfill wrote must name a `version` equal to the scan's `commit_tag` and a
`released_at` equal to that scan's `created_at`. A row marked through the API can legitimately have
no `version` at all — a deploy job that named neither a version nor a tag — but never a blank one:

```js
db.releases.countDocuments({ version: "" })   // must be 0
```

Then confirm no project still hides a marked tag name. A bare list of every project with a non-empty
`deleted_branches` is not that check — most of those entries are ordinary deleted branches and the
list is long enough to read as noise. Intersect against the tag names of the scans that were
actually released:

```js
const releasedTags = new Set(
  db.scans.find({ _id: { $in: db.releases.distinct("scan_id") } }, { commit_tag: 1 })
    .toArray().map(s => s.commit_tag).filter(t => t));
db.projects.find({ deleted_branches: { $exists: true, $ne: [] } }, { name: 1, deleted_branches: 1 })
  .toArray()
  .map(p => ({ name: p.name, hidden: p.deleted_branches.filter(b => releasedTags.has(b)) }))
  .filter(p => p.hidden.length > 0)      // must be []
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

### Re-stamp the waiver flags on the builds that are in production

A finding's `waived` flag is written onto the finding document when its scan is analysed, and until
this release only the **head** scan was ever re-stamped when a waiver changed. A build that is in
production therefore answers "what is in production" through the waiver set of the day it was
analysed: revoke a waiver and the released build still hides the finding, so release-mode analytics
can report **zero criticals against a build that has one**, with no waiver left in the system.

From this release a recalculation covers the head scan **and** the scans release mode resolves to,
so any later waiver change heals the project. Nothing heals the existing rows on its own — a
project whose waivers never change again keeps the stale flags — so run one pass over the projects
that have releases, as a Job, after the backfill:

```
python - <<'PY'
import asyncio
from app.db.mongodb import close_mongo_connection, connect_to_mongo, get_database
from app.services.stats import recalculate_project_stats

async def main():
    await connect_to_mongo()
    db = await get_database()
    project_ids = await db.releases.distinct("project_id")
    for project_id in project_ids:
        await recalculate_project_stats(project_id, db)
    print(f"re-stamped {len(project_ids)} project(s) with releases")
    await close_mongo_connection()

asyncio.run(main())
PY
```

It takes a per-project distributed lock and is safe to re-run. Spot-check one project afterwards:
switch the analytics scope to the release environment and confirm the severity counts match the
released build's findings rather than reading zero.

The release view also carries its own date now. `GET /api/v1/analytics/scope` returns
`oldest_analysis_at`, and the control above every analytics tab renders it, because a release
resolves to a build nobody rebuilt: vulnerabilities published since that analysis are absent from
the answer by construction, and re-stamping waivers cannot change that. Expect support questions
about the new line the first day; it is not an error state.

---

## 9. Teil B — the ad-hoc analyze endpoint

`POST /api/v1/analyze` runs the analysis pipeline in memory and stores nothing. Three facts decide
whether it works after the rollout.

### Nothing has to precede the deploy

`adhoc_api_keys` and its three indexes are created by startup's `create_indexes` on an empty
collection, so unlike §1 there is no index to pre-build and no migration to run. The collection does
not exist before the first key is minted.

### `analyze:adhoc` must be granted explicitly, or nobody can use it

This is the step that is easiest to miss and hardest to recover from. `analyze:adhoc` is a new
entry in `ALL_PERMISSIONS` — 43 entries before this release, 44 after — and:

* `has_permission` is plain list membership. There is **no wildcard escape**: measured,
  `has_permission(["*"], Permissions.ANALYZE_ADHOC)` returns `False`.
* `ALL_PERMISSIONS` is read only when `init_db` creates the *first* admin. Nothing backfills a new
  permission onto user documents that already exist.

So after the rollout **no existing user, including the platform admin, can mint an ad-hoc key** until
someone grants the permission. Do it deliberately, to the identities that should have it, and only
once the image carries the subprocess ceiling described below:

```js
db.users.updateMany(
  { username: { $in: ["<the identities that should hold it>"] } },
  { $addToSet: { permissions: "analyze:adhoc" } }
)
```

Verify by minting a key through `POST /api/v1/analyze-keys/` as one of them, then calling
`POST /api/v1/analyze` with it. The permission is re-checked on the owner at every request, so
removing it later revokes every key that identity holds: `POST /analyze` then answers 403, not 401.

### The rate limiter fails open

The 5/min and 60/hour windows live in Redis. On a `RedisError` the endpoint **logs a warning and
allows the request** — a Redis incident silently removes the limit rather than removing the
endpoint. That is the deliberate trade (an outage should not stop analyses), but it means a Redis
alert is also an ad-hoc rate-limit alert. Watch for `adhoc: Redis unavailable for rate limiting`
in the backend logs.

### Why the ordering with §0 step 10 matters

A CLI scanner started by an ad-hoc request used to outlive the request's 504: `cli_timeout` is
awaited inside the coroutine the deadline cancels, so cancelling the request cancelled the only
ceiling the scanner had, and each retry started another one. Measured before the fix: four requests,
four `sleep`-equivalent scanners still alive and parented to the API process 20 s after the last
504. The analyzer now kills and reaps its subprocess on cancellation. Granting `analyze:adhoc`
against an older image hands out that behaviour, which is why step 10 comes after the deploy.

---

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
