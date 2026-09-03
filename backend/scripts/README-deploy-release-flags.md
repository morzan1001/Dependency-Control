# Deploy runbook — release flag and the historical tag-build backfill

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

Run the backfill as a Kubernetes **Job**, never via `kubectl exec`: the autoscaler evicts backend
pods and a long exec dies with them. The Job manifest, its labels and its NetworkPolicy are in
`README-deploy-waves-2-3.md` section 2 — nothing about them changes here.

Order: indexes, then the rescan brake, then deploy, then dry run, then execute.

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

2. Deploy (section 3) and run the backfill (sections 4–5).

3. Seed `last_rescanned_at` in tranches. One tranche is the newest usable source of N projects;
   raise N once a tranche has drained. Repeat until the aggregation above counts zero:

   ```js
   const TRANCHE = 100;
   const tips = db.scans.aggregate([
     { $match: { status: { $in: ["completed", "completed_with_errors"] },
                 is_rescan: { $ne: true },
                 sbom_refs: { $exists: true, $ne: [] },
                 last_rescanned_at: null } },
     { $sort: { project_id: 1, created_at: -1 } },
     { $group: { _id: "$project_id", tip_id: { $first: "$_id" } } },
     { $limit: TRANCHE }
   ]).map(r => r.tip_id);
   db.scans.updateMany({ _id: { $in: tips } }, [{ $set: { last_rescanned_at: "$$NOW" } }]);
   ```

   A seeded source stays quiet for the full 730 h, i.e. about 30 days — long enough to spread the
   remaining tranches over as many days as you want.

4. The backfill adds a second rescan target per project: a marked release is re-evaluated in its
   own right, and the tag builds it marks are old and unstamped, so they are due immediately.
   Seed them the same way:

   ```js
   db.scans.updateMany({ is_release: true, last_rescanned_at: null },
                       [{ $set: { last_rescanned_at: "$$NOW" } }]);
   ```

5. Switch the scheduler back on:

   ```js
   db.system_settings.updateOne({}, { $set: { global_rescan_enabled: true } })
   ```

### Option B — take the burst deliberately

Skip the brake, and watch it land. Acceptable when the count from the aggregation is small enough
for the worker pool and the window is quiet.

### What to watch either way

* `worker_queue_size` — the queue depth gauge. It should rise once and drain, not step up again
  every 300 s. A second step means the clock is not being stamped and the wave is repeating.
* Backend logs for `Recovery limit (1000) reached` on a pod restart: the backlog outgrew what a
  restarting pod will re-queue, and the remainder waits for housekeeping's stuck-scan sweep.
* `db.scans.countDocuments({ status: "pending" })` before and an hour after the first cycle.

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
  would put every historical tag name straight back after the backfill pruned it. Projects will
  therefore show fewer deleted branches from the first sync onwards, whether or not the backfill
  has run.

---

## 4. Dry run the backfill

```
python -m scripts.backfill_release_flags
```

Read the report. `releases to record` is the number of historical tag builds; `projects to prune`
is how many projects carry one of those tag names in `deleted_branches`. The dry run computes the
plan and stops; `--execute` applies that same plan, so the report is the change list.

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

## 5. Execute

```
python -m scripts.backfill_release_flags --limit 20 --execute    # smoke test
python -m scripts.backfill_release_flags --execute
```

`--batch-size` and `--sleep-ms` throttle both the walk and the writes. Defaults are 500 and 50 ms.

Re-running is safe. A scan that already has a release row is skipped rather than marked again, and
one left holding only its row — a run killed between its two writes — has just its flag set. The
report counts those on the `of those, flags to repair` line.

---

## 6. Verify

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

Every row must name a `version` equal to the scan's `commit_tag` and a `released_at` equal to that
scan's `created_at`. Then confirm no project still hides a marked tag name:

```js
db.projects.find({ deleted_branches: { $exists: true, $ne: [] } }, { name: 1, deleted_branches: 1 })
```

Finally, open a project that gained a release and check the Releases list renders it, and that the
Pipelines table's release filter returns the same scan.

---

## 7. After the backfill

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
