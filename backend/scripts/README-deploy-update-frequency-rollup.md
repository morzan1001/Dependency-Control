# Deploy runbook — update-frequency delta ledger

One backfill and one verification, both **written but not executed**. Run them as Kubernetes
**Jobs** (see the volume and label notes in `README-deploy-waves-2-3.md` section 2, they apply
unchanged), never via `kubectl exec`: the autoscaler evicts backend pods and a long exec dies
with them.

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

Two independent flags gate this feature:

| Flag | Controls | Ship as |
|---|---|---|
| `UPDATE_FREQUENCY_ROLLUP_ENABLED` | writing a delta at ingest | on |
| `UPDATE_FREQUENCY_USE_ROLLUP` | reading the comparison from the ledger | **off** until step 5 |

## 1. Deploy with the read flag off — this step already changes numbers

Every finished scan starts producing a delta from this moment, so the backfill in step 3 only has
to cover history.

**This is not a silent step.** Both read paths now pick the analysed branch by the same rule, and
that rule changed: the configured default branch wins when it has at least two commits in the
window, otherwise the branch with the most commits in the window wins, ties going to the most
recent. The old fallback took the branch of the newest scan, which a single scan on a feature
branch could hijack. 491 of 708 projects carry no configured default branch and therefore all
fall on the changed fallback, so `branch`, `scan_count`, `updates_per_month`, `patch_ratio`,
`total_updates` and `last_scan_date` can all move here — before the flag is ever flipped.

Rows whose numbers are unavailable are also listed now instead of being counted away, so the
table gets longer.

```
kubectl rollout status deployment/dependency-control-backend -n dependency-control
```

## 2. Dry run

```
python -m scripts.backfill_update_frequency --since-days 365 --dry-run
```

Prints chain count, scan count and a runtime estimate. Measured baseline for the numbers to
sanity-check against: 30,159 usable non-rescan scans across 674 projects in a **90-day** window,
1,881 scans in the largest single project. The dry run is what tells you how much more a
365-day window adds; the runtime is linear in that count (see step 3).

**Why 365 and not 90.** The window selector on the comparison tab already offers *Last 12
months*, and that read has no live fallback: with only 90 days in the ledger, every project
picked at 365 days answers `partial` or `pending` after the flip, which drops it out of the
ranking and the team averages. Backfilling 90 days would only be enough if that option were
removed from `WindowSelect` first.

## 3. Backfill — off-hours

```
python -m scripts.backfill_update_frequency --since-days 365 --execute
```

**What it costs.** The script budgets `0.04 s` of work per scan plus the `--sleep-ms` throttle,
spread over `--concurrency` workers, so at the defaults (2 workers, 100 ms) it is `0.07 s` per
scan: about **12 min per 10,000 scans**, or ~35 min for a 90-day window's 30,159 scans. A
365-day window costs that per-scan figure times whatever the dry run counted, and holds the
cache churn below open for just as much longer.

**Why off-hours.** The run reads two dependency sets per scan out of a 34 GB collection behind a
~1.5 GB WiredTiger cache on a `cpu=2 / 4Gi` mongod. Even throttled it churns the cache at roughly
22 MB/s, which evicts the working set the live traffic depends on.

Watch `wiredTiger.cache.bytes read into cache` and the backend's p99 latency. **Abort if
eviction climbs steeply or the API slows** — the run is resumable, so stopping costs nothing:

```
db.serverStatus().wiredTiger.cache["bytes read into cache"]
```

Resuming skips scans that already carry a current delta, so a second run picks up exactly where
the first stopped. Chains are processed oldest-first and parallelised across chains but never
inside one; that ordering is what lets each scan find its predecessor.

## 4. Parity — the actual gate

```
python -m scripts.verify_update_frequency_parity --sample 1000 --window-days 90
```

`--sample 1000` covers every project with two usable scans in the window.

**This is more expensive than the backfill — run it off-hours too.** The projects are verified
one after another, each costing a full live walk of its window, and then `verify_comparison`
computes the whole live comparison again over the same projects. That is **two complete passes
over the same 30,159 scans**, neither of them throttled — at the backfill's own `0.04 s` per
scan, roughly 20 min per pass, so ~40 min of unthrottled reads against the same mongod that the
backfill was told to spare. Re-running at `--window-days 365` to prove the widest selector
option costs the same again over the larger scan set.

| Exit | Meaning | Do |
|---|---|---|
| 0 | every field agreed, or only deviations with a named cause | continue to step 5 |
| 2 | at least one deviation without a named cause | **stop**, investigate |
| 3 | the sample was empty, so nothing was compared | **stop**, the gate did not run |
| 1 | connection or runtime error | fix and re-run |

Exit 2 is not advisory, and a deviation is excused only where the two paths are designed to
differ (`recent_updates`, `dominant_ecosystem`, `slowest_packages` at their caps). Nothing is
excused per project: a scan that only one path folded is a hole in the ledger and the tool names
what the ledger holds for it.

## 5. Flip the read flag

Set `UPDATE_FREQUENCY_USE_ROLLUP=true` and roll out. The comparison then answers from a handful
of bounded queries instead of walking every scan of every visible project. Budget for it: the
endpoint gives the rollup recompute 30 s against the live path's 240 s, and the lock waiter is
sized to that, so treat 30 s as the number to alert on, not a sub-second answer.

**Rollback** is setting it back to `false`. Nothing is deleted and the live path is untouched, so
the fallback stays available. The cache key carries the flag state, so flipping it does not serve
the other path's entries for the rest of their TTL.

## What users will see change

These are corrections, not regressions, and they are visible enough to belong in the release
notes:

- Projects that used to be dropped silently reappear. 210 of 217 projects with a configured
  default branch were being lost to a validation error.
- Update coverage falls, in places from 100% to a two-digit figure. A scan whose outdated
  analysis was missing used to count the previous scan's whole backlog as resolved.
- `Updates / Month` falls for projects with dense CI. The rate divides by the requested window
  now, not by the span between the first and last scan, which used to turn two scans ten minutes
  apart into a thirtyfold rate.
- Rows say which branch they describe, and rows whose window is only partly covered are listed
  but ranked nowhere.
- The comparison loads on an explicit action rather than on opening the tab.
- The three upstream release-cadence tiles on the project page — *Releases / 12 mo*, *Days
  between releases*, *Days since latest release* — go empty after the flip wherever they had
  data. The page requests a calendar window and no explicit branch, which is exactly the shape
  the ledger serves, and the fold never calls deps.dev. Only the *Last 20 scans* option still
  routes the page through the live walk, so that is where the tiles survive.
- A `ready` row does not promise full coverage. `ready` means the ledger accounts for at least
  80% of the branch's commits in the window; below that the row turns `partial`. So a row can
  be ranked and averaged while up to a fifth of its window is unmeasured. A branch with more
  than 1000 documents in the window is `ready` by construction: both paths read only the newest
  1000, and the branch's own commit count describes more than either of them analysed.
- A project whose window holds fewer than two scans *with an SBOM* now reports insufficient data
  instead of a zero update rate. It used to be ranked at 0.0 updates/month and could be named
  worst_project on a comparison that never happened.

## Not covered here

The nightly reconcile (delta count against scan count) does not exist yet. Until it does, a write
path nobody hooked would drift silently — one such path was already missed once during design
(`archive.py` reinserting a scan on restore).
