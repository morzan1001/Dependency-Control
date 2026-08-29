# Deploy runbook — update-frequency delta ledger

One backfill and one verification, both **written but not executed**. Run them as Kubernetes
**Jobs** (see the volume and label notes in `README-deploy-waves-2-3.md` section 2, they apply
unchanged), never via `kubectl exec`: the autoscaler evicts backend pods and a long exec dies
with them.

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

Three independent flags gate this feature:

| Flag | Controls | Code default | Helm value | Ship as |
|---|---|---|---|---|
| `UPDATE_FREQUENCY_ROLLUP_ENABLED` | writing a delta at ingest | `true` | none | on — nothing to set |
| `UPDATE_FREQUENCY_USE_ROLLUP` | reading the analytics from the ledger | `false` | `backend.env.updateFrequencyUseRollup` | **off** until step 5 |
| `UPDATE_FREQUENCY_RECONCILE_ENABLED` | the nightly reconcile of ledger against scans | `false` | `backend.env.updateFrequencyReconcileEnabled` | **off** until step 6 |

The two flags with a Helm value are rendered as literal `env` entries of
`backend-deployment.yaml`, so steps 5 and 6 are a values change plus a rollout. The write flag
runs on its `app/core/config.py` default and can only be turned off in the chart.

## 1. Deploy with the read flag off — this step already changes numbers

Every finished scan starts producing a delta from this moment, so the backfill in step 3 only has
to cover history. The Job pods in steps 2-4 inherit the same default, so the backfill will not
refuse (it exits 2 when the write flag is off, before touching anything).

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
1,881 scans in the largest single project, 50,422 over the whole history. The dry run is what
tells you where between those two a 365-day window lands; the runtime is linear in that count
(see step 3).

### How far back to backfill — a choice, not a default

**Backfill as far back as the widest window you intend to ship.** `WindowSelect` offers 30, 90
and 365 days on the comparison tab, and 365 is not gated by anything: the endpoint accepts
`window_days` up to 3650.

What a narrower backfill than the shipped selector actually produces — it is honest output, not
corruption, which is why this is a choice and not a blocker:

- **Comparison tab at 365 days, ledger covering 90.** The fold sums the deltas it has, and
  compares what it accounted for against the commits the branch really holds in the 365-day
  window. A quarter of a year against a full year is far below the 80% `ready` threshold, so
  the row reads **`partial`**: its numbers are exact for the stretch they cover, they are shown,
  and the row is deliberately kept out of the ranking, the team averages and best/worst. Around
  674 of 708 projects land here. Only a project with no delta at all in the window — one that
  last scanned more than 90 but less than 365 days ago, at most 34 of them — reads `pending`.
  A branch with 1,000 or more deltas in the window is `ready` regardless, because neither path
  reads past that cap.
- **Project page at 365 days.** `_rollup_project_metrics` serves only a `ready` fold, so a
  `partial` one falls back to the live walk. The page is correct and complete — and costs a full
  365-day walk of that project's scans, plus the deps.dev round-trips, exactly as before the
  flip. Nothing degrades; the saving simply does not apply to that view.

What widening costs is less than the calendar suggests: the 365-day scan count is bounded by the
whole history, 50,422 scans, so going from a 90-day to an all-time backfill is **+20,263 scans,
~25 min, ~32 GB of extra cache churn** — 1.7x the 90-day run, not 4x. There is no meaningful cost
argument for stopping at 90. Take the number from the dry run and decide once; widening later
means running the backfill again over the older stretch.

The other way to close the gap is to drop the 365-day option from `WindowSelect`. That takes a
year-long view away from users to save 25 minutes of off-hours backfill, so it is the worse one.

## 3. Backfill — off-hours

```
python -m scripts.backfill_update_frequency --since-days 365 --execute
```

`--since-days 0` backfills the whole history instead and ends the question for good: ~60 min
against a 90-day window's ~35.

**What it costs.** The script budgets `0.04 s` of work per scan plus the `--sleep-ms` throttle,
spread over `--concurrency` workers, so at the defaults (2 workers, 100 ms) it is `0.07 s` per
scan and ~1.6 MB of dependency reads per scan: about **12 min and 17 GB of cache churn per
10,000 scans**. Against the measured scan counts:

| `--since-days` | scans | runtime | cache churn |
|---|---|---|---|
| 90 | 30,159 | ~35 min | ~48 GB |
| 365 | between the two rows — the dry run prints it | | |
| 0 (whole history) | 50,422 | ~60 min | ~79 GB |

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
backfill was told to spare. Run it again at `--window-days 365` for the widest selector option:
the scan set is at most the whole history, so budget ~34 min per pass, ~67 min in total.

| Exit | Meaning | Do |
|---|---|---|
| 0 | every field agreed, or only deviations with a named cause | continue to step 5 |
| 2 | at least one deviation without a named cause | **stop**, investigate |
| 3 | the sample was empty, so nothing was compared | **stop**, the gate did not run |
| 1 | connection or runtime error | fix and re-run |

Exit 2 is not advisory. A deviation is excused only where the two paths are designed to differ:
`dominant_ecosystem` always, `recent_updates` where a scan carried more than the writer's 20
samples or the live list hit its 30-event cap, and `slowest_packages` once the list is at its
15-entry cap. Nothing is excused per project: a scan that only one path folded is a hole in the
ledger and the tool names what the ledger holds for it.

**A declined project does not slip past the gate.** The per-project half compares nothing for a
project whose fold is not `ready`; it prints "the ledger declined this project" and moves on,
which on its own would leave the exit code silent. It does not, because the comparison half still
folds that project: a hole in the ledger makes it `partial`, `pending` or `error` there while the
live walk reports `ready`, and that `data_status` disagreement has no named cause — exit 2. The
declines that survive to exit 0 are the ones where the live walk had nothing to report either
(no comparable branch, or fewer than two scans with an SBOM). Read the `ledger declined:` line in
the totals regardless; it is where the reason per project is spelled out.

## 5. Flip the read flag

Set `backend.env.updateFrequencyUseRollup: true` in the production values file and upgrade. The
chart renders it as `UPDATE_FREQUENCY_USE_ROLLUP`. The comparison then answers from a handful
of bounded queries instead of walking every scan of every visible project. Budget for it: the
endpoint gives the rollup recompute 30 s against the live path's 240 s, and the lock waiter is
sized to that, so treat 30 s as the number to alert on, not a sub-second answer.

**Rollback** is setting it back to `false`. Nothing is deleted and the live path is untouched, so
the fallback stays available. The cache key carries the flag state, so flipping it does not serve
the other path's entries for the rest of their TTL.

## 6. Arm the nightly reconcile — only once step 4 came back clean

Set `backend.env.updateFrequencyReconcileEnabled: true` in the production values file and
upgrade. The chart renders it as `UPDATE_FREQUENCY_RECONCILE_ENABLED`.

**Not before the backfill.** The reconcile repairs at most 500 scans a night, throttled to the
backfill's own rate. Against an unbackfilled 90-day window every one of the ~30,159 in-window
scans reads as `missing`, so it would spend the full budget every night — ~1.6 MB of dependency
reads per scan, ~800 MB a night against the same `cpu=2 / 4Gi` mongod step 3 is told to spare —
and take about 60 nights to reach what one throttled off-hours run does in ~35 minutes. That is
why it has a flag of its own: turning it off must not mean turning the writer off with it.

The run is anchored to the clock, not to the deployment: `_reconcile_due` lets it start only
inside `HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC` (02:00 UTC, local night in
`europe-west1`) and only once per calendar day. A midday rollout therefore arms it without
starting it.

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
  between releases*, *Days since latest release* — go empty wherever the ledger answers, because
  the fold never calls deps.dev. That is the calendar-window views of a project whose fold reads
  `ready`. They survive on *Last 20 scans*, which has no calendar window and stays on the live
  walk, and on any project whose fold is not `ready` and therefore falls back to it — so the
  tiles come and go with the ledger's coverage, which is confusing and worth a release note.
- A `ready` row does not promise full coverage. `ready` means the ledger accounts for at least
  80% of the branch's commits in the window; below that the row turns `partial`. So a row can
  be ranked and averaged while up to a fifth of its window is unmeasured. A branch with 1000 or
  more documents in the window is `ready` by construction: both paths read only the newest 1000,
  and the branch's own commit count describes more than either of them analysed.
- A project whose window holds fewer than two scans *with an SBOM* now reports insufficient data
  instead of a zero update rate. It used to be ranked at 0.0 updates/month and could be named
  worst_project on a comparison that never happened.

## Post-deploy watch — the nightly reconcile

The loop runs in all 15 pods, so the reconcile takes the distributed lock
`update_frequency_reconcile` and only the holder does the work; it also no-ops entirely while
`UPDATE_FREQUENCY_ROLLUP_ENABLED` is off.

Watch `update_frequency_reconcile_drift_total{kind,outcome}`.

| `kind` | What the run found | Repair |
|---|---|---|
| `missing` | an in-window scan with no delta | derive it |
| `stale` | a delta at an older `schema_version` | derive it again |
| `severed` | a delta diffed against a scan that is gone along with its own delta — retention's signature | derive it again against the surviving predecessor |
| `orphan` | a delta whose scan is gone or no longer usable | delete the delta and its outdated set |
| `dependent` | a delta diffed against an orphan this run deleted | derive it again |

`outcome` is `resolved` (repaired in this run) or `deferred` (left for the next one). A steady
non-zero rate means a write path is inserting, changing or deleting scans without calling the
rollup writer — that class of bug was already missed once during design (`archive.py` reinserting
a scan on restore) and is invisible in the analytics themselves, which keep serving numbers
either way.

**The caps are per run: 500 derivations and 5,000 orphan deletions.** A non-zero `deferred` count
means the night ran out of budget. One such night is normal after an incident; several in a row is
a backfill dressed up as drift — stop the reconcile from grinding through it 500 at a time, turn
the flag off, run step 3 over the affected stretch and turn it back on. The reconcile is a
detector with a repair attached, not a migration tool.

**Two things it will not tell you.** It only looks at the last 90 days, so drift in a wider
backfilled stretch is the backfill script's job — re-run step 3 over it after any incident that
touched old scans. And a scan deleted from the newest end of a branch leaves no successor pointing
at it, so both censuses agree and the run reports nothing; what is lost there is the movement into
the deleted scan.
