# Deploy runbook — scan stats accumulator

This release computes a scan's `stats` block in the backend, folding the scan's findings one at a
time out of a projected, index-hinted cursor. Nothing about the numbers is meant to change; this
runbook exists to prove that before the rollout and to confirm it after.

There is no feature flag. The only rollback is an image rollback, and an image rollback does not
repair data — see section 5.

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

Run the script invocations below as a Kubernetes **Job**, never via `kubectl exec`: the autoscaler
evicts backend pods and a long exec dies with them. The manifest, its volume list, its labels and
the NetworkPolicy it needs are in `README-deploy-waves-2-3.md` section 2 and apply here unchanged —
only `command` differs.

## 1. Verify the `(scan_id, type)` index — before the rollout, not during it

The stats read passes an explicit hint for `scan_id + type`. A hint MongoDB cannot satisfy is an
**error, not a downgrade**: the read fails with `hint provided does not correspond to an existing
index` instead of falling back to a collection scan, so on a database without that index every
stats read fails — the analysis engine, the waiver recalculation and the script below alike.

`create_indexes` in `app/core/init_db.py` creates it unconditionally, so any cluster that has
booted this application already has it. Confirm rather than assume, in `mongosh`:

```
db.findings.getIndexes().filter(i => i.name === "scan_id_1_type_1")
```

An empty result means stop. Create it and wait for the build to finish before deploying — a large
index build does not belong in a rollout's startup path:

```
db.findings.createIndex({ scan_id: 1, type: 1 }, { name: "scan_id_1_type_1" })
```

Check the same on the restored replica used in section 2, not only on production. A restore that
never ran the application has never run `create_indexes`.

## 2. Dry run against a prod-restored replica — this is the differential

Every `stats` block in the restore was written by the **currently deployed** release. The dry run
recomputes each one with the **new** release's engine and reports where the two disagree, so a
single run from the new image is the old-versus-new comparison. There is no separate run to do on
the old image: the divergence counters only exist in the new one.

So the Job for this step takes the **new** image and a `MONGODB_URL` pointing at the **restore**.
Getting either the wrong way round makes the step meaningless rather than noisy, so check both
before applying it.

```
python -m scripts.backfill_risk_scores --limit 500      # timed smoke test first, see section 4
python -m scripts.backfill_risk_scores                  # whole estate; writes nothing
```

The run is a dry run by default and only writes with `--execute`. `--execute` writes
`stats.risk_score` and `stats.adjusted_risk_score` and nothing else; the divergence report never
writes, in either mode.

Keep the full output. The last block is:

```
[DRY-RUN] scans processed:           <n>
[DRY-RUN] scans needing new scores:  <n>
...
[DRY-RUN] scans skipped (no findings for non-zero stats): <n>
...
[DRY-RUN] scans whose full Stats differ: <n>
[DRY-RUN]   <field>: <scans>
```

## 3. Reading the divergence report

`scans whose full Stats differ` counts scans, once each, whose stored block disagrees with the
recomputation in **any** top-level `Stats` field. The lines under it name the fields and count the
scans per field, so one scan with three drifted fields adds one to the total and one to each of
three field lines.

The stored block is normalised through the `Stats` model before the comparison, so a scalar an
older writer never emitted defaults to `0` rather than reading as drift.

**A non-zero total after the accounted-for classes below have been subtracted is translation
drift. Stop and investigate — do not re-run it.** The comparison is deterministic over the same
data; a second run produces the same answer. A field that disagrees disagrees because the backend
now counts it differently from the numbers already in the database, and shipping that silently
changes every dashboard, ranking and alert threshold built on it.

Three classes are accounted for and must be netted out before reading the total:

| Line in the breakdown | Accounted for when | Why |
|---|---|---|
| `risk_score`, `adjusted_risk_score` | the count tracks `scans needing new scores` | these two are exactly what this script exists to repair; a stored score written before the current scale differs without any engine disagreement. A count *above* `scans needing new scores` means those stored scores carry more than one decimal, which no current writer produces |
| any field, on a scan counted by `scans skipped (no findings for non-zero stats)` | | the scan's findings are gone, so the recomputation reads nothing and every counter reads zero against a non-zero stored block — that is retention, not arithmetic |
| `threat_intel`, `reachability`, `prioritized`, `secret_priority` | the count matches the number of stored blocks that omit the key | these four default to absent, so a block written before the sub-block existed reads as differing on it wholesale |

Everything else — `critical`, `high`, `medium`, `low`, `negligible`, `info`, `unknown`, or one of
the four sub-blocks on scans that *do* carry it — is drift with no accounted-for cause. To see the
scans behind a field, re-run with a small `--limit` against the same restore and diff a named
scan's stored block against a recomputation by hand.

`<unparseable>` is its own line: the stored block did not validate against the `Stats` model at
all. That is a corrupt document, not a counter disagreement; find it before reading anything else.

## 4. Measure the read volume — do not assume it

The engine's per-scan read shape changed, and the size of the change depends on the data, so
measure it here instead of predicting it.

**Memory does not grow with a scan's finding count.** The fold holds counters, never a list of
findings, so a scan with a hundred thousand findings costs the same resident memory as one with
ten. What grew is what crosses the wire: the findings cursor now covers *every* finding of the
scan rather than only its unwaived vulnerabilities, and carries the twelve projected paths the
fold needs rather than one. **Latency and network scale with the scan's finding count**, and the
tail is set by the largest single scan, because one stats read streams one whole scan.

The numbers to look at:

1. **Seconds per scan.** Time the `--limit 500` run and divide by the `scans processed` it prints.
   That is the per-scan cost of a stats read on this data, and it multiplies by the estate size
   the script prints on its first line (`N scan(s) with a stats block`).
2. **The largest scans**, because they set the worst-case latency of a single stats read in the
   live path:

   ```
   db.findings.aggregate([{ $sortByCount: "$scan_id" }, { $limit: 5 }])
   ```

3. **Documents and bytes returned**, sampled either side of the timed run:

   ```
   db.serverStatus().metrics.document.returned
   db.serverStatus().network.bytesOut
   ```

   Divide each delta by `scans processed` for the per-stats-read figure.

If the per-scan figure is uncomfortable against your largest scans, that is a finding to raise
before the rollout, not after — the same read runs on every scan completion and every waiver
recalculation.

## 5. Deploy, then run the same dry run against production

```
kubectl rollout status deployment/dependency-control-backend -n dependency-control
kubectl get pods -n dependency-control     # no old ReplicaSet pods left
```

**Re-run the dry run immediately afterwards, against production this time.** This is
reconciliation, not a repeat of section 2, and it is mandatory:

```
python -m scripts.backfill_risk_scores
```

During a rolling deploy both versions serve at once and both write the same `scan.stats` and
`project.stats` fields, so a scan that completes mid-rollout carries whichever version's pod
finished it. Rolling the image back leaves those blocks exactly as they were written — the image
is the code, not the data. This run is what says whether any of them disagree.

Throttle this one: unlike section 2 it reads the live cluster. `--sleep-ms` (default 50) is the
gap between batches of `--batch-size` (default 500) scans; raise it if p99 latency moves.

**Compare the field names against section 2, not the totals.** The restore is a point-in-time
copy and production has moved on, so the totals will not match. A field name that appears here
and did not appear in section 2 is the signal: investigate it before deciding how to repair the
affected scans.
