# Deploy runbook — audit wave 1 (PR #103)

Run the steps in this order. Steps 2 and 3 are in-pod one-offs: `python -m scripts.<name>` from `/app`. Both default to dry-run and only write with `--execute`.

## 1. Deploy the new image — wait until ALL old pods are gone

The license cleanup (step 3) MUST NOT start while any old pod is still serving: live old code re-writes `license: "non-standard"` into `dependency_enrichments` on every enrichment pass, undoing the cleanup.

```
kubectl rollout status deployment/<backend> && kubectl get pods   # no old ReplicaSet pods left
```

## 2. Backfill stored risk scores

```
python -m scripts.backfill_risk_scores            # dry-run: review "scans needing new scores"
python -m scripts.backfill_risk_scores --execute
```

- **Must run to completion.** The project-stats mirror only covers scans updated in the *same* run: if the run is interrupted, a re-run classifies already-updated scans as `unchanged` and never re-mirrors them, so those projects' `project.stats` stay stale until the project's next natural rescan.
- Expect ~15-30 min for ~44k scans. `--limit N` is available for a smoke test, but the real run must be limitless and uninterrupted.

## 3. Clean placeholder licenses out of `dependency_enrichments`

Removes the ~1666 docs' `license: "non-standard"` plus `unknown`/`NOASSERTION` remnants ($unset on `license`, $pull on `licenses_detailed`). New code stopped writing these, but `$set` semantics never remove the stale keys.

```
python -m scripts.cleanup_placeholder_licenses            # dry-run: expect ~1666 on the license pass
python -m scripts.cleanup_placeholder_licenses --execute
```

## 4. Optional: re-analyze the ~130 empty-inventory projects

~130 of 638 projects currently have zero dependency docs at their latest scan. 126 heal on their own at the next scheduled rescan (global interval ~730h ≈ 30 days, rolling per project); ~4 have no completed scan with `sbom_refs` and cannot heal automatically. A one-off re-analysis of the affected latest scans closes the gap immediately instead of over a month.

## Heads-up for users: one-time delta noise

The first post-deploy scan of most projects will show a wave of spurious "removed + added" pairs in scan deltas: vulnerability ids are now canonicalized (CVE preferred over GHSA etc.), so pre-deploy findings keyed under an alias id look "removed" while the same finding reappears "added" under the canonical id. One-time effect per project; subsequent deltas are clean.
