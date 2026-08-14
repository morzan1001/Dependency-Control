# Deploy runbook — audit waves 2 & 3

Three migrations, all **written but not executed**. Run them in the order below, each as a
Kubernetes **Job** (section 2), never via `kubectl exec`. Every script defaults to dry-run and
only writes with `--execute`.

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

## 1. Deploy the new image — wait until all old pods are gone

```
kubectl rollout status deployment/dependency-control-backend -n dependency-control
kubectl get pods -n dependency-control     # no old ReplicaSet pods left
```

Migration 3.1 re-keys `dependency_enrichments`. Old code writes qualifier-keyed docs on every
enrichment pass, so a surviving old pod re-creates exactly what the migration collapses.

## 2. Run migrations as Jobs, not `kubectl exec`

The wave-1 lesson: the autoscaler evicts the backend pod mid-run, and a long `kubectl exec`
dies with it. Use a Job built from the backend image.

Three things the manifest must get right:

- **Volumes: keep only `tmp-volume`, `internal-ca`, `mongodb-client-tls`.** The `grype-db`
  GCS-FUSE volume fails outside the Deployment with `failed to find the sidecar container` —
  the gcsfuse webhook only injects it for annotated workloads.
- **Pod labels `app.kubernetes.io/instance=dependency-control` and
  `app.kubernetes.io/name=dependency-control`, and deliberately NOT
  `app.kubernetes.io/component=backend`.** The first two satisfy the NetworkPolicy selector;
  omitting the third keeps the Job pod out of the backend Service's endpoints, so it never
  receives traffic.
- **A NetworkPolicy for the Job**, because the chart's egress rules are scoped to
  `component=backend`. It needs unrestricted port 53 (DNS) plus TCP 27017 to the percona
  podSelector.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: dependency-control-migration
  namespace: dependency-control
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: dependency-control
      app.kubernetes.io/name: dependency-control
      job: migration
  policyTypes: [Egress]
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: percona-server-mongodb
      ports:
        - protocol: TCP
          port: 27017
---
apiVersion: batch/v1
kind: Job
metadata:
  name: dc-migration
  namespace: dependency-control
spec:
  backoffLimit: 0
  template:
    metadata:
      labels:
        app.kubernetes.io/instance: dependency-control
        app.kubernetes.io/name: dependency-control
        job: migration
    spec:
      restartPolicy: Never
      serviceAccountName: dependency-control
      containers:
        - name: migration
          image: <same image:tag as the backend Deployment>
          workingDir: /app
          command: ["python", "-m", "scripts.<script name>"]   # add --execute for the real run
          envFrom: <copy verbatim from the backend Deployment>
          volumeMounts:
            - { name: tmp-volume, mountPath: /tmp }
            - { name: internal-ca, mountPath: /etc/ssl/internal-ca, readOnly: true }
            - { name: mongodb-client-tls, mountPath: /etc/mongodb-tls, readOnly: true }
      volumes:
        - name: tmp-volume
          emptyDir: {}
        - name: internal-ca
          secret:
            secretName: dependency-control-root-ca-secret
            items: [{ key: ca.crt, path: ca.crt }]
        - name: mongodb-client-tls
          secret:
            secretName: dependency-control-mongodb-client-tls
```

Copy `envFrom`, `securityContext` and the exact secret names from the live Deployment
(`kubectl get deploy dependency-control-backend -n dependency-control -o yaml`) rather than
trusting the placeholders above. Run each migration dry-run first, read the counters, then
re-apply the Job with `--execute`.

## 3. The migrations, in order

### 3.1 `merge_enrichment_purl_qualifiers.py` — required

Enrichment now joins on the canonical purl (everything from the first `?` or `#` stripped).
**6,041 of 13,203 `dependency_enrichments` docs are qualifier-keyed and unreachable** by the new
readers until they are merged; **1,156** of them collapse as pure duplicates. Without this the
system still self-heals per artifact on that artifact's next scan, but the orphaned
qualifier-keyed docs stay behind forever.

```
python -m scripts.merge_enrichment_purl_qualifiers            # dry-run
python -m scripts.merge_enrichment_purl_qualifiers --execute
```

- **Re-runnable.** The survivor is re-keyed *before* its siblings are deleted, so a crash leaves
  removable duplicates, never lost data.
- **Concurrency window.** The script is not transactional against live enrichment writes. If the
  run aborts with a `DuplicateKeyError`, that is a live writer having created the canonical doc
  underneath it — **just re-run the script**; the second pass picks the now-canonical doc as the
  survivor and finishes the group.

### 3.2 `relabel_partial_scans.py` — recommended

Relabels the **~1,831** historical scans that carry a `SCAN-ERROR-*` finding from `completed` to
`completed_with_errors`, and backfills `failed_analyzers` from the finding ids. Includes the **26
`SCAN-ERROR-system`** scans: all 26 have dependencies, i.e. they are partial GridFS loads, which
current code classifies as `completed_with_errors` — labelling them `failed` would be wrong.

It skips only scans with **zero dependencies AND zero non-system findings** (the true
all-SBOMs-failed shape, which belongs in `failed`). Production has none; any hit is printed for
manual handling rather than guessed at.

It also corrects `latest_run.status`, because the Pipelines table renders `latest_run` in
preference to the scan's own fields.

```
python -m scripts.relabel_partial_scans            # dry-run: expect ~1,831 relabelled, 0 skipped
python -m scripts.relabel_partial_scans --execute
```

Re-runnable: relabelled scans no longer match the `completed` filter.

### 3.3 `dedupe_duplicated_scan_findings.py` — recommended

Removes the **~10k surplus finding documents** left by scans that persisted their whole set twice
before finding ids became deterministic (W30). Roughly 20 scans, all retried.

Only touches a scan whose stored count is an exact integer multiple `k` (>= 2) of its own
`findings_count`, **and** where every identity group `(type, component, version, finding_id)`
divides by `k`; it then keeps `size / k` documents per group. It does **not** collapse each group
to one document: a finding set may legitimately hold several documents of one identity (the
engine separates them by an occurrence suffix), so collapsing would delete real data. Scans that
do not divide evenly are printed and left alone.

```
python -m scripts.dedupe_duplicated_scan_findings            # dry-run
python -m scripts.dedupe_duplicated_scan_findings --execute
```

`--min-retry-count` defaults to 1, since only a retried scan can double-persist; that keeps the
per-scan count query off all 45k scans. Pass `--min-retry-count 0` for an exhaustive sweep.

## 4. Post-deploy watch items

### OSV request volume — watch for a day

`external_api_rate_limit_hits_total{service="OSV API"}`

OSV hydration adds one `/v1/vulns/{id}` request per **newly seen** vulnerability id. The census
measured **1,039–3,980 distinct ids** across all latest scans, so expect a few thousand extra
requests during the warm-up window, then ~0 once the 7-day `osvrec:{id}:{modified}` cache holds.
The first scan of each project also re-queries `querybatch` once per component, because the
`osv:` component-cache prefix is retired by design (bumped to `osv2:`).

### Unhydrated OSV ids — watch the ratio

`partial_vulnerabilities_unhydrated`, surfaced as a `SCAN-ERROR` finding and a `Partial (...)`
summary on the scan.

**228 of 3,980** ids did not resolve during the census (timeouts / 404s). They are visible rather
than silent, but a rising ratio means OSV availability, not a code defect. Note also that **361
records genuinely carry no rating at all** — that is the UNKNOWN floor, so "UNKNOWN should be
zero" is a wrong expectation.
