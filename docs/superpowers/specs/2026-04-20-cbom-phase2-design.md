# CBOM Phase 2 — Design Spec

**Status:** Approved (brainstorm 2026-04-20)
**Scope:** Phase 2 of a three-phase CBOM extension, building on Phase 1
**Not in git:** Working artifact, do not commit.

## Goals

Extend the Phase 1 CBOM foundation with deeper analysis capabilities and analytics visualization:

1. Certificate lifecycle analyzer with configurable expiry thresholds
2. Protocol/cipher-suite analyzer backed by a versioned IANA snapshot
3. Where-used / hotspot analytics across project / team / global scopes
4. Trend dashboards in the DependencyControl frontend, Metabase optional for deep analytics

Phase 2 delivers visible user value across developer, team-lead, and admin journeys while preparing the data model for Phase 3 compliance reporting.

## Non-Goals (Phase 2)

- Compliance framework exports (FIPS/BSI PDFs) — Phase 3
- Policy audit history — Phase 3
- PQC migration plan generator — Phase 3
- Key-management hygiene analyzer (hardcoded keys, weak RNG) — Phase 3
- Automatic IANA catalog updates — only manual PR-driven bumps
- Real network-graph visualisations — Cross-Project view is a list, not a graph
- Metabase dashboard definitions in repo — dashboards are ops-managed; we expose a deep-link only
- Trend alerts ("alert when quantum-vulnerable rises above N") — Phase 3
- Export formats (CSV/PDF) for hotspots/trends — Phase 3

## Architecture Overview

### New backend components

```
backend/app/
├── services/
│   ├── analyzers/crypto/
│   │   ├── certificate_lifecycle.py     # CertificateLifecycleAnalyzer (7 checks)
│   │   ├── protocol_cipher.py           # ProtocolCipherSuiteAnalyzer
│   │   └── catalogs/
│   │       ├── __init__.py
│   │       ├── iana_tls_cipher_suites.yaml  # IANA snapshot
│   │       └── loader.py                # in-memory lookup from YAML
│   ├── crypto_policy/
│   │   └── seed/
│   │       ├── cert_lifecycle_defaults.yaml
│   │       └── protocol_cipher_defaults.yaml
│   └── analytics/
│       ├── __init__.py
│       ├── crypto_hotspots.py           # aggregation for α/β/γ scopes
│       ├── crypto_trends.py             # time-series aggregation
│       └── scopes.py                    # scope+permission resolution
└── api/v1/endpoints/
    └── crypto_analytics.py              # /analytics/crypto/{hotspots,trends,scan-delta}
```

### Extended components

- `app/models/finding.py` — 8 new `FindingType` values
- `app/schemas/crypto_policy.py` — `CryptoRule` gains expiry threshold fields and `match_cipher_weaknesses`
- `app/services/analysis/registry.py` — two new registrations (`crypto_certificate_lifecycle`, `crypto_protocol_cipher`)
- `app/services/crypto_policy/seeder.py` — loads new YAML seeds + IANA catalog
- `app/api/v1/endpoints/` — new `crypto_analytics.py` router

### New frontend components

```
frontend/src/
├── pages/
│   ├── project/CryptoHotspotsPage.tsx          # α scope
│   ├── project/CryptoTrendsPage.tsx            # α scope
│   ├── team/CryptoTeamAnalyticsPage.tsx        # β scope
│   └── admin/CryptoGlobalAnalyticsPage.tsx     # γ scope
├── components/crypto/analytics/
│   ├── HotspotTable.tsx
│   ├── HotspotHeatmap.tsx
│   ├── HotspotTreemap.tsx
│   ├── HotspotBarChart.tsx
│   ├── CrossProjectNetworkView.tsx             # simple list, not a graph
│   ├── TrendsTimeSeriesChart.tsx
│   ├── ScanDeltaView.tsx
│   └── AnalyticsViewSwitcher.tsx               # segmented control, URL state
├── api/cryptoAnalytics.ts
└── types/cryptoAnalytics.ts
```

### Data flow — Certificate Lifecycle Analyzer

```
Scan completes → analysis engine dispatches crypto analyzers
    → CertificateLifecycleAnalyzer lists CryptoAssets where asset_type=CERTIFICATE
    → For each cert: 7 checks (expired, expiring, not-yet-valid, weak-signature,
      weak-key, self-signed, validity-too-long)
    → Checks c+d follow signature_algorithm_ref to related algorithm assets
    → Emits findings with detailed context
```

### Data flow — Cipher Suite Analyzer

```
Scan completes → ProtocolCipherSuiteAnalyzer lists CryptoAssets where asset_type=PROTOCOL
    → For each cipher_suites entry, look up IANA catalog
    → Emit findings per suite, tagged with weakness categories
    → CryptoRules with match_cipher_weaknesses can amplify/filter
```

### Data flow — Hotspot Aggregation

```
GET /api/v1/analytics/crypto/hotspots?scope=α&project_id=X&group_by=name
    → scopes.py resolves project list + permissions
    → crypto_hotspots.py runs MongoDB aggregation over crypto_assets (filtered to latest scans)
    → Joined with findings for severity_mix + finding_count (client-side merge)
    → Cached in-memory (LRU+TTL) keyed on (scope, scope_id, group_by, scan_ids, user_perms)
    → Returns HotspotResponse
```

## Design principles (carried over from Phase 1)

- Fail-soft: a single broken asset does not abort the analyzer
- Bulk writes chunked; queries always carry a limit
- Reuse existing Finding pipeline (waivers, webhooks, scoring) via new FindingType enum values
- Analyzers register in the same dict-based registry
- Engine dispatches via `is_crypto_analyzer()` unchanged
- Policy overrides (per-project) work transparently for new rules

## Data Model

### FindingType extensions (8 new values)

```python
class FindingType(str, Enum):
    # ... existing ...

    # Certificate lifecycle
    CRYPTO_CERT_EXPIRED            = "crypto_cert_expired"
    CRYPTO_CERT_EXPIRING_SOON      = "crypto_cert_expiring_soon"
    CRYPTO_CERT_NOT_YET_VALID      = "crypto_cert_not_yet_valid"
    CRYPTO_CERT_WEAK_SIGNATURE     = "crypto_cert_weak_signature"
    CRYPTO_CERT_WEAK_KEY           = "crypto_cert_weak_key"
    CRYPTO_CERT_SELF_SIGNED        = "crypto_cert_self_signed"
    CRYPTO_CERT_VALIDITY_TOO_LONG  = "crypto_cert_validity_too_long"

    # Protocol / cipher suite
    CRYPTO_WEAK_PROTOCOL           = "crypto_weak_protocol"
```

Finding.component: `"<cert_subject or protocol_type> [bom-ref:<bom_ref>]"`.
Finding.details: type-specific. Expiry includes `days_until_expiry`, `threshold_matched`; cipher-suite includes parsed components + `weakness_tags`.

### CryptoRule extensions

```python
class CryptoRule(BaseModel):
    # ... existing ...

    # Certificate expiry thresholds (in days); None = not used by this rule
    expiry_critical_days: Optional[int] = Field(None, ...)
    expiry_high_days:     Optional[int] = Field(None, ...)
    expiry_medium_days:   Optional[int] = Field(None, ...)
    expiry_low_days:      Optional[int] = Field(None, ...)
    validity_too_long_days: Optional[int] = Field(None, ...)

    # Cipher-suite weakness matching
    match_cipher_weaknesses: List[str] = Field(default_factory=list, ...)
```

Severity selection for expiring certificates (lowest-matching threshold wins):
```
days = (cert.not_valid_after - now).days
if expiry_critical_days is not None and days <= expiry_critical_days: CRITICAL
elif expiry_high_days is not None     and days <= expiry_high_days:   HIGH
elif expiry_medium_days is not None   and days <= expiry_medium_days: MEDIUM
elif expiry_low_days is not None      and days <= expiry_low_days:    LOW
else: no finding
```
Negative days → CRYPTO_CERT_EXPIRED (CRITICAL, separate type, no threshold needed).

### IANA Cipher-Suite Catalog

**File:** `backend/app/services/analyzers/crypto/catalogs/iana_tls_cipher_suites.yaml`

```yaml
version: 1
source: "IANA TLS Cipher Suite Registry"
source_url: "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4"
snapshot_date: "2026-04-20"
suites:
  - name: TLS_RSA_WITH_RC4_128_SHA
    value: "0x00,0x04"
    key_exchange: RSA
    authentication: RSA
    cipher: RC4-128
    mac: SHA-1
    weaknesses: [weak-cipher-rc4, weak-mac-sha1, no-forward-secrecy]
  # ...
```

Weakness tag vocabulary:
```
weak-cipher-rc4, weak-cipher-des, weak-cipher-3des, weak-cipher-null, weak-cipher-export
weak-mac-md5, weak-mac-sha1
weak-kex-rsa, weak-kex-dh-weak, weak-kex-anon
no-forward-secrecy, export-grade, anonymous, null-cipher, null-auth
```

Loader: `catalogs/loader.py` — loads YAML on app startup, cached as `Dict[str, CipherSuiteEntry]`.
`CURRENT_IANA_CATALOG_VERSION = 1`; version persisted in scans for reporting transparency.

### Analytics schemas (`backend/app/schemas/analytics.py`)

```python
class HotspotEntry(BaseModel):
    key: str
    grouping_dimension: str              # name|primitive|asset_type|weakness_tag|severity
    asset_count: int
    finding_count: int
    severity_mix: Dict[str, int]
    locations: List[str]                 # file paths (α) or project_ids (β/γ)
    project_ids: List[str]
    first_seen: datetime
    last_seen: datetime

class HotspotResponse(BaseModel):
    scope: Literal["project", "team", "global"]
    scope_id: Optional[str]
    grouping_dimension: str
    items: List[HotspotEntry]
    total: int
    generated_at: datetime
    cache_hit: bool

class TrendPoint(BaseModel):
    timestamp: datetime
    metric: str
    value: float

class TrendSeries(BaseModel):
    scope: str
    scope_id: Optional[str]
    metric: str
    bucket: Literal["day", "week", "month"]
    points: List[TrendPoint]
    range_start: datetime
    range_end: datetime

class ScanDelta(BaseModel):
    from_scan_id: str
    to_scan_id: str
    added: List[HotspotEntry]
    removed: List[HotspotEntry]
    unchanged_count: int
```

No new MongoDB collections. Live aggregation over `crypto_assets` + `findings` + `scans`.

### Denormalization: `findings.scan_created_at`

For trend range queries without `$lookup`, every finding write copies `scan_created_at` into the finding doc. Migration helper in PR B backfills for existing findings (idempotent, resumable, progress marker in system-settings).

### Permission model

New permission `analytics:global` (default: admins only, in `PRESET_ADMIN`).
- α project scope → `check_project_access(..., "viewer")`
- β team scope → new helper `check_team_access` (mirrors project pattern)
- γ global scope → `RequirePermission("analytics:global")` or `system:manage`

## Analyzer details

### CertificateLifecycleAnalyzer

- Single class with 7 check methods (`_check_expired`, `_check_expiring`, `_check_not_yet_valid`, `_check_weak_signature`, `_check_weak_key`, `_check_self_signed`, `_check_validity_too_long`)
- One try/except per check so a failure in one check does not block the others
- `signature_algorithm_ref` resolution: prefetch all ALGORITHM assets for the scan into a `bom_ref → CryptoAsset` index once per `analyze()` call
- Seed defaults in `cert_lifecycle_defaults.yaml` provide sensible expiry thresholds (7/30/90/180 days) and a disabled-by-default CA/Browser-Forum 398-day rule
- Finding shape follows Phase 1 conventions; `details` carries `days_until_expiry`, `threshold_matched`, `related_algo_bom_ref`

### ProtocolCipherSuiteAnalyzer

- Initialises the IANA catalog once via `load_iana_catalog()` from `catalogs/loader.py`
- For each PROTOCOL asset, iterates `asset.cipher_suites`; unknown entries are skipped (vendor-specific or new IANA entries)
- Severity derived from the set of weakness tags via `_WEAKNESS_SEVERITY_MAP` (module-level constant):
  - `export-grade` / `null-*` / `anonymous` → CRITICAL
  - `weak-cipher-rc4` / `weak-cipher-des` → HIGH
  - `weak-mac-md5` / `weak-cipher-3des` → HIGH
  - `weak-mac-sha1` → MEDIUM
  - `no-forward-secrecy` → LOW
- Rules with `match_cipher_weaknesses` emit an amplification finding tagged with `rule_id` in details — allows project-scoped "flag anything without PFS"
- Per-suite finding contains: `cipher_suite`, `cipher_suite_value`, `key_exchange`, `authentication`, `cipher`, `mac`, `weakness_tags`, `catalog_version`

### Registry

```python
analyzers: Dict[str, Analyzer] = {
    # existing ...
    "crypto_certificate_lifecycle": CertificateLifecycleAnalyzer(),
    "crypto_protocol_cipher": ProtocolCipherSuiteAnalyzer(),
}

CRYPTO_ANALYZERS: Set[str] = {
    "crypto_weak_algorithm", "crypto_weak_key", "crypto_quantum_vulnerable",
    "crypto_certificate_lifecycle", "crypto_protocol_cipher",
}
```

Engine dispatch code from Phase 1 remains unchanged.

## Analytics aggregation

### Hotspot service

```python
class CryptoHotspotService:
    async def hotspots(
        self, *, scope, scope_id, group_by, scan_id=None, limit=100,
    ) -> HotspotResponse: ...
```

- Scope resolution determines `project_ids` list
- Aggregation pipeline filters to the latest completed scan per project
- `$group` on the selected grouping dimension
- Second parallel aggregation against `findings` for severity mix; merged client-side
- Result: sorted by asset_count desc, limited

Grouping dimensions:
- `name` — `{name, variant}` tuple
- `primitive` — `$primitive`
- `asset_type` — `$asset_type`
- `weakness_tag` — requires `$unwind` over `findings.details.weakness_tags`
- `severity` — `$findings.severity`

### Trend service

```python
class CryptoTrendService:
    async def trend(
        self, *, scope, scope_id, metric, bucket, range_start, range_end,
    ) -> TrendSeries: ...
```

Metrics:
- `total_crypto_findings`
- `quantum_vulnerable_findings`
- `weak_algo_findings`
- `weak_key_findings`
- `cert_expiring_soon`
- `cert_expired`
- `unique_algorithms`
- `unique_cipher_suites`

Pipeline uses `$dateTrunc` on `scan_created_at`. Bucket auto-selection:
- range ≤ 14d → day
- range ≤ 90d → week
- range ≤ 365d → month
- range > 365d → month with hard cap at 2 years total

### Scan delta

- Endpoint: `GET /analytics/crypto/scan-delta?project_id=X&from=<scan_id>&to=<scan_id>`
- Key = `(name, variant, primitive)` (bom_ref can drift between scans)
- Response: `added`, `removed` (as `HotspotEntry[]`), `unchanged_count`
- Also stored on scan completion: `scan.crypto_delta = {added: N, removed: M}` for ScansPage "new since last" badge

### Caching

- `functools.lru_cache` + TTL wrapper; key = `(scope, scope_id, group_by, scan_ids_fingerprint, user_perms_hash)`
- TTL: 300 s
- maxsize: 512
- `cache_hit: true` surfaced in response
- No Redis in Phase 2

## API endpoints

```
GET /api/v1/analytics/crypto/hotspots
    ?scope={project,team,global}&scope_id=&group_by=&scan_id=&limit=

GET /api/v1/analytics/crypto/hotspots/{key}/locations
    ?scope=&scope_id=&grouping=

GET /api/v1/analytics/crypto/trends
    ?scope=&scope_id=&metric=&bucket=&range_start=&range_end=

GET /api/v1/analytics/crypto/scan-delta
    ?project_id=&from=&to=
```

Validation:
- Pydantic Query with enum coercion
- `range_end - range_start` max 2 years
- `limit` max 500

Prometheus metrics:
- `analytics_query_duration_seconds{scope, group_by, metric}`
- `analytics_cache_hits_total{scope}`
- `analytics_query_errors_total{scope, reason}`

## MCP tools

Read-only additions:
- `get_crypto_hotspots(project_id, group_by)` → top-20
- `get_crypto_trends(project_id, metric, days)` → TrendSeries
- `get_scan_delta(project_id, from_scan_id, to_scan_id)` → ScanDelta summary

No writes from MCP.

## Frontend

### Pages

- `pages/project/CryptoHotspotsPage.tsx` — sub-tab under Cryptography in `ProjectDetails.tsx`
- `pages/project/CryptoTrendsPage.tsx` — sibling sub-tab
- `pages/team/CryptoTeamAnalyticsPage.tsx` — under team-detail route
- `pages/admin/CryptoGlobalAnalyticsPage.tsx` — new route `/settings/crypto-analytics`, gated on `analytics:global`

### View switcher

Shared `AnalyticsViewSwitcher.tsx` — segmented control with state in URL query param (`analytics_view=table|heatmap|treemap|bar|network`). Exactly one view visible at a time. `network` view only shown for β/γ.

### Per-view components

- `HotspotTable` — sort, filter, per-row collapsible locations, click → drill-down drawer
- `HotspotHeatmap` — tailwind grid with bg-opacity driven by count (recharts has no native heatmap)
- `HotspotTreemap` — recharts `<Treemap>`
- `HotspotBarChart` — recharts `<BarChart>` top-20
- `CrossProjectNetworkView` — list, not graph; each row: algo + "used in N projects" + expandable project list
- `TrendsTimeSeriesChart` — recharts `<LineChart>`; metric selector, range preset buttons (7d/30d/90d/365d/custom), optional stacked-area "by severity"
- `ScanDeltaView` — drawer from ScansPage, three collapsibles (added / removed / unchanged count)

### Navigation

- Project Cryptography tab gains sub-navigation: Inventory / Findings / Hotspots / Trends
- Team-Detail page gains `Crypto analytics` sub-tab (β)
- Admin sidebar adds `Crypto analytics` (γ), permission-gated

### Metabase integration

Minimal:
- Admin global-analytics page shows a footer link "Open crypto dashboard in Metabase"
- Deep-link URL via env var `METABASE_CRYPTO_DASHBOARD_URL`
- Button hidden when env var empty
- No iframe, no Metabase API calls from the frontend

## URL query param conventions

All Phase 2 analytics params prefixed `analytics_`:
- `analytics_view` — selected view in switcher
- `analytics_group_by` — grouping dimension
- `analytics_metric` — trend metric
- `analytics_bucket` — trend bucket
- `analytics_range` — preset or custom

## Testing

### Unit

- `test_certificate_lifecycle_analyzer.py` — parametrised tests for all 7 checks, including threshold ladders, missing dates, unresolved signature refs
- `test_iana_catalog_loader.py` — YAML loads, tag vocabulary enforced, unknown suite returns None
- `test_protocol_cipher_analyzer.py` — each weakness category → correct severity; unknown suite skipped; match_cipher_weaknesses amplification
- `test_crypto_rule_expiry_extensions.py` — new fields validated (negative → error)
- `test_crypto_hotspot_service.py` — mock-DB aggregate results across all 5 groupings, limit + sort, severity_mix merging
- `test_crypto_trend_service.py` — bucket auto-selection, range validation, empty result
- `test_scan_delta.py` — key tuple (name, variant, primitive), added/removed/unchanged
- `test_scope_resolver.py` — α/β/γ permission gating positive + negative
- `test_finding_types_phase2.py` — 8 new enum values

### Integration

- `test_cert_lifecycle_pipeline.py` — CBOM → analyzer → findings
- `test_protocol_cipher_pipeline.py` — same for protocol analyzer
- `test_hotspots_endpoint.py` — all 3 scopes × 5 groupings, auth header variants, 403 paths
- `test_trends_endpoint.py` — valid ranges, bucket coercion, permission gates
- `test_scan_delta_endpoint.py` — payload shape
- `test_analytics_caching.py` — `cache_hit: true` on repeat

### Performance

- `test_hotspots_scale.py` — 50 projects × 1k crypto_assets, `scope=global` hotspots query < 2 s, RAM < 500 MB

### Frontend

- `HotspotTable.test.tsx` — renders, drill-down, sort
- `AnalyticsViewSwitcher.test.tsx` — URL state sync, deep-link
- `TrendsTimeSeriesChart.test.tsx` — rendering, metric switch
- Smoke tests for Heatmap/Treemap

### Catalog drift sentinel

Test that asserts `len(load_iana_catalog()) > 300` to catch accidental catalog wipes.

## Rollout

Four sequential PRs:

- **PR A — Backend analyzers** (~1.5 weeks)
  - FindingType + CryptoRule schema extensions
  - CertificateLifecycleAnalyzer + tests
  - ProtocolCipherSuiteAnalyzer + IANA catalog + loader + tests
  - Registry + seeder updates (bump `CURRENT_SEED_VERSION` to 2)
  - No frontend changes; new findings surface in existing Findings UI
- **PR B — Analytics backend** (~2 weeks)
  - `analytics/` module (scopes, hotspots, trends, scan-delta)
  - API endpoints
  - LRU+TTL cache
  - Permission `analytics:global` seeded into PRESET_ADMIN
  - `scan_created_at` denormalization + idempotent migration helper
- **PR C — Frontend project-level** (~2 weeks)
  - API client + types
  - View switcher
  - HotspotTable/Heatmap/Treemap/BarChart/NetworkView
  - TrendsTimeSeriesChart + range picker
  - ScanDeltaView + ScansPage integration
  - Project Cryptography sub-navigation
- **PR D — Team/admin + Metabase + MCP** (~1.5 weeks)
  - Team analytics route + page
  - Admin global analytics route + page
  - Metabase deep-link (env-var gated)
  - Three new MCP tools

No feature flag. Backward compatible throughout.

## Operations

- MongoDB: no new collections. New indexes:
  - `findings.scan_created_at`
  - `crypto_assets.(project_id, asset_type, primitive)`
- Seeder version bumped (`CURRENT_SEED_VERSION = 2`)
- IANA catalog versioned (`CURRENT_IANA_CATALOG_VERSION = 1`)
- Helm: new optional env var `METABASE_CRYPTO_DASHBOARD_URL`
- Grafana dashboard: extend analogously to Phase 1 metrics

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| IANA catalog drift | Versioned YAML in repo with `snapshot_date`/`source_url`; unknown suites skipped silently; update docs in `docs/catalog-updates.md` |
| Cert analyzer OOM on 1k+ certs | Bulk read with limit=50k, per-cert try/except, perf test guards < 2 s for 1k |
| Global hotspot queries I/O-heavy | LRU+TTL cache, admin-only gate, top-500 hard cap, Prometheus alerts on duration > 5 s |
| Denormalisation migration holds lock on large deployments | Migration helper is idempotent + resumable + batched (1000 docs/batch), progress in system-settings |
| Severity ladder surprises users | Effective-policy endpoint reveals thresholds; findings carry `threshold_matched` in details |
| URL param collisions | `analytics_` prefix on all Phase 2 params |
| `analytics:global` accidental assignment | Admin UI warns on permission grant; only `PRESET_ADMIN` gets it by default |
| Metabase deep link points at wrong env | Env var per environment; link hidden when unset |

## Estimated effort

4 PRs, sequential, **6–7 weeks** for an experienced fullstack engineer.
