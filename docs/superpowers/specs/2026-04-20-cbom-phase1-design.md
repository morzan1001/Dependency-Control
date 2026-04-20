# CBOM Phase 1 — Design Spec

**Status**: Approved (brainstorm 2026-04-20)
**Scope**: Phase 1 of a three-phase CBOM (Cryptography Bill of Materials) extension to DependencyControl
**Not in git**: This spec is a working artifact, do not commit.

## Goals

Extend the existing SBOM analysis platform to ingest, store, and analyze Cryptography Bills of Materials. Phase 1 delivers end-to-end value: pipeline ingestion → persistence → analysis → findings → UI, plus an editable policy engine with project-level overrides.

## Non-Goals (Phase 1)

- Compliance-framework report exports (FIPS/BSI PDFs) — Phase 3
- Certificate lifecycle, protocol-version, where-used hotspot analyzers — Phase 2
- Post-quantum migration plan generator — Phase 3
- Key-management hygiene analyzer (hardcoded keys, weak RNG) — Phase 3
- Policy audit history — deferred until explicitly requested
- Trend dashboards, cross-project crypto analytics — Phase 2

## Architecture Overview

### New Components

```
backend/app/
├── services/
│   ├── cbom_parser.py              # CycloneDX-1.6 crypto-asset parser
│   ├── analyzers/crypto/
│   │   ├── base.py                 # Shared CryptoRuleAnalyzer
│   │   └── (three registered instances, see §Analyzer Pipeline)
│   └── crypto_policy/
│       ├── seeder.py               # Loads NIST/BSI/CNSA seed on startup
│       ├── resolver.py             # Effective policy = system ∘ project override
│       └── seed/                   # YAML seed files
│           ├── nist_sp_800_131a.yaml
│           ├── bsi_tr_02102.yaml
│           ├── cnsa_2_0.yaml
│           └── nist_pqc.yaml
├── models/
│   ├── crypto_asset.py
│   └── crypto_policy.py
├── repositories/
│   ├── crypto_asset.py
│   └── crypto_policy.py
├── schemas/
│   ├── cbom.py                     # ParsedCBOM, ParsedCryptoAsset
│   └── crypto_policy.py
└── api/v1/endpoints/
    ├── cbom_ingest.py
    ├── crypto_assets.py
    └── crypto_policies.py
```

### Frontend

- New `Cryptography` tab in project view: Inventory sub-view + Findings sub-view + Summary header
- New admin page `Crypto Policy` (system-wide rule editor)
- New project-settings sub-tab `Crypto Policy Override` (per-project rule overrides)

### Pipeline

- New template file in `dependency-control-pipeline-templates/cbom-scan.yaml` that runs IBM CBOMkit and POSTs to the new ingest endpoint.

### Data Flow

```
CBOMkit (pipeline)          CycloneDX-1.6 SBOM (existing pipeline)
      │                                │
      ▼                                ▼
POST /api/v1/ingest/cbom    POST /api/v1/ingest
      │                                │
      │                      sbom_parser.py detects
      │                      cryptographic-asset components
      │                                │
      └──────┬─────────────────────────┘
             ▼
       cbom_parser.parse_crypto_components()
             │
             ▼
   CryptoAssetRepository.bulk_upsert()
             │
             ▼
   analysis_engine dispatches crypto analyzers
             │
             ▼
   CryptoRuleAnalyzer × 3 → Findings (new FindingTypes)
             │
             ▼
  Existing finding pipeline (waivers, scoring, webhooks, notifications)
```

## Design Principles (carried over from existing codebase)

- Same repository/model patterns as `Dependency` (`PyObjectId`, `populate_by_name`, `project_id + scan_id` foreign keys)
- Analyzers implement existing `analyzers/base.py` contract and register via `analysis/registry.py`
- Crypto analyzers run in the same `analysis/engine.py` as current analyzers
- No unbounded `.to_list(None)` — bulk writes in `_BULK_CHUNK_SIZE = 500` chunks, all queries carry a `limit`

## Data Model

### CryptoAsset (collection `crypto_assets`)

```python
class CryptoAssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"

class CryptoPrimitive(str, Enum):  # CycloneDX-1.6-aligned
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    HASH = "hash"
    MAC = "mac"
    PKE = "pke"
    SIGNATURE = "signature"
    KEM = "kem"
    KDF = "kdf"
    DRBG = "drbg"
    OTHER = "other"

class CryptoAsset(BaseModel):
    id: PyObjectId
    project_id: str
    scan_id: str

    bom_ref: str                 # stable ID within a CBOM
    name: str                    # "RSA", "SHA-256", "TLS", "cert:CN=foo"
    asset_type: CryptoAssetType

    # Algorithm-only
    primitive: Optional[CryptoPrimitive] = None
    variant: Optional[str] = None
    parameter_set_identifier: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    key_size_bits: Optional[int] = None
    curve: Optional[str] = None

    # Certificate-only
    subject_name: Optional[str] = None
    issuer_name: Optional[str] = None
    not_valid_before: Optional[datetime] = None
    not_valid_after: Optional[datetime] = None
    signature_algorithm_ref: Optional[str] = None
    certificate_format: Optional[str] = None

    # Protocol-only
    protocol_type: Optional[str] = None
    version: Optional[str] = None
    cipher_suites: List[str] = Field(default_factory=list)

    # Context
    occurrence_locations: List[str] = Field(default_factory=list)
    detection_context: Optional[str] = None
    confidence: Optional[float] = None
    related_dependency_purls: List[str] = Field(default_factory=list)

    properties: Dict[str, str] = Field(default_factory=dict)
    created_at: datetime
```

**Indexes**: `(project_id, scan_id)`, `(project_id, asset_type)`, `(project_id, name)`, `(project_id, primitive)`.

**Schema rationale**: Flat, optional-heavy schema over inherited subclasses — matches CycloneDX 1.6's own type-switch model and existing Pydantic-v2 usage in the repo.

### CryptoPolicy (collection `crypto_policies`)

Two roles per document: `system` (single seeded default) or `project` (one override per project).

```python
class CryptoPolicySource(str, Enum):
    NIST_SP_800_131A = "nist-sp-800-131a"
    BSI_TR_02102 = "bsi-tr-02102"
    CNSA_2_0 = "cnsa-2.0"
    NIST_PQC = "nist-pqc"
    CUSTOM = "custom"

class CryptoRule(BaseModel):
    rule_id: str
    name: str
    description: str
    finding_type: FindingType
    default_severity: Severity

    match_primitive: Optional[CryptoPrimitive] = None
    match_name_patterns: List[str] = []          # glob, case-insensitive
    match_min_key_size_bits: Optional[int] = None
    match_curves: List[str] = []
    match_protocol_versions: List[str] = []
    quantum_vulnerable: Optional[bool] = None

    enabled: bool = True
    source: CryptoPolicySource
    references: List[str] = []

class CryptoPolicy(BaseModel):
    id: PyObjectId
    scope: Literal["system", "project"]
    project_id: Optional[str] = None             # required if scope="project"
    rules: List[CryptoRule]
    version: int                                 # bumps on every edit
    updated_at: datetime
    updated_by: Optional[str] = None
```

**Indexes**: `(scope, project_id)` unique.

**Merge semantics**: System default is always present post-seed. Project override ID-matches replace, new IDs append, `enabled=false` disables. Implemented in `CryptoPolicyResolver.resolve(project_id) → EffectivePolicy`.

**Seed updates preserve overrides**: On `CURRENT_SEED_VERSION` bump, only the `scope=system` document is rewritten; project overrides are untouched.

### FindingType extensions

```python
class FindingType(str, Enum):
    # ... existing ...
    CRYPTO_WEAK_ALGORITHM = "crypto_weak_algorithm"
    CRYPTO_WEAK_KEY = "crypto_weak_key"
    CRYPTO_QUANTUM_VULNERABLE = "crypto_quantum_vulnerable"
```

- `Finding.component`: `"<name> [bom-ref:<bom_ref>]"`
- `Finding.details`: `{rule_id, matched_value, policy_source, ...}`
- Waivers work unchanged — match by `finding_type`, `finding_id`, or `component`.

## Ingest & Parser

### Endpoint `POST /api/v1/ingest/cbom`

- Auth: reuse existing `api/deps.py` OIDC + API-key guards
- Request body: `{project_name, scan_metadata, cbom}` where `cbom` is CycloneDX-1.6 JSON
- Response: `{scan_id, status: "accepted"}` (async, handled by `scan_manager`)
- Rate limits: same as `/api/v1/ingest`

### Embedded-CBOM detection in existing SBOM ingest

`services/sbom_parser.py` gains `_extract_crypto_assets(cdx_doc)` called after the component loop. Crypto components attach to `ParsedSBOM.crypto_assets` (new optional field). The analysis engine persists them via `CryptoAssetRepository`. Shared entrypoint: `cbom_parser.parse_crypto_components(components)` — zero duplication between the two paths.

### Parser contract (`cbom_parser.py`)

```python
def parse_cbom(raw_payload: dict) -> ParsedCBOM
def parse_crypto_components(components: List[dict]) -> List[ParsedCryptoAsset]
```

**Fail-soft behavior** (consistent with SBOM parser):
- Missing `cryptoProperties` → skip, warn, `skipped_components += 1`
- Unknown `primitive` / `assetType` → fallback `OTHER`
- Invalid `notValidAfter` ISO date → `None`, warn
- Missing `bom-ref` → synthesize `sha256(name+variant+index)[:16]` so dedup still works

**Bulk persistence**: `CryptoAssetRepository.bulk_upsert(project_id, scan_id, assets, chunk_size=500)`.

**Hard cap**: `MAX_CRYPTO_ASSETS_PER_SCAN = 50000`. On overflow, scan is marked `partial`, a `SYSTEM_WARNING` finding is emitted, extra assets are dropped.

### CBOMkit pipeline template

New file `dependency-control-pipeline-templates/cbom-scan.yaml` with GitLab CI and GitHub Actions variants. Exact CBOMkit CLI flags to be verified via context7 during plan phase before implementation.

## Analyzer Pipeline

### Single class, three registrations

```python
class CryptoRuleAnalyzer(Analyzer):
    name: str
    finding_types: set[FindingType]

    async def analyze(self, scan: Scan, db: Database) -> AnalyzerResult:
        assets = await CryptoAssetRepository(db).list_by_scan(
            scan.project_id, scan.id, limit=MAX_CRYPTO_ASSETS_PER_SCAN
        )
        effective = await CryptoPolicyResolver(db).resolve(scan.project_id)
        rules = [r for r in effective.rules
                 if r.enabled and r.finding_type in self.finding_types]

        findings = []
        for asset in assets:
            for rule in rules:
                if self._matches(asset, rule):
                    findings.append(self._build_finding(asset, rule, scan))
        return AnalyzerResult(findings=findings)
```

Registered three times in `analysis/registry.py` with `finding_types` = `{CRYPTO_WEAK_ALGORITHM}`, `{CRYPTO_WEAK_KEY}`, `{CRYPTO_QUANTUM_VULNERABLE}` respectively. Registration stays explicit; logic stays DRY.

### Matcher logic (AND of set criteria)

| Criterion | Match rule |
|---|---|
| `match_primitive` | `asset.primitive == rule.match_primitive` |
| `match_name_patterns` | glob, case-insensitive, against `asset.name` or `asset.variant` |
| `match_min_key_size_bits` | `asset.key_size_bits is not None and asset.key_size_bits < threshold` |
| `match_curves` | `asset.curve ∈ rule.match_curves` |
| `match_protocol_versions` | `(asset.protocol_type, asset.version) ∈ list` |
| `quantum_vulnerable=True` | `asset.primitive ∈ {PKE, SIGNATURE, KEM}` AND `asset.name` ∈ quantum-vulnerable list |

No DSL, no expression engine. Phase-3 compliance frameworks ship as rule bundles over these primitives. A `custom_matcher_code` escape-hatch is designed-in but not activated in Phase 1 (YAGNI).

### Policy resolver

Per-scan in-memory `@lru_cache` keyed on `(project_id, system.version, override.version)`. No Redis in Phase 1. Invalidation implicit via version bump on write.

### Seeder

Runs in `main.py` lifespan, idempotent: skip if stored version ≥ `CURRENT_SEED_VERSION`. Seed files live at `backend/app/services/crypto_policy/seed/*.yaml` and are versioned with the code.

### Error handling & metrics

- Each analyzer wrapped in its own try/except — one crash doesn't abort the pipeline
- New Prometheus metrics: `analysis_crypto_assets_total{asset_type}`, `analysis_crypto_findings_total{rule_id,severity}`, `analysis_crypto_policy_resolve_duration_seconds`
- Existing `rescan_token` race-condition protection applies

## API

### REST endpoints

```
POST   /api/v1/ingest/cbom

GET    /api/v1/projects/{project_id}/crypto-assets
           ?scan_id=&asset_type=&primitive=&skip=&limit=
GET    /api/v1/projects/{project_id}/crypto-assets/{asset_id}
GET    /api/v1/projects/{project_id}/scans/{scan_id}/crypto-assets/summary

GET    /api/v1/crypto-policies/system                    # admin
PUT    /api/v1/crypto-policies/system                    # admin
GET    /api/v1/crypto-policies/system/rules
GET    /api/v1/projects/{project_id}/crypto-policy
PUT    /api/v1/projects/{project_id}/crypto-policy       # owner/admin
GET    /api/v1/projects/{project_id}/crypto-policy/effective
```

Findings use the existing `/findings?type=crypto_weak_algorithm` path — no new finding endpoints.

Authorization reuses `api/deps.py` guards (`require_project_member`, `require_admin`).

### MCP tools

New read-only tools:
- `list_crypto_assets`
- `get_crypto_asset_details`
- `get_crypto_summary`
- `get_project_crypto_policy`
- `suggest_crypto_policy_override` (advisory only, does not write)

Existing tools (`get_findings_by_type`, `get_top_priority_findings`, …) automatically cover the new finding types via the enum extension — only their descriptions need updates.

No write tools for policies — reduces LLM blast-radius, consistent with the existing read-heavy MCP pattern.

### Webhooks

- `finding.created` fires automatically for new finding types
- New event `crypto_asset.ingested` fires once per scan with count summary (not per asset — volume protection)

## Frontend

### Project view: `Cryptography` tab

- **Summary header**: total assets, algorithms count, certificates count, protocols count, quantum-vulnerable count (highlighted when > 0)
- **Inventory sub-view** (default): paginated `CryptoAssetTable` with server-side filtering (asset type, primitive, name search); row click → `CryptoAssetDetailDrawer`
- **Findings sub-view**: existing findings component with `type IN (crypto_*)` preset + extra "Rule" column

### Admin: `Crypto Policy` page

- Rules as an editable table (not JSON editor)
- Editable fields: `enabled`, `default_severity`, `match_min_key_size_bits`, name patterns
- Filter by source (NIST/BSI/CNSA/Custom)
- `Add Custom Rule` modal for full rule creation
- `Revert to Seed Defaults` button (bumps version, rewrites from seed)
- Version and `updated_by` shown in footer

### Project settings: `Crypto Policy Override` sub-tab

- Shows effective (merged) policy as a table
- Per-rule toggle: `Use System Default` ↔ `Override`
- Project owner can edit, members read-only
- `Reset Override` removes the override document entirely

### Reused components

`CryptoAssetTable`, `CryptoAssetDetailDrawer`, `CryptoSummaryHeader`, `CryptoPolicyEditor` (shared between admin and project UIs). Everything else reuses existing Findings, Filter, Waiver-Dialog, and Pagination components. `CryptoPolicyEditor` is the one genuinely new complex component; target ≤ 400 lines, split if it grows.

### Explicit Phase-1 UI exclusions

No heatmaps, no trend charts, no graphical rule builder, no PQC migration plan generator.

## Testing

### Unit

- `test_cbom_parser.py` — all CycloneDX-1.6 crypto variants + fail-soft cases, with real CBOMkit samples and hand-built edge cases
- `test_crypto_policy_resolver.py` — merge semantics, cache invalidation, override preservation
- `test_crypto_rule_analyzer.py` — parameterized matcher tests (~20 cases)
- `test_crypto_policy_seeder.py` — idempotence, version gate, override preservation across reseeds

### Integration

- `test_ingest_cbom.py` — POST → DB → analyzer → findings E2E
- `test_embedded_cbom_in_sbom.py` — CycloneDX SBOM with crypto components via `/ingest` produces both `Dependency` and `CryptoAsset` records
- `test_project_policy_override.py` — override disables a rule → finding disappears on rescan
- `test_waiver_applies_to_crypto_finding.py` — existing waiver logic works with new types
- `test_cbom_limit_enforcement.py` — hard cap triggers `partial` + `SYSTEM_WARNING`

### Performance

- `backend/tests/perf/test_crypto_analyzer_scale.py` — 10k assets × 50 rules < 5s runtime, RAM peak < 300MB

### Fixtures

`backend/tests/fixtures/cbom/`:
- `cbomkit_openssl_sample.json`
- `cyclonedx_1_6_with_crypto_assets.json`
- `legacy_crypto_mixed.json` (MD5, RSA-1024, TLS 1.0)
- `modern_crypto.json` (AES-256-GCM, RSA-4096, TLS 1.3)

Coverage: new modules meet SonarQube threshold; every new service/analyzer file has at least one happy-path and one fail-soft test.

## Rollout

Five independently-deployable PRs, each backwards-compatible:

1. **Backend + persistence**: models, repositories, parser, `/ingest/cbom`, seeding (no analyzers yet)
2. **Analyzers + policy resolver**: three registrations, matcher logic
3. **Frontend inventory + findings tab**: read-only views
4. **Frontend policy editor**: system and project UIs
5. **Pipeline template + docs**: CBOMkit template, README, pipeline-docs updates

No feature flag required — new endpoints and collections are opt-in by non-use.

## Operations

- **MongoDB**: two new collections, indexes created in app-startup index manager
- **Seed migration**: `seed_crypto_policies()` runs once on first deploy, idempotent thereafter
- **Helm**: no new secrets/configmaps; two new optional env vars (`MAX_CRYPTO_ASSETS_PER_SCAN`, `CRYPTO_POLICY_SEED_VERSION`)
- **Grafana**: dashboard updates analogous to existing analysis metrics (out of scope for this spec, in scope for deployment PR)

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| CBOMkit output schema drifts between versions | Fail-soft parser, real-sample fixtures, persist CBOMkit version in `tool_version` |
| Policy overrides silently hide all findings | `/crypto-policy/effective` exposes diff; `updated_by` + `version` recorded; full audit history deferred |
| Legacy codebases produce 100k+ crypto assets | Hard cap 50000 + `partial` status + SYSTEM_WARNING finding |
| Rule matcher too rigid for customer needs | `custom_matcher_code` escape-hatch designed-in, activated in Phase 3 |
| Seed data (NIST/BSI) stale at implementation time | `source` + `references` URLs on every rule; `CURRENT_SEED_VERSION` enables re-seed on updates |
| NIST PQC recommendations change | Quantum-vulnerable list in dedicated YAML for small-surface updates |

## Estimated effort

4–6 weeks for a single experienced engineer, five PRs, low deployment risk.
