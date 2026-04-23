# CBOM Phase 3 — Design Spec

**Status:** Approved (brainstorm 2026-04-20)
**Scope:** Phase 3 of a three-phase CBOM extension. Builds on Phases 1 + 2.
**Not in git:** Working artifact, do not commit.

## Goals

Deliver audit-readiness and migration-planning capabilities on top of the Phase 1/2 foundation:

1. **Compliance-Report Engine** — render framework-based reports (NIST SP 800-131A, BSI TR-02102, CNSA 2.0, FIPS 140-3 algorithm-level, ISO/IEC 19790 algorithm-level) in four formats (PDF, CSV, JSON, SARIF).
2. **PQC Migration Plan Generator** — rule-based, cross-scope priority-ranked list of quantum-vulnerable assets mapped to NIST PQC successors.
3. **Key-Management Hygiene Rules** — nine OpenGrep rule-files shipped via pipeline-templates repo, auto-integrated into existing SAST scans, emitting a new `CRYPTO_KEY_MANAGEMENT` finding type.
4. **Policy Audit History** — per-save snapshot of every `CryptoPolicy` change with diff computation, revert flow, webhooks, in-app notifications, and soft retention.

## Non-Goals (Phase 3)

- Real CMVP database integration for FIPS 140-3 (algorithm-level only; module-certification deferred to Phase 4)
- Live policy-conflict detection across overrides
- Scheduled / periodic report generation (user-triggered only)
- External share-links for reports (all downloads stay auth-gated)
- LLM-generated prose in migration plan (rule-based only)
- Backend-hosted crypto-misuse rule endpoint (GitHub-raw URLs only; endpoint architecturally ready for future work)
- Policy-audit grouping or roll-up views
- Cross-framework combined scoring

## Architecture Overview

### New backend components

```
backend/app/
├── services/
│   ├── compliance/
│   │   ├── engine.py                        # ComplianceReportEngine
│   │   ├── frameworks/                      # 6 framework modules
│   │   │   ├── nist_sp_800_131a.py
│   │   │   ├── bsi_tr_02102.py
│   │   │   ├── cnsa_2_0.py
│   │   │   ├── fips_140_3.py                # algorithm-level
│   │   │   ├── iso_19790.py                 # fips_140_3 wrapper
│   │   │   └── pqc_migration_plan.py        # meta-framework
│   │   ├── renderers/
│   │   │   ├── pdf_renderer.py              # WeasyPrint
│   │   │   ├── csv_renderer.py
│   │   │   ├── json_renderer.py
│   │   │   └── sarif_renderer.py
│   │   └── templates/                       # Jinja2 for PDF
│   ├── pqc_migration/
│   │   ├── generator.py
│   │   ├── mappings_loader.py
│   │   ├── scoring.py
│   │   └── mappings.yaml
│   └── audit/
│       ├── history.py                       # record_policy_change + compute_change_summary
│       └── retention.py
├── models/
│   ├── compliance_report.py
│   ├── policy_audit_entry.py
│   └── finding.py                           # MODIFY: +CRYPTO_KEY_MANAGEMENT
├── repositories/
│   ├── compliance_report.py
│   └── policy_audit_entry.py
├── schemas/
│   ├── compliance.py
│   ├── pqc_migration.py
│   └── policy_audit.py
├── api/v1/endpoints/
│   ├── compliance_reports.py
│   ├── pqc_migration.py                     # within /analytics/crypto
│   └── policy_audit.py                      # under /crypto-policies/*/audit
└── services/normalizers/
    └── sast.py                              # MODIFY: tag crypto-misuse-* rule IDs
```

### Modified components

- `models/finding.py` — new `CRYPTO_KEY_MANAGEMENT` enum value
- `services/normalizers/sast.py` — prefix-based rule-ID → finding_type mapping
- `api/v1/endpoints/crypto_policies.py` — write paths call `record_policy_change`
- `services/crypto_policy/seeder.py` — seed-write calls `record_policy_change` with action=SEED
- `core/constants.py` — three new webhook events, permission constants unchanged

### New frontend components

```
frontend/src/
├── components/pqc/
│   ├── PQCMigrationPanel.tsx
│   ├── MigrationPlanTable.tsx
│   └── MigrationItemDetailDrawer.tsx
├── components/compliance/
│   ├── ComplianceReportsPanel.tsx
│   ├── NewReportDialog.tsx
│   ├── ReportStatusBadge.tsx
│   └── ReportDetailDrawer.tsx
├── components/audit/
│   ├── PolicyAuditTimeline.tsx
│   ├── PolicyDiffView.tsx
│   └── RevertConfirmDialog.tsx
├── api/
│   ├── compliance.ts
│   ├── pqcMigration.ts
│   └── policyAudit.ts
└── types/
    ├── compliance.ts
    ├── pqcMigration.ts
    └── policyAudit.ts
```

### Pipeline-templates repo additions

```
dependency-control-pipeline-templates/
├── rules/crypto-misuse/
│   ├── hardcoded-keys.opengrep.yaml
│   ├── weak-rng.opengrep.yaml
│   ├── ecb-mode.opengrep.yaml
│   ├── iv-reuse.opengrep.yaml
│   ├── short-iv-gcm.opengrep.yaml
│   ├── pbkdf2-low-iterations.opengrep.yaml
│   ├── insecure-tls.opengrep.yaml
│   ├── hardcoded-salt.opengrep.yaml
│   └── weak-hash-usage.opengrep.yaml
├── sast-opengrep.gitlab-ci.yml              # MODIFY: include crypto-misuse config
├── sast-opengrep.github-actions.yml         # MODIFY
├── crypto-misuse-scan.gitlab-ci.yml         # NEW standalone
└── crypto-misuse-scan.github-actions.yml    # NEW standalone
```

### Data flow sketches

Compliance report:
```
POST /api/v1/compliance/reports
    → ComplianceReport persisted with status=pending
    → BackgroundTask: ComplianceReportEngine.generate()
        → ScopeResolver → project_ids
        → _gather_inputs (assets, findings, policy)
        → framework.evaluate(data) → FrameworkEvaluation
        → renderer.render(evaluation) → bytes
        → GridFS.upload → artifact_gridfs_id
        → status=completed, webhook fired
    → Client polls GET /reports/{id} → when completed → /download
```

PQC migration plan:
```
GET /api/v1/analytics/crypto/pqc-migration?scope=user
    → ScopeResolver → project_ids
    → PQCMigrationPlanGenerator:
        list quantum-vulnerable assets (primitive ∈ {PKE,SIG,KEM}, name ∈ known QV set)
        per asset: lookup mapping, compute priority, determine timeline
    → MigrationPlanResponse (cached 5min)
```

Policy audit write:
```
PUT /crypto-policies/{scope}/… or /revert
    → record_policy_change(old, new, action, actor, comment)
        → compute_change_summary(old, new)
        → insert PolicyAuditEntry
        → fire webhook crypto_policy.changed
        → notify relevant users
    → original upsert completes
```

Key-management hygiene:
```
CI OpenGrep scan with crypto-misuse config
    → findings posted to /ingest SAST channel
    → sast normalizer: rule_id starts with crypto-misuse- → finding_type = CRYPTO_KEY_MANAGEMENT
    → findings appear alongside Phase-1/2 crypto findings
```

### Design principles (carried over)

- Fail-soft: audit-write failures, webhook-dispatch failures, individual renderer failures never block the primary action
- Bulk reads with explicit limits
- Reuse Phase-1/2 ScopeResolver, Finding pipeline, webhook infra, notification service
- Every new MongoDB collection gets indexes in the startup index manager
- TDD throughout

## Data Model

### FindingType extension

```python
class FindingType(str, Enum):
    # ... Phase 1 + 2 ...
    CRYPTO_KEY_MANAGEMENT = "crypto_key_management"
```

Total: 12 `crypto_*` finding types.

### `ComplianceReport` (collection `compliance_reports`)

```python
class ReportStatus(str, Enum):
    PENDING, GENERATING, COMPLETED, FAILED

class ReportFormat(str, Enum):
    PDF, CSV, JSON, SARIF

class ReportFramework(str, Enum):
    NIST_SP_800_131A, BSI_TR_02102, CNSA_2_0,
    FIPS_140_3, ISO_19790, PQC_MIGRATION_PLAN

class ComplianceReport(BaseModel):
    id: PyObjectId
    scope: Literal["project", "team", "global", "user"]
    scope_id: Optional[str]
    framework: ReportFramework
    format: ReportFormat
    status: ReportStatus
    requested_by: str
    requested_at: datetime
    completed_at: Optional[datetime]
    artifact_gridfs_id: Optional[str]
    artifact_filename: Optional[str]
    artifact_size_bytes: Optional[int]
    artifact_mime_type: Optional[str]
    policy_version_snapshot: Optional[int]
    iana_catalog_version_snapshot: Optional[int]
    summary: Dict[str, Any]
    error_message: Optional[str]
    expires_at: Optional[datetime]
```

Indexes: `(scope, scope_id, framework, requested_at)`, `(status)`, `(expires_at)` for cleanup.
Artifacts in GridFS; metadata persists after artifact expiry.

### `PolicyAuditEntry` (collection `crypto_policy_history`)

```python
class PolicyAuditAction(str, Enum):
    CREATE, UPDATE, DELETE, REVERT, SEED

class PolicyAuditEntry(BaseModel):
    id: PyObjectId
    policy_scope: Literal["system", "project"]
    project_id: Optional[str]
    version: int
    action: PolicyAuditAction
    actor_user_id: Optional[str]
    actor_display_name: Optional[str]     # denormalised
    timestamp: datetime
    snapshot: Dict[str, Any]              # full CryptoPolicy dump
    change_summary: str                   # <=200 chars
    comment: Optional[str]
    reverted_from_version: Optional[int]
```

Indexes: `(policy_scope, project_id, version)`, `(timestamp)` desc, `(actor_user_id, timestamp)`.

### PQC migration data

`backend/app/services/pqc_migration/mappings.yaml` — versioned snapshot. Each mapping keys on `(source_family, source_primitive, use_case)` → `(recommended_pqc, standard, notes)`. Also carries `timelines` list (deadline names, date, applicable families) used in priority scoring.

### Response schemas

```python
class MigrationItemStatus(str, Enum):
    MIGRATE_NOW, MIGRATE_SOON, PLAN_MIGRATION, MONITOR

class MigrationItem(BaseModel):
    asset_bom_ref, asset_name, asset_variant, asset_key_size_bits
    project_ids: List[str]
    asset_count: int
    source_family, source_primitive, use_case
    recommended_pqc, recommended_standard, notes
    priority_score: int               # 0..100
    status: MigrationItemStatus
    recommended_deadline: Optional[str]

class MigrationPlanResponse(BaseModel):
    scope, scope_id, generated_at
    items: List[MigrationItem]
    summary: MigrationPlanSummary
    mappings_version: int
```

### Framework evaluation shape

```python
@dataclass
class ControlDefinition:
    control_id: str
    title: str
    description: str
    severity: Severity
    remediation: str
    maps_to_rule_ids: List[str]
    maps_to_finding_types: List[FindingType]
    custom_evaluator: Optional[Callable]

@dataclass
class ControlResult:
    control_id: str
    title: str
    description: str
    status: Literal["passed", "failed", "waived", "not_applicable"]
    severity: Severity
    evidence_finding_ids: List[str]
    evidence_asset_bom_refs: List[str]
    waiver_reasons: List[str]
    remediation: str

@dataclass
class FrameworkEvaluation:
    framework_key: ReportFramework
    framework_name: str
    framework_version: str
    generated_at: datetime
    scope_description: str
    controls: List[ControlResult]
    summary: Dict[str, int]
    residual_risks: List[ResidualRisk]
    inputs_fingerprint: str
```

### New webhook events + permissions

```python
WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED = "compliance_report.generated"
WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED       = "crypto_policy.changed"
WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED = "pqc_migration_plan.generated"
```

No new permissions — reuses Phase-1/2 admin/member model. Global compliance-reports require `system:manage` or `analytics:global` (Phase 2 permission). Policy-audit-read follows the same scope rules as the policy itself.

## Analyzer / Service details

### ComplianceReportEngine

Orchestrator workflow:
1. Mark pending report `status=generating`
2. Resolve scope → `project_ids`
3. Gather inputs: `CryptoAssets` (latest scans per project), crypto `findings`, effective policy, optional PQC plan
4. Instantiate framework module from `FRAMEWORK_REGISTRY[report.framework]`
5. Call `framework.evaluate(data) → FrameworkEvaluation`
6. Instantiate renderer from `RENDERER_REGISTRY[report.format]`
7. `renderer.render(evaluation, report) → bytes`
8. Upload to GridFS → `artifact_gridfs_id`
9. Set `status=completed`, summary, completed_at, fire webhook
10. On any exception: `status=failed`, `error_message` populated

Each renderer is fail-safe in isolation: a single renderer crash doesn't poison the framework-evaluation artefacts.

### Frameworks

- **NIST SP 800-131A, BSI TR-02102, CNSA 2.0**: controls auto-derived from Phase-1 seed rules. One seed rule → one control, with `maps_to_rule_ids=[rule.rule_id]`. Default evaluator checks for failed findings mapped to those rule_ids + finding types.
- **FIPS 140-3**: static control list of ~30 algorithm-level items from NIST SP 800-140C/D/F. Custom evaluators check `CryptoAsset.name` against approved-algorithm sets. Title page carries "Algorithm-level conformance only" disclaimer.
- **ISO/IEC 19790**: wrapper around FIPS 140-3 with ISO-specific control IDs (Annex D mapping) and preamble.
- **PQC Migration Plan**: meta-framework delegating to `PQCMigrationPlanGenerator`. One `ControlResult` per migration item: `migrate_now`→`failed` HIGH, `migrate_soon`→`failed` MEDIUM, `plan_migration`/`monitor`→`not_applicable`.

### Renderers

All implement `render(evaluation, report) → bytes` and declare `format`, `mime_type`, `extension`.

- **PDF**: WeasyPrint via Jinja2 templates. Cover + Executive Summary (counts + inline SVG donut) + per-control detail + residual-risks + appendix (inputs_fingerprint).
- **CSV**: flat table one row per control.
- **JSON**: nested structure mirroring `FrameworkEvaluation`.
- **SARIF**: SARIF 2.1.0; `tool.driver.name="DependencyControl Compliance"`; failed controls → `results[]` with `ruleId`=control_id; waived → `kind=pass`, `baselineState=unchanged`.

### PQCMigrationPlanGenerator

1. Fetch assets matching quantum-vulnerable primitive set ∩ known-QV family names
2. Per asset: lookup mapping in `mappings.yaml`
3. Compute priority 0..100 via weighted sum:
   - exposure (35%) — heuristic based on asset_type/certificate_format/detection_context
   - key_weakness (30%) — relative to minimum secure key size per family
   - deadline_pressure (25%) — proximity to nearest applicable NIST timeline
   - asset_count (10%) — `log(count+1) * scale`
4. Sort descending; truncate to `limit`
5. Bucket into `MigrationItemStatus` by thresholds (80/50/25)
6. Cache via TTLCache keyed on scope + mappings_version

### Audit history service

`record_policy_change` is the single entry point. Called from all policy-write endpoints and the seeder. Semantics:
- Computes `change_summary` via pure diff of rule sets + specific compared fields
- Inserts `PolicyAuditEntry`
- Dispatches webhook (best-effort)
- Notifies relevant users via existing notification service
- Write failures in audit/webhook/notification are logged but never block the primary policy mutation

### SAST normalizer modification

`_finding_type_from_rule(rule_id) = CRYPTO_KEY_MANAGEMENT if rule_id.startswith("crypto-misuse-") else SAST`. Single-line change; rest of normalizer untouched. Finding fields (component=file:line, details.rule_id) unchanged.

## API endpoints

Compliance reports (6):
```
POST   /api/v1/compliance/reports
GET    /api/v1/compliance/reports?scope=&scope_id=&framework=&status=&limit=&skip=
GET    /api/v1/compliance/reports/{id}
GET    /api/v1/compliance/reports/{id}/download
DELETE /api/v1/compliance/reports/{id}
```

PQC migration (1):
```
GET    /api/v1/analytics/crypto/pqc-migration?scope=&scope_id=&limit=500
```

Policy audit (system + project variants):
```
GET    /api/v1/crypto-policies/system/audit?skip=&limit=50
GET    /api/v1/crypto-policies/system/audit/{version}
POST   /api/v1/crypto-policies/system/revert
DELETE /api/v1/crypto-policies/system/audit?before=<iso>
GET    /api/v1/projects/{project_id}/crypto-policy/audit?skip=&limit=50
GET    /api/v1/projects/{project_id}/crypto-policy/audit/{version}
POST   /api/v1/projects/{project_id}/crypto-policy/revert
DELETE /api/v1/projects/{project_id}/crypto-policy/audit?before=<iso>
```

Authorization:
- Reports: scope-based; `global` requires admin; download revalidates at request time
- Audit read: `system` → admin; `project` → member. Write (revert, prune): owner or admin
- Validation: Pydantic `Query` enums; limit caps (50-500); range caps (audit-prune `before` must be > retention_min)
- Rate limits: POST /compliance/reports → max 10 concurrent pending per user, else 429

Prometheus metrics:
- `compliance_reports_generated_total{framework, format, status}`
- `compliance_report_generation_duration_seconds`
- `policy_audit_entries_written_total{scope, action}`
- `policy_audit_webhook_failures_total`
- `pqc_migration_plans_generated_total{scope}`

## MCP tools

Four new read-only tools in `backend/app/services/chat/tools.py`:
- `generate_pqc_migration_plan(project_id)` → `MigrationPlanResponse` scope=project
- `list_compliance_reports(project_id=None, framework=None, limit=10)` → metadata only
- `list_policy_audit_entries(policy_scope, project_id?, limit=20)` → timeline entries
- `get_framework_evaluation_summary(scope, scope_id, framework)` → `{passed, failed, waived, not_applicable}` counts; no artifact rendering

## Frontend

### `/analytics` Cryptography sub-tabs (new, added to Phase-2 set)

- **PQC Migration** — `PQCMigrationPanel` with summary cards + sortable `MigrationPlanTable` + row-click `MigrationItemDetailDrawer` + "Export as Report" button opening `NewReportDialog` pre-filled with framework=PQC_MIGRATION_PLAN
- **Compliance Reports** — `ComplianceReportsPanel` listing reports with `ReportStatusBadge`; "Generate" button → `NewReportDialog`; polls `/reports` at 2s while any `pending|generating` exist; row-click → `ReportDetailDrawer` with format-specific download buttons

### Policy audit UI

- `/settings/crypto-policy` admin page — append `PolicyAuditTimeline` (entries most-recent-first, expandable diff, revert button)
- Project Crypto Policy Override tab — append `PolicyAuditTimeline` (project scope)
- `PolicyDiffView` shows added/removed/modified rule sections
- `RevertConfirmDialog` requires comment before confirming

### Navigation after Phase 3

`/analytics` Cryptography: Hotspots / Trends / Inventory / Findings / **PQC Migration** / **Compliance Reports**
`/settings/crypto-policy`: editor (existing) + Audit Timeline (new)
Project Crypto Policy Override tab: editor (existing) + Audit Timeline (new)

## Testing

Unit:
- `test_compute_change_summary.py` — extensive diff table cases
- `test_audit_history_service.py` — write + webhook + notification with mocks
- `test_framework_<each>.py` — per-framework control evaluation
- `test_renderer_<each>.py` — format output assertions; SARIF 2.1.0 schema validation
- `test_compliance_engine.py` — orchestrator state machine
- `test_pqc_migration_generator.py` + `test_pqc_mappings_loader.py` + `test_scoring.py`
- `test_sast_normalizer_crypto_misuse.py` — rule-id → finding-type mapping
- Drift sentinels: `test_pqc_mappings_complete.py`, `test_framework_control_ids_unique.py`

Integration:
- `test_compliance_report_lifecycle.py` — full POST → background → download
- `test_compliance_report_permissions.py` — scope/auth paths, cross-user download blocked
- `test_compliance_report_formats.py` — all 4 formats × 1 framework
- `test_compliance_report_expiry.py` — expired artifacts return 410, metadata intact
- `test_policy_audit_integration.py` — write triggers audit + webhook + notification
- `test_policy_revert.py` — revert creates new version with reverted_from_version set
- `test_policy_audit_prune.py` — date-filtered delete
- `test_pqc_migration_endpoint.py` — sort order, cache hit
- `test_sast_ingest_tags_crypto_misuse.py` — ingest fixture → correct finding types

Performance:
- `test_compliance_report_scale.py` — evaluation < 5s for 10k findings × 5k assets, PDF < 10s

Frontend:
- Component tests for `NewReportDialog`, `ReportStatusBadge`, `ComplianceReportsPanel` (polling behavior), `MigrationPlanTable`, `PolicyAuditTimeline`, `PolicyDiffView`

OpenGrep rule-quality gates:
- Each rule has `testdata/positive/` and `testdata/negative/` fixtures; Rules-repo CI runs `opengrep --test` on every PR

## Rollout

Six sequential PRs:

| PR | Scope | Est |
|---|---|---|
| A | FindingType + SAST normalizer + OpenGrep rules + pipeline template updates | 1w |
| B | Policy audit + revert + webhooks + notifications | 1.5w |
| C | Compliance framework engine + 5 framework modules + fixtures | 2w |
| D | Renderers (PDF/CSV/JSON/SARIF) + report endpoints + background task + GridFS | 1.5w |
| E | PQC migration generator + meta-framework + MCP tools | 1w |
| F | Frontend: PQC + Compliance tabs in /analytics + Audit Timeline panels | 1.5w |

Total **~8.5 weeks** for an experienced full-stack engineer.

Dependency rationale:
- A is independent; ships earliest value
- B before C: compliance frameworks consume `policy_version_snapshot`
- C before D: renderers consume `FrameworkEvaluation`
- D before E: PQC meta-framework delegates through engine
- F last: all endpoints ready

No feature flag required.

## Operations

- MongoDB: 2 new collections (`compliance_reports`, `crypto_policy_history`); GridFS already in use
- Env vars (all optional): `COMPLIANCE_REPORT_RETENTION_DAYS` (90), `COMPLIANCE_REPORT_MAX_BYTES` (50_000_000), `POLICY_AUDIT_RETENTION_DAYS` (unset = forever), `CRYPTO_MISUSE_RULES_BASE_URL`
- Dockerfile update for WeasyPrint: install `libcairo2 libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 shared-mime-info`
- Startup health check: render a 1-byte test PDF to verify WeasyPrint at app boot
- Daily retention cleanup task (reuses Phase-2 startup-task pattern): prune expired artifacts + old audit entries
- Webhook registration UI shows 3 new events

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| WeasyPrint system libs missing in prod → silent render failure | Dockerfile update + startup health check logs failure |
| FIPS/ISO reports perceived as CMVP-certified | Title-page disclaimer + meta-field in JSON/CSV/SARIF |
| Large reports → GridFS memory spike | Hard cap + pre-write size check + `status=failed` with clear message |
| Webhook failures lose audit trail | Audit entry persisted BEFORE webhook; failures counted in metric; Prune never touches entries that lack webhook-success confirmation |
| PQC mappings stale after NIST updates | `CURRENT_MAPPINGS_VERSION` + drift sentinel test |
| OpenGrep rules produce noise | Rule-quality gate with `testdata/positive/negative` in rules-repo CI; conservative entropy filters on hardcoded-keys rule |
| Revert reactivates dangerous rules | Revert always creates new version (immutable history); audit entry + webhook for SIEM visibility |
| Report generation concurrency | 10-concurrent semaphore per user; 429 with Retry-After |
| SARIF schema drift | JSON-Schema validation in unit tests |
| ISO/FIPS mapping mismatch with customer expectation | Inputs_fingerprint + framework-version in every report cover |

## Explicit non-goals (re-stated for clarity)

- CMVP integration (Phase 4)
- Policy conflict detection (Phase 4)
- Scheduled reports
- External share-links
- LLM-prose migration summaries
- Backend rule endpoint for crypto-misuse (architecturally future-ready)
- Audit grouping / roll-ups
- Cross-framework combined scoring

## Estimated effort

**8.5 weeks**, 6 PRs, single experienced full-stack engineer.
