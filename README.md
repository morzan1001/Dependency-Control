# Dependency Control

**Dependency Control** is a centralized security and compliance platform for managing software supply chain risks. It aggregates SBOMs, CBOMs, secret scans, SAST, and IaC analysis to provide a unified view of your project's security and cryptographic posture.

[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=morzan1001_Dependency-Control&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=morzan1001_Dependency-Control)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=morzan1001_Dependency-Control&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=morzan1001_Dependency-Control)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=morzan1001_Dependency-Control&metric=bugs)](https://sonarcloud.io/summary/new_code?id=morzan1001_Dependency-Control)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=morzan1001_Dependency-Control&metric=coverage)](https://sonarcloud.io/summary/new_code?id=morzan1001_Dependency-Control)

![Dashboard](assets/dashboard.png)

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **Security Analysis** | Vulnerability scanning (Trivy, Grype, OSV, deps.dev) with EPSS + KEV prioritisation, secret detection, SAST, IaC misconfiguration, malware & typosquatting checks |
| **License & Lifecycle** | SPDX-driven license compliance, cross-dependency compatibility, End-of-Life monitoring, OSSF Scorecard, scoped waivers |
| **Cryptography & PQC** | CycloneDX 1.6 CBOM ingestion, weak-algorithm/key/protocol detection, IANA-backed cipher-suite checks, certificate lifecycle, framework-seeded policy with audit trail, per-asset PQC migration plan |
| **Compliance Reports** | NIST SP 800-131A, BSI TR-02102, FIPS 140-3, ISO/IEC 19790, CNSA 2.0, License Audit, CVE Remediation SLA, PQC Migration Plan — JSON / CSV / SARIF / PDF |
| **Recommendations** | Prioritised remediations across vulnerabilities, secrets, SAST, IaC, licenses, quality, and crypto findings |
| **Analytics & Reporting** | Risk scoring, trend series, scan-to-scan deltas, hotspots, SBOM/CBOM inventory, centralized dashboard, Metabase analytics |
| **Project & Access** | Project & Team management, fine-grained permissions, 2FA, project API keys |
| **Integrations** | GitLab CI/CD (OIDC), GitHub Actions (OIDC), Webhooks, Email/Slack/Mattermost notifications, MCP server for LLM clients |

<p align="center">
  <img src="assets/pipeline.png" width="48%" alt="Pipeline Integration" />
  <img src="assets/project.png" width="48%" alt="Project View" />
</p>

## 🔍 Supported Scanners

Dependency Control integrates with leading open-source security tools to provide comprehensive coverage.

### CI/CD Scanners (Ingestion)
These tools run in your pipeline and send data to Dependency Control:
*   **[Syft](https://github.com/anchore/syft)** - Generates Software Bill of Materials (SBOM) from container images and filesystems.
*   **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** - Scans for leaked credentials and secrets in your codebase.
*   **[OpenGrep](https://github.com/opengrep/opengrep)** - Fast and lightweight Static Application Security Testing (SAST). Ships with a dedicated **crypto-misuse** ruleset (hardcoded keys, weak RNG, ECB mode, IV reuse, insecure TLS, weak hashes, low PBKDF2 iterations) — see the pipeline-templates repo `rules/crypto-misuse/`.
*   **[Bearer](https://github.com/bearer/bearer)** - Code security scanning focusing on sensitive data flows and privacy.
*   **[KICS](https://github.com/Checkmarx/kics)** - Finds security vulnerabilities, compliance issues, and infrastructure misconfigurations in IaC.
*   **[IBM CBOMkit-theia](https://github.com/IBM/cbomkit-theia)** - Generates a Cryptographic Bill of Materials (CBOM) by scanning source code for cryptographic assets.

### SBOM Analysis (Internal)
Once an SBOM is ingested, the backend performs deep analysis using:
*   **[Trivy](https://github.com/aquasecurity/trivy)** & **[Grype](https://github.com/anchore/grype)** - Vulnerability scanning against the SBOM.
*   **[OSV.dev](https://osv.dev)** - Distributed vulnerability database.
*   **[Deps.dev](https://deps.dev)** - Insights on dependency health and security.
*   **End-of-Life** - Checks for software components that have reached their end of life.
*   **Malware Detection** - Checks packages against known open-source malware databases.
*   **Typosquatting** - Detects potential typosquatting attacks in dependency names.
*   **License Compliance** - Analyzes licenses for compliance and risk.

## 🧪 Analysis Capabilities

Each domain receives the same treatment: ingestion, deduplication, prioritised findings, scoped waivers, and trend/delta analytics.

### Vulnerabilities

*   Combined finding stream from **Trivy**, **Grype**, **OSV.dev**, and **deps.dev** — deduplicated by CVE/GHSA/PURL with source attribution preserved.
*   **EPSS** scoring and **CISA KEV** flagging to surface what is being actively exploited.
*   **Reachability analysis** via call-graph integration so non-reachable CVEs can be deprioritised.
*   **Auto-fixable suggestion** computes the lowest version that resolves every active CVE for a package.
*   Stale-finding sweeps and configurable suppression windows.

### Secrets

*   **TruffleHog** ingestion with detector metadata, line-precise locations, and verified-status preservation.
*   Redacted values only — raw secrets never persisted.
*   Finding-, file-, and rule-scope waivers with reason tracking.

### SAST & IaC

*   **OpenGrep** and **Bearer** SAST results, **KICS** IaC misconfigurations.
*   Dedicated crypto-misuse OpenGrep ruleset: hardcoded keys, weak RNG, ECB mode, IV reuse, insecure TLS, weak hashes, low PBKDF2 iterations.
*   Rule-scope waivers so suppressing one rule applies across every file in the project.

### License compliance

*   SPDX-driven categorisation: permissive / weak-copyleft / strong-copyleft / network-copyleft / proprietary / unknown.
*   Per-project policy with distribution model, deployment model, and library-usage controls — plus allowlist / denylist.
*   Cross-dependency compatibility checks (GPL-2.0 vs GPL-3.0, EPL vs GPL, CDDL vs GPL, SSPL collisions).
*   Scoped waivers (finding, file, rule).

### Cryptography & PQC

*   **CycloneDX 1.6 CBOM** ingestion (IBM [CBOMkit-theia](https://github.com/IBM/cbomkit-theia)) analysed against configurable cryptographic policies.
*   Detection: weak algorithms (MD5, SHA-1, DES, 3DES, RC4), weak keys (RSA < 2048/3072, short DSA/ECDSA), weak protocols (TLS 1.0/1.1, SSHv1), cipher-suite weaknesses (live IANA TLS registry, Redis-cached), certificate-lifecycle problems, quantum-vulnerable primitives.
*   Policy seeded from **NIST SP 800-131A**, **BSI TR-02102**, **CNSA 2.0**, **NIST PQC**; per-project overrides with full audit trail and revert.
*   Per-asset PQC migration plan (ML-KEM / ML-DSA / SLH-DSA mappings, priority score, deadline).

### Quality & lifecycle

*   **End-of-Life** monitoring via [endoflife.date](https://endoflife.date).
*   **Malware** detection against open-source malware databases.
*   **Typosquatting** detection on dependency names.
*   **OSSF Scorecard** for maintainer-risk surface.

### Compliance reports

Point-in-time reports against any of the bundled frameworks:

| Framework | Use case |
|-----------|----------|
| `nist-sp-800-131a` | NIST algorithm transition status |
| `bsi-tr-02102` | German BSI cryptographic catalog |
| `fips-140-3` | FIPS 140-3 algorithm-level conformance |
| `iso-19790` | ISO/IEC 19790:2012 (FIPS-aligned) |
| `cnsa-2.0` | NSA CNSA 2.0 PQC / classical guidance |
| `license-audit` | SPDX-driven license risk audit |
| `cve-remediation-sla` | Time-to-fix tracking against severity SLAs |
| `pqc-migration-plan` | Per-asset post-quantum transition target |

Output formats: JSON, CSV, SARIF, PDF (PDF requires WeasyPrint / Pango / Cairo system libraries in the runtime image).

### Cross-cutting

*   Prioritised remediation engine across **all** finding types (vulnerabilities, secrets, SAST, IaC, licenses, quality, crypto).
*   Trend analysis, hotspots, and scan-to-scan deltas — available for vulnerabilities, components, and crypto assets.
*   MCP server so LLM clients (Claude, Cursor, …) can query findings, generate remediation plans, and inspect the policy state directly.

## 🛠️ Quick Start (Docker Compose)

The easiest way to run Dependency Control locally.

### 1. Configure Hosts
Add the following to your `/etc/hosts` file to route traffic correctly via Traefik:
```
127.0.0.1 dependencycontrol.local api.dependencycontrol.local metabase.local
```

### 2. Start the Stack
```bash
docker compose up -d --build
```

### 3. Access Services
*   **Frontend Dashboard:** [https://dependencycontrol.local](https://dependencycontrol.local)
*   **Backend API Docs:** [https://api.dependencycontrol.local/docs](https://api.dependencycontrol.local/docs)
*   **Metabase (Analytics):** [https://metabase.local](https://metabase.local)

*Note: Accept the self-signed certificate warning in your browser.*

## 📦 CI/CD Integration

Dependency Control is designed to sit in your CI/CD pipeline.

### GitLab CI (OIDC)
Enable **GitLab Integration** in the System Settings, then use the `CI_JOB_TOKEN` to authenticate. No manual API Key management required!

```yaml
dependency-scan:
  script:
    - |
      curl -X POST "https://api.dependencycontrol.local/api/v1/ingest" \
        -H "Content-Type: application/json" \
        -H "JOB-TOKEN: $CI_JOB_TOKEN" \
        -d @payload.json
```

### GitHub Actions (OIDC)
Enable **GitHub Integration** in the System Settings, then use the `ACTIONS_ID_TOKEN_REQUEST_TOKEN` to authenticate. No manual API Key management required!

```yaml
- name: Dependency Scan
  env:
    ACTIONS_ID_TOKEN_REQUEST_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}
  run: |
    OIDC_TOKEN=$(curl -s -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=dependency-control" | jq -r '.value')
    curl -X POST "https://api.dependencycontrol.local/api/v1/ingest" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $OIDC_TOKEN" \
      -d @payload.json
```

> **Note:** The GitHub Actions workflow must have `id-token: write` permission.

### API Key (Other CI Systems)
For other systems (Jenkins, etc.), generate a Project API Key in the dashboard and use the `X-API-Key` header.

```bash
# SBOM ingest
curl -X POST "https://api.dependencycontrol.local/api/v1/ingest" \
  -H "x-api-key: $DEP_CONTROL_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @sbom-payload.json

# CBOM ingest (CycloneDX 1.6 with cryptographic-asset components)
curl -X POST "https://api.dependencycontrol.local/api/v1/ingest/cbom" \
  -H "x-api-key: $DEP_CONTROL_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @cbom-payload.json
```

CBOM payloads are capped at 25 MiB; oversized uploads return `413 Payload Too Large`.

### Pinning the bundled scanner

The backend serves a reusable `scanner.sh` for SBOM/CBOM/secret/SAST/IaC ingestion. Every released version is **frozen** under `ci-cd/scripts/versions/scanner-X.Y.Z.sh` and is reachable through `?v=X.Y.Z`; the unversioned URL serves whichever version is currently the latest pointer.

```bash
# Discover the current frozen versions and their hashes
curl -sSL "$DEP_CONTROL_URL/api/v1/scripts" | jq

# Pin the version + hash you reviewed; future deploys won't change the bytes
SCANNER_VERSION="1.1.0"
SCANNER_SHA256="<from manifest>"

curl -sSfL "$DEP_CONTROL_URL/api/v1/scripts/scanner.sh?v=$SCANNER_VERSION" -o scanner.sh
echo "$SCANNER_SHA256  scanner.sh" | sha256sum -c -
bash scanner.sh all
```

Without `?v` the response is the latest pointer and may change on any backend deploy — fine for ad-hoc use, never pin a hash against it.

👉 **See [ci-cd/](ci-cd/) for complete pipeline examples.**

## 🤖 MCP Integration

Dependency Control exposes its tool suite over [Model Context Protocol](https://modelcontextprotocol.io) so Claude Desktop, Cursor & Co. can query your security data directly. Create a token under **Profile → MCP API Keys** (requires `mcp:access`), then point your client at `POST /api/v1/mcp`:

```json
{
  "mcpServers": {
    "dependency-control": {
      "type": "http",
      "url": "https://your-dependency-control.example.com/api/v1/mcp",
      "headers": { "Authorization": "Bearer mcp_YOUR_TOKEN_HERE" }
    }
  }
}
```

## ☸️ Kubernetes Deployment

A Helm chart is available for production deployments.

```bash
helm upgrade --install dependency-control ./helm/dependency-control \
  --namespace dependency-control --create-namespace \
  --set backend.secrets.secretKey="CHANGE_ME"
```

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
