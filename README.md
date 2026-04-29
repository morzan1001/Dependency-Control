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
| **Security Analysis** | Vulnerability scanning (Trivy, Grype, OSV), Secret detection, SAST, Malware & Typosquatting detection |
| **Cryptographic Analysis** | CycloneDX 1.6 CBOM ingestion, weak-algorithm / weak-key / weak-protocol detection, certificate lifecycle, cipher-suite weakness checks (IANA-backed), quantum-vulnerability assessment |
| **Crypto Policy Engine** | System-wide policy seeded from NIST SP 800-131A, BSI TR-02102, CNSA 2.0 and NIST PQC; per-project overrides, full audit trail with revert |
| **Compliance Reports** | NIST SP 800-131A, BSI TR-02102, FIPS 140-3, ISO/IEC 19790, CNSA 2.0, License Audit, CVE Remediation SLA, PQC Migration Plan — JSON / CSV / SARIF / PDF |
| **Crypto Analytics** | Hotspots (per asset name / primitive / type / severity / weakness tag), trend series, scan-to-scan deltas |
| **PQC Migration** | Per-asset post-quantum migration plan (ML-KEM / ML-DSA / SLH-DSA mappings, deadlines, priority scoring) |
| **License & Lifecycle** | License compliance, End-of-Life monitoring, policy enforcement with scoped waivers |
| **Recommendations** | Prioritised remediations across vulnerabilities, secrets, SAST, IaC, licenses, quality, and crypto findings |
| **Management** | Project & Team management, fine-grained permissions, 2FA, project API keys |
| **Integrations** | GitLab CI/CD (OIDC), GitHub Actions (OIDC), Webhooks, Email/Slack/Mattermost notifications, MCP server for LLM clients |
| **Visibility** | Risk scoring, trend analysis, SBOM/CBOM inventory, centralized dashboard, Metabase analytics |

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

### Cryptographic Analysis

**Dependency Control** ingests CycloneDX-1.6 Cryptographic Bills of Materials (CBOMs) produced by [IBM CBOMkit-theia](https://github.com/IBM/cbomkit-theia) and analyses them against configurable cryptographic policies.

**Detection coverage**

*   **Weak algorithms** — MD5, SHA-1, DES, 3DES, RC4 and other primitives disallowed by the active policy.
*   **Weak keys** — RSA below the policy minimum (2048 / 3072 bits depending on framework), short DSA/ECDSA parameters.
*   **Quantum-vulnerable primitives** — classical RSA, DH, ECDH, ECDSA, EC-DSA flagged for PQC migration; post-quantum primitives (ML-KEM, ML-DSA, SLH-DSA) are explicitly not flagged.
*   **Weak protocols** — TLS 1.0 / 1.1, SSHv1 and similar deprecated versions.
*   **Cipher-suite weaknesses** — backed by the live IANA TLS cipher-suite registry (Redis-cached, with a bundled YAML fallback) so suites like `TLS_RSA_WITH_RC4_128_SHA` surface their weakness tags (`weak-cipher-rc4`, `weak-mac-sha1`, `no-forward-secrecy`, …).
*   **Certificate lifecycle** — expired / expiring-soon / not-yet-valid / weak-signature / weak-key / self-signed / validity-too-long.
*   **Key-management hygiene** — fed from the OpenGrep crypto-misuse SAST ruleset (hardcoded keys, weak RNG, ECB mode, IV reuse, insecure TLS, weak hashes, low PBKDF2 iterations).

**Policy engine**

*   Seeded with **NIST SP 800-131A**, **BSI TR-02102**, **CNSA 2.0** and **NIST PQC** recommendations.
*   Per-project overrides editable via the dashboard.
*   Full **policy audit trail** (every create / update / delete / revert recorded, with diff view and revert action).
*   Multi-framework matches collapse into a single finding with `details.matched_rules` listing every framework that flagged the asset.

**Compliance reports**

Generate point-in-time reports against any of the bundled frameworks:

| Framework | Use case |
|-----------|----------|
| `nist-sp-800-131a` | NIST algorithm transition status |
| `bsi-tr-02102` | German BSI cryptographic catalog |
| `fips-140-3` | FIPS 140-3 algorithm-level conformance |
| `iso-19790` | ISO/IEC 19790:2012 (algorithm-level, FIPS-aligned) |
| `cnsa-2.0` | NSA CNSA 2.0 PQC / classical guidance |
| `license-audit` | SPDX-driven license risk audit |
| `cve-remediation-sla` | Time-to-fix tracking against severity SLAs |
| `pqc-migration-plan` | Per-asset post-quantum transition target |

Output formats: JSON, CSV, SARIF, PDF (PDF requires WeasyPrint / Pango / Cairo system libraries in the runtime image).

**Crypto analytics**

*   `GET /api/v1/analytics/crypto/hotspots` — top crypto hotspots grouped by asset name, primitive, asset type, severity, or weakness tag.
*   `GET /api/v1/analytics/crypto/trends` — time-bucketed crypto finding / asset trends.
*   `GET /api/v1/analytics/crypto/scan-delta` — added / removed / unchanged crypto assets between two scans.
*   `GET /api/v1/analytics/crypto/pqc-migration` — generated PQC migration plan for the current scope.

**Pipeline templates**

Ready-to-use pipeline templates are available in the [dependency-control-pipeline-templates](https://github.com/zakmccracken/dependency-control-pipeline-templates) repository:

*   **GitLab CI** — [`cbom-scan.gitlab-ci.yml`](https://github.com/zakmccracken/dependency-control-pipeline-templates/blob/main/cbom-scan.gitlab-ci.yml)
*   **GitHub Actions** — [`cbom-scan.github-actions.yml`](https://github.com/zakmccracken/dependency-control-pipeline-templates/blob/main/cbom-scan.github-actions.yml)

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
