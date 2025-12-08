# Dependency Control

**Dependency Control** is a centralized security and compliance platform for managing software dependencies. It ingests SBOMs (Software Bill of Materials) and Secret Scan results from your CI/CD pipelines, analyzes them for vulnerabilities, license issues, and malware, and provides a unified dashboard for risk management.

## Features

*   **Centralized Ingestion:** Accepts SBOMs (CycloneDX/SPDX) and TruffleHog secret scans via API.
*   **Multi-Scanner Analysis:** Aggregates results from **Trivy**, **Grype**, **OSV**, **Deps.dev**, **End-of-Life**, **Malware**, and **Typosquatting** analyzers.
*   **Secret Management:** Tracks leaked secrets and allows marking them as false positives (Waivers).
*   **Waiver System:** Define exceptions for vulnerabilities or secrets (e.g., "Accepted Risk" or "False Positive") to keep pipelines green.
*   **Notifications:** Alerts via Email, Slack, or Mattermost when critical issues are found.
*   **Housekeeping:** Automatically cleans up old scan data based on retention policies.

## Quick Start (Docker Compose)

Ideal for testing and local development.

### 1. Configure Hosts
Since Traefik is used for routing with custom domains, add the following to your `/etc/hosts` file:
```
127.0.0.1 api.dependencycontrol.local appsmith.local metabase.local
```

### 2. Start the Stack
```bash
docker compose up -d --build
```

### 3. Access Services
*   **Backend API:** `https://api.dependencycontrol.local/docs`
*   **Appsmith (Frontend):** `https://appsmith.local`
    *   Used for managing projects, waivers, and viewing findings.
*   **Metabase (Analytics):** `https://metabase.local`
    *   Used for advanced dashboards and reporting.

*Note: You may need to accept the self-signed certificate warning in your browser.*

## Production Deployment (Kubernetes)

A Helm chart is provided for deploying to Kubernetes.

### Prerequisites
*   Kubernetes Cluster (v1.24+)
*   Helm (v3.0+)
*   MongoDB (or use the included operator)

### Installation

1.  **Add the repository:**
    ```bash
    helm repo add dependency-control https://morzan1001.github.io/Dependency-Control/
    helm repo update
    ```

2.  **Install the chart:**
    ```bash
    helm upgrade --install dependency-control dependency-control/dependency-control \
      --namespace dependency-control --create-namespace \
      --set backend.secrets.secretKey="YOUR_SECURE_KEY"
    ```

## CI/CD Integration

Integrate Dependency Control into your pipelines to block builds on critical findings.

### GitHub Actions
```yaml
- name: Upload SBOM
  run: |
    curl -X POST "$DEP_CONTROL_URL/api/v1/ingest" \
      -H "x-api-key: ${{ secrets.DEP_CONTROL_API_KEY }}" \
      -d @payload.json
```

### GitLab CI
```yaml
dependency-scan:
  script:
    - curl -X POST "$DEP_CONTROL_URL/api/v1/ingest" ...
```

See `ci-cd/` for full examples including TruffleHog integration.

## License

MIT License. See [LICENSE](LICENSE) for details.
