# Dependency Control Helm Chart

A production-ready Helm chart for deploying the Dependency Control stack on Kubernetes, designed for high availability and security.

## Features

*   **High Availability**:
    *   **Backend**: Horizontal Pod Autoscaling (HPA), Pod Disruption Budgets (PDB), and Pod Anti-Affinity for fault tolerance.
    *   **Database**: MongoDB Replica Set (3 members) managed via the [MongoDB Community Operator](https://github.com/mongodb/mongodb-kubernetes-operator).
*   **Security**:
    *   **Hardening**: Containers run as non-root, read-only root filesystems, and dropped capabilities.
    *   **Network**: Strict Network Policies (Default Deny) to isolate components.
*   **Ingress**: Integrated Traefik Ingress Controller with TLS support.

## Prerequisites

*   Kubernetes 1.19+
*   Helm 3.0+

## Installation

1.  **Update Dependencies**:
    ```bash
    helm dependency update ./helm/dependency-control
    ```

2.  **Install Chart**:
    ```bash
    helm install dep-control ./helm/dependency-control \
      --namespace dependency-control \
      --create-namespace
    ```

## Configuration

Key configuration options in `values.yaml`:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `backend.autoscaling.enabled` | Enable Horizontal Pod Autoscaler | `true` |
| `backend.replicaCount` | Initial replica count | `2` |
| `mongodb.cluster.members` | Number of MongoDB Replica Set members | `3` |
| `networkPolicy.enabled` | Enable strict network policies | `true` |
| `traefik.enabled` | Enable Traefik Ingress Controller | `true` |

### Secrets Management
For production environments, it is recommended to manage secrets (like `backend.secrets.secretKey` or API keys) using external tools like **External Secrets Operator** or **Sealed Secrets**, rather than passing them directly in `values.yaml`.

## Architecture

*   **Backend**: FastAPI service handling SBOM ingestion and analysis. Scales based on CPU usage.
*   **Workers**: Integrated async workers for processing scans (Trivy, Grype, etc.).
*   **Database**: MongoDB Replica Set provided by the Community Operator.
