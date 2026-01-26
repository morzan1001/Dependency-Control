# Dependency Control Helm Chart

SBOM management platform with HA MongoDB, DragonflyDB cache, and optional internal TLS.

## Quick Start

```bash
helm install dependency-control ./dependency-control -f values.yaml
```

## Key Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.tls.enabled` | Enable internal TLS | `false` |
| `global.tls.source` | `certManager` or `custom` | `certManager` |
| `database.type` | `mongodb` or `percona` | `mongodb` |
| `secrets.provider` | `kubernetes` or `external-secrets` | `kubernetes` |
| `ingress.enabled` | Enable Ingress | `false` |
| `ingress.className` | Ingress class (`traefik`, `nginx`, `pomerium`) | `traefik` |

## Production Example

```yaml
global:
  tls:
    enabled: true
    source: certManager

environment: production

database:
  type: percona
  cluster:
    replicas: 3

secrets:
  provider: external-secrets

ingress:
  enabled: true
  className: pomerium
  hostname: app.example.com
  tls: true
  annotations:
    ingress.pomerium.io/tls_upstream: "true"
    ingress.pomerium.io/tls_custom_ca_secret: "my-release-dependency-control-root-ca-secret"

networkPolicy:
  enabled: true
```

## Components

- **Backend**: FastAPI application (Python)
- **Frontend**: Vue.js SPA (Nginx)
- **Database**: MongoDB (Community Operator) or Percona Server for MongoDB
- **Cache**: DragonflyDB (Redis-compatible)

## Dependencies

| Chart | Purpose |
|-------|---------|
| `mongodb-operator` | MongoDB Community Operator |
| `psmdb-operator` | Percona MongoDB Operator |
| `dragonfly` | Redis-compatible cache |
| `traefik` | Ingress controller (optional) |
| `cert-manager` | TLS certificates (optional) |

## Documentation

See [values.yaml](values.yaml) for all configuration options.
