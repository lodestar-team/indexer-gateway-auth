# indexer-gateway-auth Helm chart

Deploys [`indexer-gateway-auth`](https://github.com/lodestar-team/indexer-gateway-auth),
an authenticating reverse proxy for the Graph Indexer Management API.

## Install

```sh
kubectl create secret generic iga-tokens \
  --from-literal=IGA_TOKEN_OPERATOR="$(openssl rand -hex 32)"

helm install iga ./charts/indexer-gateway-auth \
  --set existingSecret=iga-tokens
```

## Key values

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/lodestar-team/indexer-gateway-auth` | Image repository |
| `image.tag` | `""` (chart appVersion) | Image tag |
| `replicaCount` | `1` | Number of replicas |
| `config` | see `values.yaml` | The `config.toml`, rendered into a ConfigMap |
| `existingSecret` | `""` | Secret whose keys become env vars resolving `env:` token refs |
| `service.port` | `8400` | Proxy port |
| `service.metricsPort` | `7300` | Prometheus metrics port |
| `probes.enabled` | `true` | Wire `/healthz` + `/readyz` probes |
| `serviceMonitor.enabled` | `false` | Create a Prometheus `ServiceMonitor` |
| `resources` | small defaults | Container resource requests/limits |

The container runs as non-root (uid 65532) with a read-only root filesystem; the
audit log is written to stdout.

## Secrets

Never inline real tokens in `config`. Reference them as `env:NAME` and provide a
Secret (via `existingSecret`) whose keys match those names.
