<h1 align="center">indexer-gateway-auth</h1>

<p align="center">
  <em>An authenticating reverse proxy for the Graph Protocol Indexer Management API.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0">
  <img src="https://img.shields.io/badge/rust-2021-orange.svg" alt="Rust 2021">
  <img src="https://img.shields.io/badge/status-alpha-yellow.svg" alt="Status: alpha">
</p>

---

`indexer-gateway-auth` (`iga`) is a small, stateless reverse proxy that places an
application-layer **authentication and authorization** boundary in front of the
Indexer Management API (served by `indexer-agent`, default `:18000`/`:8000`) and
the `graph-node` **admin** (`:8020`) and **status** (`:8030`) endpoints.

It adds bearer-token, JWT, and mTLS authentication; GraphQL-operation-aware
authorization (read vs. mutate, with per-field overrides); a structured audit
record of every state-mutating call; and rate limiting — **with zero changes to
upstream components**. It ships as a sidecar and stays a drop-in for existing
community tooling: `indexer-tools-v3`, the Indexer CLI, and `curl`-based scripts.

> Design rationale: **TOOL-RFC-001**.

## Why this exists

The Indexer Management API permits state-mutating operations — setting indexing
rules, queuing/approving/executing allocation actions, writing cost models — that
directly govern how an indexer deploys stake and earns revenue. The standard
interaction model is an **unauthenticated** local connection
(`graph indexer connect http://localhost:18000`), and the only documented
protection is network isolation. There is **no token, scope, or audit mechanism**
anywhere in the management-API surface.

Operators work around this with VPNs, overlay networks, and bundled reverse
proxies — all of which solve the problem at the network layer and provide no
identity, scoping, or audit trail. `iga` closes the application-layer gap
directly and supplies the missing audit surface, while the durable fix (native
auth in `indexer-agent`, a token field in `indexer-tools`) is pursued upstream.

## Features

- 🔑 **Authentication** — static bearer tokens (constant-time comparison), JWT
  (HS256 today, JWKS/RS256/ES256 ready), and mTLS subject/SAN → principal mapping.
- 🛡️ **GraphQL-aware authorization** — the body is *parsed, never executed*; a
  `mutation` root is a `write`, `query`/`subscription` a `read`. Aliases resolve
  to real field names and fragments are expanded, so neither can mask a gated
  field. Policy can demand fine-grained scopes (e.g. `actions:execute`) per field
  or named operation.
- 📓 **Audit trail** — every write (optionally every read) is one structured JSON
  line: principal, source IP, operation, hashed variables, upstream status, and
  latency.
- 🚦 **Rate limiting** — separate read/write budgets *(in progress)*.
- 📈 **Observability** — Prometheus metrics on `:7300` *(in progress)*.
- 🪶 **Drop-in & stateless** — a single static binary; horizontally scalable;
  trivially deployable as a sidecar.

## Architecture

```
                          indexer-gateway-auth (sidecar)
                       ┌───────────────────────────────────┐
indexer-tools-v3  ─────▶  authn ─▶ authz ─▶ audit ─▶ proxy  ├─▶ indexer-agent :18000
indexer-cli       ─────▶  (token  (scope   (JSON   (reqwest │   graph-node    :8020/:8030
curl / scripts    ─────▶   /mTLS)  policy)  log)     pass)  │
                       └───────────────────────────────────┘
                                      │ /metrics :7300 (Prometheus)
```

The proxy holds the only network path to the upstream; the upstream binds to
`localhost` or a cluster-internal address. A request flows through four stages —
**authenticate → classify & authorize → audit → proxy** — and the GraphQL body is
read exactly once.

### Request lifecycle

1. **Authentication.** mTLS client certificate → `Authorization: Bearer <token>`.
   Static tokens match a configured set; JWTs are verified (signature, `exp`,
   `nbf`, issuer, audience) with scopes read from a claim. A missing credential is
   `401` unless an `anonymous` read-only principal is explicitly enabled; an
   *invalid* credential is always `401`.
2. **Classification.** Structural and fail-closed — a malformed body is rejected
   (`400`), never forwarded. Batched and multi-operation documents take the
   **highest** scope present.
3. **Authorization.** The principal's scopes are matched against the classified
   scope (`write` implies `read`); matching policy overrides only ever *tighten*
   the requirement. Denials are `403`.
4. **Audit.** A single JSON line is emitted to the configured sink.
5. **Proxy.** The request is forwarded to the routed upstream and the response
   relayed back. Hop-by-hop headers and the gateway's own `Authorization` header
   are stripped — the upstream never sees the bearer token.

## Quick start

```sh
# 1. Build
cargo build --release

# 2. Configure (copy and edit the example)
cp config.example.toml config.toml

# 3. Supply secrets via the environment (never inline them)
export IGA_TOKEN_CI="$(openssl rand -hex 32)"
export IGA_TOKEN_OPERATOR="$(openssl rand -hex 32)"

# 4. Run
./target/release/indexer-gateway-auth --config config.toml
```

With `indexer-agent` bound to `127.0.0.1:18000`, point your tooling at the proxy
instead:

```sh
# A read-only query — allowed for the read token
curl -s http://localhost:8400/ \
  -H "Authorization: Bearer $IGA_TOKEN_CI" \
  -H 'content-type: application/json' \
  -d '{"query":"{ indexingRules { identifier } }"}'

# A mutation with the read token — denied (403), never reaches the upstream
curl -s http://localhost:8400/ \
  -H "Authorization: Bearer $IGA_TOKEN_CI" \
  -H 'content-type: application/json' \
  -d '{"query":"mutation { setIndexingRule(rule: {}) { identifier } }"}'

# The same mutation with the operator token — allowed
curl -s http://localhost:8400/ \
  -H "Authorization: Bearer $IGA_TOKEN_OPERATOR" \
  -H 'content-type: application/json' \
  -d '{"query":"mutation { setIndexingRule(rule: {}) { identifier } }"}'
```

For **`indexer-tools-v3`**, point its `agentEndpoint` at the proxy and pass the
token via the request `Authorization` header.

## Authentication modes

Set `auth.mode` to one of:

| Mode | Credential | Principal & scopes from |
|------|------------|-------------------------|
| `bearer` | `Authorization: Bearer <token>` | matched `[[auth.tokens]]` entry |
| `jwt` | `Authorization: Bearer <jwt>` | verified claims (`sub`, `scopes_claim`) |
| `mtls` | client certificate | matched `[[auth.mtls]]` subject (CN/SAN) |

## Scopes & policy

Scopes are plain strings. The two built-ins are `read` and `write`, and `write`
satisfies `read`. Anything else (e.g. `actions:execute`) is matched exactly and
only granted when policy requires it:

```toml
[[policy.override]]
field          = "executeApprovedActions"   # gate a specific top-level field…
require_scopes = ["actions:execute"]         # …behind an extra scope

[[policy.override]]
operation      = "DangerousOp"               # …or a specific named operation
require_scopes = ["actions:execute"]
```

An operator token would then need both `write` *and* `actions:execute` to invoke
`executeApprovedActions`.

## Routing

By default everything is forwarded to the management API. Two path prefixes route
to `graph-node` (the prefix is stripped before forwarding):

| Request path | Upstream |
|--------------|----------|
| `/...` | `upstream.agent_management` (`:18000`) |
| `/_admin/...` | `upstream.graph_node_admin` (`:8020`) — JSON-RPC, treated as `write` |
| `/_status/...` | `upstream.graph_node_status` (`:8030`) |

## Audit log

Each audited request is a single JSON line (variables are hashed by default;
raw values are only logged when explicitly enabled):

```json
{"timestamp":"2026-06-01T12:00:00+00:00","principal":"operator","source_ip":"10.0.0.5","scope":"write","operation_name":"SetRule","operation_kinds":["mutation"],"top_level_fields":["setIndexingRule"],"variables_hash":"9f86d0…","outcome":"allowed","upstream_status":200,"latency_ms":12}
```

## Configuration

TOML, with `env:NAME` references for secrets resolved at load time. See
[`config.example.toml`](config.example.toml) for the fully-commented reference.

```toml
listen  = "0.0.0.0:8400"
metrics = "0.0.0.0:7300"

[upstream]
agent_management  = "http://127.0.0.1:18000"
graph_node_admin  = "http://127.0.0.1:8020"
graph_node_status = "http://127.0.0.1:8030"

[auth]
mode = "bearer"

[[auth.tokens]]
name   = "operator"
token  = "env:IGA_TOKEN_OPERATOR"   # resolved from the environment
scopes = ["read", "write"]

[policy]
fail_closed_on_parse_error = true

[ratelimit]
write_per_minute = 30
read_per_minute  = 600
```

Static tokens **must** be supplied via `env:` references, never inlined in
committed config.

## Security model

- The proxy **must** be the sole network path to the upstream; bind the upstream
  to `localhost`/cluster-internal for the control to be meaningful.
- Static tokens are compared in **constant time** and supplied via the
  environment — never inlined.
- The gateway's `Authorization` header is **not** forwarded upstream, so the
  bearer token cannot leak into upstream logs.
- The proxy **parses but never executes** GraphQL; a malformed body **fails
  closed**.
- TLS should be enabled whenever the proxy is reachable beyond `localhost`; mTLS
  is recommended for zero-trust setups.

## Development

```sh
cargo test            # unit + integration tests
cargo clippy --all-targets
cargo fmt --check
```

## Roadmap

- [x] GraphQL operation classifier — `read`/`write`, batches, aliases, fragments, fail-closed parsing
- [x] Configuration — TOML + `env:` secret resolution
- [x] Authorization — scope matching + policy overrides
- [x] Authentication — static bearer (constant-time), JWT (HS256, JWKS-ready), mTLS mapping
- [x] Audit logging — structured JSON line, hashed variables, pluggable sink
- [x] Pass-through proxy — `reqwest`, route-aware, hop-by-hop + `Authorization` stripped
- [x] `axum` service + graceful shutdown; integration-tested against a mock upstream
- [ ] TLS termination + mTLS client-certificate extraction
- [ ] Rate limiting (`tower_governor`)
- [ ] Prometheus metrics endpoint (`:7300`)
- [ ] `cargo-fuzz` target on the classifier

## Upstream / contribution path

1. Propose an optional `authorizationHeader` field in `indexer-tools-v3`'s
   endpoint config — the smallest change, immediate relief for the most-used tool.
2. Propose native bearer/JWT auth in `indexer-agent`'s management API as the
   durable fix; this proxy then degrades to a thin scoping/audit shim.
3. Offer the audit-log schema as a reusable convention for indexer operations.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
