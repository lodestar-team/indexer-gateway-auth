//! HTTP service: the authn → classify → authz → audit → proxy pipeline.
//!
//! A single fallback handler runs the whole pipeline so the GraphQL body is read
//! exactly once and reused for both classification and forwarding. Errors short-
//! circuit with the appropriate status and an audit record; success forwards to
//! the routed upstream and relays the response verbatim.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::response::Response;
use axum::Router;
use http::{header, HeaderMap, Method, StatusCode};

use crate::audit::{hash_variables, now_rfc3339, AuditRecord, AuditSink, Outcome};
use crate::auth::{Authenticator, Credentials};
use crate::authz::authorize;
use crate::classify::{classify, Classification, OperationInfo, Scope};
use crate::config::{Config, Policy};
use crate::principal::Principal;
use crate::proxy::{filter_response_headers, route, Proxy, ProxyError, UpstreamTarget};

/// Shared, cheaply-cloneable application state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    authenticator: Authenticator,
    policy: Policy,
    proxy: Proxy,
    audit: AuditSink,
    allow_anonymous_read: bool,
    fail_closed_on_parse_error: bool,
    /// Audit reads as well as writes (writes are always audited).
    audit_reads: bool,
    /// Include raw variables in audit records (off by default; may leak secrets).
    log_variables: bool,
    /// Maximum request body size accepted, in bytes.
    body_limit: usize,
}

/// Tunables that don't (yet) live in the config file.
#[derive(Debug, Clone, Copy)]
pub struct AppOptions {
    /// Audit reads as well as writes (writes are always audited).
    pub audit_reads: bool,
    /// Include raw variables in audit records (off by default; may leak secrets).
    pub log_variables: bool,
    /// Maximum request body size accepted, in bytes.
    pub body_limit: usize,
}

impl Default for AppOptions {
    fn default() -> Self {
        AppOptions {
            audit_reads: false,
            log_variables: false,
            body_limit: 1024 * 1024,
        }
    }
}

impl AppState {
    pub fn new(
        config: &Config,
        authenticator: Authenticator,
        proxy: Proxy,
        audit: AuditSink,
        options: AppOptions,
    ) -> Self {
        AppState {
            inner: Arc::new(Inner {
                authenticator,
                policy: config.policy.clone(),
                proxy,
                audit,
                allow_anonymous_read: config.auth.allow_anonymous_read,
                fail_closed_on_parse_error: config.policy.fail_closed_on_parse_error,
                audit_reads: options.audit_reads,
                log_variables: options.log_variables,
                body_limit: options.body_limit,
            }),
        }
    }
}

/// Build the axum router for the proxy. Bind with
/// `.into_make_service_with_connect_info::<SocketAddr>()` so the source IP is
/// available for audit.
pub fn build_router(state: AppState) -> Router {
    Router::new().fallback(handle).with_state(state)
}

async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> Response {
    let state = state.inner;
    let (parts, body) = request.into_parts();
    let method = parts.method.clone();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());
    let headers = parts.headers;
    let source_ip = peer.ip().to_string();

    // --- 1. Authentication ------------------------------------------------
    let bearer = extract_bearer(&headers);
    let creds = Credentials {
        bearer,
        client_cert: None, // populated by the TLS layer when mTLS is enabled
    };
    let principal = match state
        .authenticator
        .authenticate(&creds, state.allow_anonymous_read)
    {
        Ok(p) => p,
        Err(e) => {
            state.audit.emit(&AuditRecord {
                timestamp: now_rfc3339(),
                principal: "-".to_string(),
                source_ip: Some(source_ip),
                scope: None,
                operation_name: None,
                operation_kinds: vec![],
                top_level_fields: vec![],
                variables_hash: None,
                variables: None,
                outcome: Outcome::AuthFailed {
                    reason: e.to_string(),
                },
                upstream_status: None,
                latency_ms: None,
            });
            return error_response(StatusCode::UNAUTHORIZED, "unauthorized", true);
        }
    };

    // --- 2. Read body (once) ---------------------------------------------
    let body_bytes = match axum::body::to_bytes(body, state.body_limit).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
                false,
            )
        }
    };

    // --- 3. Classification ------------------------------------------------
    let (target, _) = route(&path_and_query);
    let classification = match classify_request(
        &method,
        target,
        &body_bytes,
        state.fail_closed_on_parse_error,
    ) {
        Ok(c) => c,
        Err(reason) => {
            audit_pre_upstream(
                &state,
                &principal,
                &source_ip,
                None,
                Outcome::Rejected {
                    reason: reason.clone(),
                },
            );
            return error_response(StatusCode::BAD_REQUEST, &reason, false);
        }
    };

    // --- 4. Authorization -------------------------------------------------
    if let Err(denied) = authorize(&principal, &classification, &state.policy) {
        audit_pre_upstream(
            &state,
            &principal,
            &source_ip,
            Some(&classification),
            Outcome::Denied {
                reason: denied.to_string(),
            },
        );
        return error_response(StatusCode::FORBIDDEN, &denied.to_string(), false);
    }

    // --- 5. Proxy & audit -------------------------------------------------
    let variables = extract_variables(&body_bytes);
    let variables_hash = variables.as_ref().map(hash_variables);
    let started = Instant::now();
    let result = state
        .proxy
        .forward(method, &path_and_query, &headers, body_bytes.clone())
        .await;
    let latency_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(upstream) => {
            let should_audit = classification.scope == Scope::Write || state.audit_reads;
            if should_audit {
                state.audit.emit(&AuditRecord {
                    timestamp: now_rfc3339(),
                    principal: principal.name.clone(),
                    source_ip: Some(source_ip),
                    scope: Some(classification.scope),
                    operation_name: first_op_name(&classification),
                    operation_kinds: classification.operations.iter().map(|o| o.kind).collect(),
                    top_level_fields: top_fields(&classification),
                    variables_hash,
                    variables: if state.log_variables { variables } else { None },
                    outcome: Outcome::Allowed,
                    upstream_status: Some(upstream.status.as_u16()),
                    latency_ms: Some(latency_ms),
                });
            }
            relay_response(upstream)
        }
        Err(e) => {
            let status = match &e {
                ProxyError::NoUpstream(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_GATEWAY,
            };
            state.audit.emit(&AuditRecord {
                timestamp: now_rfc3339(),
                principal: principal.name.clone(),
                source_ip: Some(source_ip),
                scope: Some(classification.scope),
                operation_name: first_op_name(&classification),
                operation_kinds: classification.operations.iter().map(|o| o.kind).collect(),
                top_level_fields: top_fields(&classification),
                variables_hash,
                variables: None,
                outcome: Outcome::Allowed, // authorized; failure was upstream
                upstream_status: None,
                latency_ms: Some(latency_ms),
            });
            tracing::warn!(error = %e, "upstream request failed");
            error_response(status, "upstream unavailable", false)
        }
    }
}

/// Decide the request's classification, accounting for non-GraphQL routes.
///
/// * `GET` → read (GraphQL-over-GET is query-only by spec).
/// * graph-node admin (JSON-RPC) → write (it mutates deployments; no GraphQL).
/// * otherwise → structural GraphQL classification, honouring fail-closed policy
///   on parse errors.
fn classify_request(
    method: &Method,
    target: UpstreamTarget,
    body: &[u8],
    fail_closed: bool,
) -> Result<Classification, String> {
    if method == Method::GET {
        return Ok(read_only());
    }
    if target == UpstreamTarget::GraphNodeAdmin {
        return Ok(write_only());
    }
    match classify(body) {
        Ok(c) => Ok(c),
        Err(e) => {
            if fail_closed {
                Err(format!("could not classify request: {e}"))
            } else {
                // Fail open, but only ever to read-only.
                Ok(read_only())
            }
        }
    }
}

fn read_only() -> Classification {
    Classification {
        operations: vec![],
        scope: Scope::Read,
    }
}

fn write_only() -> Classification {
    Classification {
        operations: vec![],
        scope: Scope::Write,
    }
}

fn first_op_name(c: &Classification) -> Option<String> {
    c.operations.iter().find_map(|o| o.name.clone())
}

fn top_fields(c: &Classification) -> Vec<String> {
    c.operations
        .iter()
        .flat_map(|o: &OperationInfo| o.top_level_fields.clone())
        .collect()
}

/// Audit a request that never reached the upstream (denied/rejected). Such
/// outcomes are always recorded regardless of the read/write audit toggle.
fn audit_pre_upstream(
    state: &Inner,
    principal: &Principal,
    source_ip: &str,
    classification: Option<&Classification>,
    outcome: Outcome,
) {
    state.audit.emit(&AuditRecord {
        timestamp: now_rfc3339(),
        principal: principal.name.clone(),
        source_ip: Some(source_ip.to_string()),
        scope: classification.map(|c| c.scope),
        operation_name: classification.and_then(first_op_name),
        operation_kinds: classification
            .map(|c| c.operations.iter().map(|o| o.kind).collect())
            .unwrap_or_default(),
        top_level_fields: classification.map(top_fields).unwrap_or_default(),
        variables_hash: None,
        variables: None,
        outcome,
        upstream_status: None,
        latency_ms: None,
    });
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Pull request variables for audit fingerprinting. Handles single requests
/// (`{"variables": {...}}`) and batches (array of such objects).
fn extract_variables(body: &[u8]) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match value {
        serde_json::Value::Object(mut map) => map.remove("variables"),
        serde_json::Value::Array(items) => {
            let vars: Vec<serde_json::Value> = items
                .into_iter()
                .filter_map(|mut item| item.as_object_mut().and_then(|m| m.remove("variables")))
                .collect();
            if vars.is_empty() {
                None
            } else {
                Some(serde_json::Value::Array(vars))
            }
        }
        _ => None,
    }
}

/// Build a small JSON error response. For `401`, advertise the scheme.
fn error_response(status: StatusCode, message: &str, www_authenticate: bool) -> Response {
    let body = serde_json::json!({ "error": message }).to_string();
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json");
    if www_authenticate {
        builder = builder.header(header::WWW_AUTHENTICATE, "Bearer");
    }
    builder.body(Body::from(body)).expect("valid response")
}

/// Relay a buffered upstream response back to the client, stripping hop-by-hop
/// and length headers so hyper recomputes them for the buffered body.
fn relay_response(upstream: crate::proxy::ProxyResponse) -> Response {
    let mut builder = Response::builder().status(upstream.status);
    let headers = filter_response_headers(&upstream.headers);
    if let Some(h) = builder.headers_mut() {
        *h = headers;
    }
    builder
        .body(Body::from(upstream.body))
        .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "bad upstream response", false))
}
