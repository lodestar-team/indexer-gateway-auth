//! End-to-end tests: a real gateway in front of a mock upstream, driven over
//! HTTP. These assert the whole authn → classify → authz → audit → proxy
//! pipeline, transparent pass-through, and that the gateway's bearer token never
//! reaches the upstream.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::Request;
use axum::Router;
use http::{header, StatusCode};
use iga::audit::AuditSink;
use iga::auth::Authenticator;
use iga::config::Config;
use iga::proxy::Proxy;
use iga::server::{build_router, AppOptions, AppState};
use tokio::net::TcpListener;

/// What the mock upstream saw for a forwarded request.
#[derive(Debug, Clone)]
struct Recorded {
    path: String,
    had_authorization: bool,
    body: String,
}

/// Spawn a mock upstream that records each request and returns a fixed 200 JSON.
async fn spawn_upstream() -> (SocketAddr, Arc<Mutex<Vec<Recorded>>>) {
    let records = Arc::new(Mutex::new(Vec::new()));
    let sink = records.clone();
    let app = Router::new().fallback(move |req: Request| {
        let sink = sink.clone();
        async move {
            let path = req.uri().path().to_string();
            let had_authorization = req.headers().contains_key(header::AUTHORIZATION);
            let bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            sink.lock().unwrap().push(Recorded {
                path,
                had_authorization,
                body: String::from_utf8_lossy(&bytes).to_string(),
            });
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"data":{"ok":true}}"#,
            )
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, records)
}

/// Spawn the gateway pointed at `upstream`, returning its address.
async fn spawn_gateway(upstream: SocketAddr, audit: AuditSink) -> SocketAddr {
    spawn_gateway_with(upstream, audit, "").await
}

/// Spawn the gateway with extra TOML appended (e.g. a `[ratelimit]` section).
async fn spawn_gateway_with(upstream: SocketAddr, audit: AuditSink, extra: &str) -> SocketAddr {
    let toml = format!(
        r#"
listen = "127.0.0.1:0"
metrics = "127.0.0.1:0"
[upstream]
agent_management = "http://{upstream}"
[auth]
mode = "bearer"
[[auth.tokens]]
name = "ci-readonly"
token = "read-token"
scopes = ["read"]
[[auth.tokens]]
name = "operator"
token = "write-token"
scopes = ["read", "write"]
[policy]
fail_closed_on_parse_error = true
{extra}
"#
    );
    let config = Config::from_toml_str(&toml).unwrap();
    let authenticator = Authenticator::from_config(&config.auth).unwrap();
    let proxy = Proxy::new(reqwest::Client::new(), &config.upstream);
    let state = AppState::new(&config, authenticator, proxy, audit, AppOptions::default());
    let app = build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

async fn post_graphql(gateway: SocketAddr, token: Option<&str>, body: &str) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(format!("http://{gateway}/"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string());
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req.send().await.unwrap()
}

#[tokio::test]
async fn missing_token_is_unauthorized_and_upstream_untouched() {
    let (upstream, records) = spawn_upstream().await;
    let gateway = spawn_gateway(upstream, AuditSink::Null).await;

    let resp = post_graphql(gateway, None, r#"{"query":"{ indexingRules { id } }"}"#).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );
    assert!(
        records.lock().unwrap().is_empty(),
        "upstream must not be hit"
    );
}

#[tokio::test]
async fn invalid_token_is_unauthorized() {
    let (upstream, records) = spawn_upstream().await;
    let gateway = spawn_gateway(upstream, AuditSink::Null).await;

    let resp = post_graphql(
        gateway,
        Some("not-a-real-token"),
        r#"{"query":"{ indexingRules { id } }"}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(records.lock().unwrap().is_empty());
}

#[tokio::test]
async fn read_token_may_query() {
    let (upstream, records) = spawn_upstream().await;
    let gateway = spawn_gateway(upstream, AuditSink::Null).await;

    let resp = post_graphql(
        gateway,
        Some("read-token"),
        r#"{"query":"{ indexingRules { id } }"}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), r#"{"data":{"ok":true}}"#);
    assert_eq!(records.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn read_token_may_not_mutate() {
    let (upstream, records) = spawn_upstream().await;
    let gateway = spawn_gateway(upstream, AuditSink::Null).await;

    let resp = post_graphql(
        gateway,
        Some("read-token"),
        r#"{"query":"mutation { setIndexingRule(rule: {}) { id } }"}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        records.lock().unwrap().is_empty(),
        "denied mutation must not reach upstream"
    );
}

#[tokio::test]
async fn write_token_may_mutate_and_authorization_is_stripped() {
    let (upstream, records) = spawn_upstream().await;
    let gateway = spawn_gateway(upstream, AuditSink::Null).await;

    let resp = post_graphql(
        gateway,
        Some("write-token"),
        r#"{"query":"mutation { setIndexingRule(rule: {}) { id } }"}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let recs = records.lock().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].path, "/");
    assert!(
        !recs[0].had_authorization,
        "gateway token must not be forwarded upstream"
    );
    assert!(recs[0].body.contains("setIndexingRule"));
}

#[tokio::test]
async fn malformed_body_fails_closed() {
    let (upstream, records) = spawn_upstream().await;
    let gateway = spawn_gateway(upstream, AuditSink::Null).await;

    let resp = post_graphql(gateway, Some("write-token"), "this is not graphql json").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(records.lock().unwrap().is_empty());
}

#[tokio::test]
async fn health_endpoints_need_no_auth_and_skip_upstream() {
    let (upstream, records) = spawn_upstream().await;
    let gateway = spawn_gateway(upstream, AuditSink::Null).await;

    for path in ["/healthz", "/readyz"] {
        let resp = reqwest::Client::new()
            .get(format!("http://{gateway}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert_eq!(resp.text().await.unwrap(), "ok");
    }
    assert!(
        records.lock().unwrap().is_empty(),
        "probes must not be proxied upstream"
    );
}

#[tokio::test]
async fn write_rate_limit_returns_429() {
    let (upstream, records) = spawn_upstream().await;
    // One write per minute; reads unrestricted.
    let gateway = spawn_gateway_with(
        upstream,
        AuditSink::Null,
        "[ratelimit]\nwrite_per_minute = 1\nread_per_minute = 0",
    )
    .await;

    let mutation = r#"{"query":"mutation { setIndexingRule(rule: {}) { id } }"}"#;
    let first = post_graphql(gateway, Some("write-token"), mutation).await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = post_graphql(gateway, Some("write-token"), mutation).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    // Reads are on a separate (unlimited) budget and still succeed.
    let read = post_graphql(
        gateway,
        Some("read-token"),
        r#"{"query":"{ indexingRules { id } }"}"#,
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);

    // Only the two allowed requests reached the upstream.
    assert_eq!(records.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn write_is_audited_with_outcome_and_scope() {
    let (upstream, _records) = spawn_upstream().await;
    let dir = std::env::temp_dir();
    let path = dir.join(format!("iga-audit-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let sink = AuditSink::file(&path).unwrap();
    let gateway = spawn_gateway(upstream, sink).await;

    let resp = post_graphql(
        gateway,
        Some("write-token"),
        r#"{"query":"mutation Op { setIndexingRule(rule: {}) { id } }","variables":{"x":1}}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Give the spawned handler a moment to flush its audit line.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let contents = std::fs::read_to_string(&path).unwrap();
    let line = contents.lines().next().expect("one audit line");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["principal"], "operator");
    assert_eq!(v["scope"], "write");
    assert_eq!(v["outcome"], "allowed");
    assert_eq!(v["operation_name"], "Op");
    assert_eq!(v["upstream_status"], 200);
    assert!(v["variables_hash"].is_string());
    assert!(v.get("variables").is_none(), "raw variables off by default");
    let _ = std::fs::remove_file(&path);
}
