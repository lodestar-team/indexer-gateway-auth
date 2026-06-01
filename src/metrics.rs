//! Prometheus metrics.
//!
//! A global recorder is installed at startup and the rendered exposition is
//! served on the dedicated metrics address (`:7300` by default). Recording
//! helpers wrap the `metrics` facade so call sites stay terse and the metric
//! names live in one place.
//!
//! Exposed series (per TOOL-RFC-001 §"Observability"):
//!   * `requests_total{scope,principal,status}`
//!   * `auth_failures_total`, `authz_denied_total`, `parse_errors_total`,
//!     `rate_limited_total`
//!   * `proxy_latency_seconds{scope}`
//!
//! Note: `principal` is a label of bounded cardinality for static-token
//! deployments, but JWT subjects can be unbounded — operators running JWT at
//! scale may wish to drop the label upstream of Prometheus.

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Install the global Prometheus recorder, returning a render handle.
pub fn install_recorder() -> anyhow::Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("installing Prometheus recorder: {e}"))
}

/// Serve `GET /metrics` on `addr`, rendering the recorder's current state.
pub async fn serve(addr: SocketAddr, handle: PrometheusHandle) -> anyhow::Result<()> {
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let handle = handle.clone();
            async move { handle.render() }
        }),
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(metrics = %addr, "serving Prometheus metrics on /metrics");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Record a proxied request and its latency.
pub fn record_request(scope: &str, principal: &str, status: u16, latency_seconds: f64) {
    metrics::counter!(
        "requests_total",
        "scope" => scope.to_string(),
        "principal" => principal.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);
    metrics::histogram!("proxy_latency_seconds", "scope" => scope.to_string())
        .record(latency_seconds);
}

pub fn inc_auth_failure() {
    metrics::counter!("auth_failures_total").increment(1);
}

pub fn inc_authz_denied() {
    metrics::counter!("authz_denied_total").increment(1);
}

pub fn inc_parse_error() {
    metrics::counter!("parse_errors_total").increment(1);
}

pub fn inc_rate_limited() {
    metrics::counter!("rate_limited_total").increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_output_contains_recorded_series() {
        // A local recorder keeps the test self-contained (no global install).
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            record_request("write", "operator", 200, 0.012);
            inc_auth_failure();
            inc_authz_denied();
            inc_parse_error();
            inc_rate_limited();
        });
        let out = handle.render();
        assert!(out.contains("requests_total"));
        assert!(out.contains("proxy_latency_seconds"));
        assert!(out.contains("auth_failures_total"));
        assert!(out.contains("authz_denied_total"));
        assert!(out.contains("parse_errors_total"));
        assert!(out.contains("rate_limited_total"));
        // labels present
        assert!(out.contains("operator"));
        assert!(out.contains("scope=\"write\""));
    }
}
