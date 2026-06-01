//! Pass-through proxy to the upstream.
//!
//! Once a request is authenticated and authorized, it is forwarded to the
//! appropriate upstream and the response streamed back. The proxy is otherwise
//! transparent: it does not rewrite bodies or inspect responses.
//!
//! Two deviations from "verbatim", both deliberate:
//!   * hop-by-hop headers (RFC 7230 §6.1) are stripped, as any correct proxy must;
//!   * the `Authorization` header is stripped — the gateway has already consumed
//!     it, and the (unauthenticated) upstream has no use for it. Forwarding would
//!     only risk leaking the bearer token into upstream logs.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, Method, StatusCode};

use crate::config::Upstream;

/// Which upstream a request is routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTarget {
    AgentManagement,
    GraphNodeAdmin,
    GraphNodeStatus,
}

/// Path prefixes that route to the `graph-node` endpoints. Everything else goes
/// to the management API. The prefix is stripped before forwarding.
const ADMIN_PREFIX: &str = "/_admin";
const STATUS_PREFIX: &str = "/_status";

/// Resolve a request path to an upstream target and the path to forward.
///
/// `/_admin/...` → graph-node admin, `/_status/...` → graph-node status (prefix
/// stripped); anything else → the management API with the path unchanged.
pub fn route(path: &str) -> (UpstreamTarget, String) {
    if let Some(rest) = strip_prefix_segment(path, ADMIN_PREFIX) {
        (UpstreamTarget::GraphNodeAdmin, rest)
    } else if let Some(rest) = strip_prefix_segment(path, STATUS_PREFIX) {
        (UpstreamTarget::GraphNodeStatus, rest)
    } else {
        (UpstreamTarget::AgentManagement, path.to_string())
    }
}

/// Strip `prefix` only when it is a whole path segment (so `/_admins` does not
/// match `/_admin`). Returns the remainder, defaulting to `/`.
fn strip_prefix_segment(path: &str, prefix: &str) -> Option<String> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        Some("/".to_string())
    } else if rest.starts_with('/') {
        Some(rest.to_string())
    } else {
        None
    }
}

/// Whether a header is hop-by-hop and must not be forwarded.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Build the header set to forward upstream: the incoming headers minus
/// hop-by-hop headers, `host` (reqwest sets it for the upstream), and
/// `authorization` (consumed by the gateway).
pub fn filter_forward_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if is_hop_by_hop(name) || name == http::header::HOST || name == http::header::AUTHORIZATION
        {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Build the header set to relay a buffered upstream response back to the
/// client: drop hop-by-hop headers plus `content-length`/`transfer-encoding`,
/// which the server recomputes for the buffered body.
pub fn filter_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if is_hop_by_hop(name) || name == http::header::CONTENT_LENGTH {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// The upstream's response, buffered for relay back to the client.
pub struct ProxyResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("upstream {0:?} is not configured")]
    NoUpstream(UpstreamTarget),
    #[error("invalid upstream URL: {0}")]
    BadUrl(String),
    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
}

/// Forwards authenticated requests to the configured upstreams.
pub struct Proxy {
    client: reqwest::Client,
    agent_management: String,
    graph_node_admin: Option<String>,
    graph_node_status: Option<String>,
}

impl Proxy {
    pub fn new(client: reqwest::Client, upstream: &Upstream) -> Self {
        Proxy {
            client,
            // Trim a trailing slash so path joining is unambiguous.
            agent_management: trim_trailing_slash(&upstream.agent_management),
            graph_node_admin: upstream
                .graph_node_admin
                .as_deref()
                .map(trim_trailing_slash),
            graph_node_status: upstream
                .graph_node_status
                .as_deref()
                .map(trim_trailing_slash),
        }
    }

    fn base_for(&self, target: UpstreamTarget) -> Result<&str, ProxyError> {
        match target {
            UpstreamTarget::AgentManagement => Ok(&self.agent_management),
            UpstreamTarget::GraphNodeAdmin => self
                .graph_node_admin
                .as_deref()
                .ok_or(ProxyError::NoUpstream(target)),
            UpstreamTarget::GraphNodeStatus => self
                .graph_node_status
                .as_deref()
                .ok_or(ProxyError::NoUpstream(target)),
        }
    }

    /// Forward a request to its routed upstream and buffer the response.
    pub async fn forward(
        &self,
        method: Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<ProxyResponse, ProxyError> {
        let (target, forward_path) = route(path_and_query);
        let base = self.base_for(target)?;
        let url = format!("{base}{forward_path}");

        let response = self
            .client
            .request(method, &url)
            .headers(filter_forward_headers(headers))
            .body(body)
            .send()
            .await?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await?;
        Ok(ProxyResponse {
            status,
            headers,
            body,
        })
    }
}

fn trim_trailing_slash(s: &str) -> String {
    s.strip_suffix('/').unwrap_or(s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprefixed_path_routes_to_management() {
        assert_eq!(
            route("/"),
            (UpstreamTarget::AgentManagement, "/".to_string())
        );
        assert_eq!(
            route("/graphql"),
            (UpstreamTarget::AgentManagement, "/graphql".to_string())
        );
    }

    #[test]
    fn admin_prefix_routes_and_strips() {
        assert_eq!(
            route("/_admin/something"),
            (UpstreamTarget::GraphNodeAdmin, "/something".to_string())
        );
        assert_eq!(
            route("/_admin"),
            (UpstreamTarget::GraphNodeAdmin, "/".to_string())
        );
    }

    #[test]
    fn status_prefix_routes_and_strips() {
        assert_eq!(
            route("/_status/graphql"),
            (UpstreamTarget::GraphNodeStatus, "/graphql".to_string())
        );
    }

    #[test]
    fn similar_prefix_does_not_falsely_match() {
        // `/_admins` must not be treated as the `/_admin` route.
        assert_eq!(
            route("/_admins/x"),
            (UpstreamTarget::AgentManagement, "/_admins/x".to_string())
        );
    }

    #[test]
    fn hop_by_hop_host_and_authorization_are_stripped() {
        let mut h = HeaderMap::new();
        h.insert(http::header::HOST, "proxy.local".parse().unwrap());
        h.insert(
            http::header::AUTHORIZATION,
            "Bearer secret".parse().unwrap(),
        );
        h.insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        h.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        h.insert("x-custom", "keepme".parse().unwrap());

        let out = filter_forward_headers(&h);
        assert!(!out.contains_key(http::header::HOST));
        assert!(!out.contains_key(http::header::AUTHORIZATION));
        assert!(!out.contains_key(http::header::CONNECTION));
        assert_eq!(
            out.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(out.get("x-custom").unwrap(), "keepme");
    }

    #[test]
    fn base_for_unconfigured_upstream_errors() {
        let upstream = Upstream {
            agent_management: "http://127.0.0.1:18000".to_string(),
            graph_node_admin: None,
            graph_node_status: None,
        };
        let proxy = Proxy::new(reqwest::Client::new(), &upstream);
        assert_eq!(
            proxy.base_for(UpstreamTarget::AgentManagement).unwrap(),
            "http://127.0.0.1:18000"
        );
        assert!(matches!(
            proxy.base_for(UpstreamTarget::GraphNodeAdmin),
            Err(ProxyError::NoUpstream(UpstreamTarget::GraphNodeAdmin))
        ));
    }
}
