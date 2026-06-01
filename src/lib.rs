//! `indexer-gateway-auth` (`iga`) — an authenticating reverse proxy that places
//! an application-layer authn/authz boundary in front of the Graph Protocol
//! Indexer Management API and the `graph-node` admin/status endpoints.
//!
//! The library is organised as small, independently testable modules; the binary
//! (`src/main.rs`) wires them into an `axum` service. See `TOOL-RFC-001`.

pub mod audit;
pub mod auth;
pub mod authz;
pub mod classify;
pub mod config;
pub mod metrics;
pub mod principal;
pub mod proxy;
pub mod ratelimit;
pub mod server;
