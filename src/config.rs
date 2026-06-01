//! Configuration: TOML on disk, secrets resolved from the environment.
//!
//! The shape mirrors TOOL-RFC-001 §"Configuration". Secret material (static
//! tokens, JWT shared keys) MUST NOT be inlined in committed config; instead a
//! value of the form `env:NAME` is resolved from the process environment at
//! load time. Inlined literals are tolerated for local development but are a
//! footgun in production — `Config::load` logs nothing about them; that is the
//! operator's responsibility.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level configuration document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the proxy listens on for client traffic.
    pub listen: SocketAddr,
    /// Address the Prometheus metrics endpoint binds to.
    pub metrics: SocketAddr,
    pub upstream: Upstream,
    #[serde(default)]
    pub tls: Tls,
    pub auth: Auth,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub ratelimit: RateLimit,
}

/// Upstream endpoints the proxy guards. All SHOULD bind to `localhost` or a
/// cluster-internal address so the proxy is their only reachable network path.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub agent_management: String,
    #[serde(default)]
    pub graph_node_admin: Option<String>,
    #[serde(default)]
    pub graph_node_status: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// Require and verify a client certificate (mTLS).
    #[serde(default)]
    pub require_client_cert: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Bearer,
    Jwt,
    Mtls,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub mode: AuthMode,
    /// When true, requests with no credentials are admitted with a read-only
    /// `anonymous` principal. Off by default; a deliberate foot-gun switch.
    #[serde(default)]
    pub allow_anonymous_read: bool,
    /// Static bearer-token backend entries.
    #[serde(default)]
    pub tokens: Vec<TokenEntry>,
    /// Optional JWT backend.
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
    /// Certificate-subject → principal mappings for the mTLS backend.
    #[serde(default)]
    pub mtls: Vec<MtlsMapping>,
}

/// Maps an mTLS client certificate identity (a CN or SAN value) to a principal.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsMapping {
    /// The certificate subject CN or SAN value to match.
    pub subject: String,
    /// Principal name recorded in audit for this identity.
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEntry {
    /// Human label for the principal, used in audit records.
    pub name: String,
    /// The token value, or an `env:NAME` reference resolved at load time.
    pub token: String,
    /// Scopes granted to bearers of this token (e.g. `read`, `write`,
    /// `actions:execute`).
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    pub issuer: String,
    pub audience: String,
    /// JWKS endpoint for RS256/ES256 verification (fetched at startup).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Shared secret (or `env:NAME`) for HS256 verification.
    #[serde(default)]
    pub hs256_secret: Option<String>,
    /// Claim holding the principal's scopes.
    #[serde(default = "default_scopes_claim")]
    pub scopes_claim: String,
}

fn default_scopes_claim() -> String {
    "scopes".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Reject (rather than fail-open read-only) when a body cannot be parsed.
    #[serde(default = "default_true")]
    pub fail_closed_on_parse_error: bool,
    /// Per-field / per-operation scope overrides.
    #[serde(default, rename = "override")]
    pub overrides: Vec<Override>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            fail_closed_on_parse_error: true,
            overrides: Vec::new(),
        }
    }
}

/// A single override: raise (or otherwise pin) the scopes required to invoke a
/// given top-level field or named operation. At least one of `field`/`operation`
/// should be set; both may be, in which case both must match.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    pub require_scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    #[serde(default = "default_write_per_minute")]
    pub write_per_minute: u32,
    #[serde(default = "default_read_per_minute")]
    pub read_per_minute: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            write_per_minute: default_write_per_minute(),
            read_per_minute: default_read_per_minute(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_write_per_minute() -> u32 {
    30
}
fn default_read_per_minute() -> u32 {
    600
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("config references environment variable `{0}`, which is not set")]
    MissingEnv(String),
}

impl Config {
    /// Load and validate config from `path`, resolving all `env:` secret
    /// references against the process environment.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config: Config = toml::from_str(&text)?;
        config.resolve_secrets()?;
        Ok(config)
    }

    /// Parse config from a TOML string (no file IO), resolving `env:` secrets.
    /// Primarily for tests and embedding.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let mut config: Config = toml::from_str(text)?;
        config.resolve_secrets()?;
        Ok(config)
    }

    /// Replace every `env:NAME` secret reference with its environment value.
    fn resolve_secrets(&mut self) -> Result<(), ConfigError> {
        for token in &mut self.auth.tokens {
            token.token = resolve_secret(&token.token)?;
        }
        if let Some(jwt) = &mut self.auth.jwt {
            if let Some(secret) = &jwt.hs256_secret {
                jwt.hs256_secret = Some(resolve_secret(secret)?);
            }
        }
        Ok(())
    }
}

/// Resolve a single secret value: `env:NAME` reads `NAME` from the environment;
/// anything else is returned verbatim (a literal, for local dev).
fn resolve_secret(raw: &str) -> Result<String, ConfigError> {
    match raw.strip_prefix("env:") {
        Some(var) => std::env::var(var).map_err(|_| ConfigError::MissingEnv(var.to_string())),
        None => Ok(raw.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact configuration shown in TOOL-RFC-001 §"Configuration".
    const RFC_EXAMPLE: &str = r#"
listen   = "0.0.0.0:8400"
metrics  = "0.0.0.0:7300"

[upstream]
agent_management = "http://127.0.0.1:18000"
graph_node_admin = "http://127.0.0.1:8020"
graph_node_status = "http://127.0.0.1:8030"

[tls]
enabled = true
cert = "/etc/iga/tls/cert.pem"
key = "/etc/iga/tls/key.pem"
require_client_cert = false

[auth]
mode = "bearer"
allow_anonymous_read = false

[[auth.tokens]]
name   = "ci-readonly"
token  = "env:IGA_TEST_TOKEN_CI"
scopes = ["read"]

[[auth.tokens]]
name   = "operator"
token  = "literal-operator-token"
scopes = ["read", "write"]

[policy]
fail_closed_on_parse_error = true

[[policy.override]]
field = "executeApprovedActions"
require_scopes = ["actions:execute"]

[ratelimit]
write_per_minute = 30
read_per_minute  = 600
"#;

    #[test]
    fn parses_rfc_example_and_resolves_env() {
        std::env::set_var("IGA_TEST_TOKEN_CI", "ci-secret-value");
        let cfg = Config::from_toml_str(RFC_EXAMPLE).expect("should parse");

        assert_eq!(cfg.listen, "0.0.0.0:8400".parse().unwrap());
        assert_eq!(cfg.upstream.agent_management, "http://127.0.0.1:18000");
        assert_eq!(cfg.auth.mode, AuthMode::Bearer);
        assert!(!cfg.auth.allow_anonymous_read);

        // env: reference resolved; literal passed through.
        assert_eq!(cfg.auth.tokens[0].token, "ci-secret-value");
        assert_eq!(cfg.auth.tokens[0].scopes, vec!["read"]);
        assert_eq!(cfg.auth.tokens[1].token, "literal-operator-token");

        assert_eq!(cfg.policy.overrides.len(), 1);
        assert_eq!(
            cfg.policy.overrides[0].field.as_deref(),
            Some("executeApprovedActions")
        );
        assert_eq!(cfg.ratelimit.write_per_minute, 30);
        std::env::remove_var("IGA_TEST_TOKEN_CI");
    }

    #[test]
    fn missing_env_secret_is_an_error() {
        let toml = r#"
listen = "0.0.0.0:8400"
metrics = "0.0.0.0:7300"
[upstream]
agent_management = "http://127.0.0.1:18000"
[auth]
mode = "bearer"
[[auth.tokens]]
name = "x"
token = "env:IGA_DEFINITELY_NOT_SET_12345"
scopes = ["read"]
"#;
        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, ConfigError::MissingEnv(v) if v == "IGA_DEFINITELY_NOT_SET_12345"));
    }

    #[test]
    fn defaults_apply_when_sections_omitted() {
        let toml = r#"
listen = "0.0.0.0:8400"
metrics = "0.0.0.0:7300"
[upstream]
agent_management = "http://127.0.0.1:18000"
[auth]
mode = "jwt"
[auth.jwt]
issuer = "https://auth.example.com/"
audience = "indexer-management"
jwks_url = "https://auth.example.com/.well-known/jwks.json"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        // ratelimit + policy defaults
        assert_eq!(cfg.ratelimit.write_per_minute, 30);
        assert_eq!(cfg.ratelimit.read_per_minute, 600);
        assert!(cfg.policy.fail_closed_on_parse_error);
        assert!(!cfg.tls.enabled);
        // jwt scopes_claim default
        assert_eq!(cfg.auth.jwt.as_ref().unwrap().scopes_claim, "scopes");
    }

    #[test]
    fn shipped_example_config_parses() {
        // Guard the documented example against drift from the structs.
        std::env::set_var("IGA_TOKEN_CI", "x");
        std::env::set_var("IGA_TOKEN_OPERATOR", "y");
        let text = include_str!("../config.example.toml");
        let cfg = Config::from_toml_str(text).expect("example config must parse");
        assert_eq!(cfg.auth.mode, AuthMode::Bearer);
        assert_eq!(cfg.policy.overrides.len(), 1);
        std::env::remove_var("IGA_TOKEN_CI");
        std::env::remove_var("IGA_TOKEN_OPERATOR");
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = r#"
listen = "0.0.0.0:8400"
metrics = "0.0.0.0:7300"
surprise = true
[upstream]
agent_management = "http://127.0.0.1:18000"
[auth]
mode = "bearer"
"#;
        assert!(matches!(
            Config::from_toml_str(toml),
            Err(ConfigError::Parse(_))
        ));
    }
}
