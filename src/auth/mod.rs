//! Authentication backends: static bearer tokens, JWT, and mTLS.
//!
//! Each backend turns presented credentials into a [`Principal`] or an
//! [`AuthError`]. The active backend is selected by `auth.mode`. A missing
//! credential maps to an anonymous read-only principal *only* when
//! `auth.allow_anonymous_read` is enabled; an *invalid* credential is always a
//! `401` — we never silently downgrade a bad token to anonymous.

mod jwt;
mod mtls;
mod token;

pub use jwt::JwtBackend;
pub use mtls::{ClientCert, MtlsBackend};
pub use token::StaticTokenBackend;

use crate::config::Auth;
use crate::principal::Principal;

/// Why authentication failed. The HTTP layer renders all of these as `401`;
/// the variants exist for audit/metrics granularity, never for the client body
/// (which must not reveal whether a token merely doesn't exist).
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no credentials presented")]
    MissingCredentials,
    #[error("invalid or unknown token")]
    InvalidToken,
    #[error("client certificate not recognised")]
    InvalidClientCert,
    #[error("JWT verification failed: {0}")]
    Jwt(String),
    #[error("backend not configured: {0}")]
    Misconfigured(String),
}

/// Credentials extracted from a request by the HTTP layer.
#[derive(Debug, Default)]
pub struct Credentials<'a> {
    /// The `Authorization: Bearer <token>` value, if present.
    pub bearer: Option<&'a str>,
    /// The verified client certificate identity, if mTLS terminated one.
    pub client_cert: Option<ClientCert>,
}

/// The configured authentication mechanism.
pub enum Authenticator {
    Bearer(StaticTokenBackend),
    // Boxed: a JWT backend (validation + decoding keys) is far larger than the
    // other variants, which would otherwise bloat every `Authenticator`.
    Jwt(Box<JwtBackend>),
    Mtls(MtlsBackend),
}

impl Authenticator {
    /// Build the authenticator from the `[auth]` config section.
    ///
    /// Note: a JWT backend configured *only* with a `jwks_url` cannot be built
    /// here because fetching the key set is asynchronous; construct it via
    /// [`JwtBackend`] during async startup and wrap it yourself. HS256 (shared
    /// secret) backends build synchronously.
    pub fn from_config(auth: &Auth) -> Result<Self, AuthError> {
        use crate::config::AuthMode;
        match auth.mode {
            AuthMode::Bearer => Ok(Authenticator::Bearer(StaticTokenBackend::new(&auth.tokens))),
            AuthMode::Mtls => Ok(Authenticator::Mtls(MtlsBackend::new(&auth.mtls))),
            AuthMode::Jwt => {
                let jwt = auth.jwt.as_ref().ok_or_else(|| {
                    AuthError::Misconfigured("mode = \"jwt\" but [auth.jwt] is absent".into())
                })?;
                let backend = JwtBackend::from_config(jwt)?;
                Ok(Authenticator::Jwt(Box::new(backend)))
            }
        }
    }

    /// Resolve credentials to a principal, honouring `allow_anonymous_read`.
    pub fn authenticate(
        &self,
        creds: &Credentials<'_>,
        allow_anonymous_read: bool,
    ) -> Result<Principal, AuthError> {
        let result = match self {
            Authenticator::Bearer(b) => bearer(creds).and_then(|t| b.verify(t)),
            Authenticator::Jwt(j) => bearer(creds).and_then(|t| j.verify(t)),
            Authenticator::Mtls(m) => creds
                .client_cert
                .as_ref()
                .ok_or(AuthError::MissingCredentials)
                .and_then(|c| m.verify(c)),
        };
        // Only an *absent* credential may fall through to anonymous; an invalid
        // one stays a denial.
        match result {
            Err(AuthError::MissingCredentials) if allow_anonymous_read => {
                Ok(Principal::anonymous())
            }
            other => other,
        }
    }
}

fn bearer<'a>(creds: &Credentials<'a>) -> Result<&'a str, AuthError> {
    creds.bearer.ok_or(AuthError::MissingCredentials)
}
