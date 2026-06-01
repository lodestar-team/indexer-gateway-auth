//! Static bearer-token backend.
//!
//! Presented tokens are compared in constant time against the configured set, so
//! the proxy is not a timing oracle for guessing a valid token byte-by-byte.

use subtle::ConstantTimeEq;

use super::AuthError;
use crate::config::TokenEntry;
use crate::principal::Principal;

struct TokenRecord {
    name: String,
    token: String,
    scopes: Vec<String>,
}

pub struct StaticTokenBackend {
    tokens: Vec<TokenRecord>,
}

impl StaticTokenBackend {
    pub fn new(entries: &[TokenEntry]) -> Self {
        StaticTokenBackend {
            tokens: entries
                .iter()
                .map(|e| TokenRecord {
                    name: e.name.clone(),
                    token: e.token.clone(),
                    scopes: e.scopes.clone(),
                })
                .collect(),
        }
    }

    /// Match a presented token against the configured set in constant time.
    ///
    /// The scan deliberately does **not** short-circuit on a match: every entry
    /// is compared so per-request timing does not reveal which token matched (or
    /// how many precede it). `subtle`'s slice comparison still returns early on a
    /// length mismatch, which only leaks token length — not its contents.
    pub fn verify(&self, presented: &str) -> Result<Principal, AuthError> {
        let mut matched: Option<&TokenRecord> = None;
        for record in &self.tokens {
            let is_eq: bool = record.token.as_bytes().ct_eq(presented.as_bytes()).into();
            if is_eq {
                matched = Some(record);
            }
        }
        matched
            .map(|r| Principal::new(r.name.clone(), r.scopes.clone()))
            .ok_or(AuthError::InvalidToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, token: &str, scopes: &[&str]) -> TokenEntry {
        TokenEntry {
            name: name.to_string(),
            token: token.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn known_token_maps_to_principal() {
        let backend = StaticTokenBackend::new(&[
            entry("ci", "tok-ci", &["read"]),
            entry("op", "tok-op", &["read", "write"]),
        ]);
        let p = backend.verify("tok-op").unwrap();
        assert_eq!(p.name, "op");
        assert!(p.scopes.contains("write"));
    }

    #[test]
    fn unknown_token_is_rejected() {
        let backend = StaticTokenBackend::new(&[entry("ci", "tok-ci", &["read"])]);
        assert!(matches!(
            backend.verify("nope"),
            Err(AuthError::InvalidToken)
        ));
    }

    #[test]
    fn empty_backend_rejects_everything() {
        let backend = StaticTokenBackend::new(&[]);
        assert!(backend.verify("anything").is_err());
    }
}
