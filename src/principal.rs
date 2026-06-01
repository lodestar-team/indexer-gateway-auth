//! The authenticated identity attached to a request.
//!
//! A [`Principal`] is produced by an authentication backend (static token, JWT,
//! or mTLS) and carries the set of scopes that authorization then checks against
//! the classified operation. It deliberately holds no secret material — only a
//! display name (for audit) and granted scopes.

use std::collections::HashSet;

/// An authenticated caller and the scopes it has been granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Human-readable label, surfaced in audit records (e.g. `operator`,
    /// `ci-readonly`, a JWT subject, or a certificate CN).
    pub name: String,
    /// Granted scopes, e.g. `read`, `write`, `actions:execute`.
    pub scopes: HashSet<String>,
}

impl Principal {
    pub fn new(name: impl Into<String>, scopes: impl IntoIterator<Item = String>) -> Self {
        Principal {
            name: name.into(),
            scopes: scopes.into_iter().collect(),
        }
    }

    /// The read-only anonymous principal, used only when
    /// `auth.allow_anonymous_read` is explicitly enabled.
    pub fn anonymous() -> Self {
        Principal::new("anonymous", ["read".to_string()])
    }

    /// Whether this principal satisfies a single required scope.
    ///
    /// `write` implies `read` (a writer may read), but fine-grained scopes such
    /// as `actions:execute` are matched exactly — holding `write` does not grant
    /// them unless policy says so.
    pub fn satisfies(&self, required: &str) -> bool {
        if self.scopes.contains(required) {
            return true;
        }
        required == "read" && self.scopes.contains("write")
    }
}
