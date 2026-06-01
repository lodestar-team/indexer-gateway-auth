//! Authorization: does this principal's scopes cover the classified operation?
//!
//! The base requirement comes straight from structural classification — a
//! `read` request needs `read` (which `write` satisfies), a `write` request
//! needs `write`. Policy overrides then add *fine-grained* requirements on top:
//! a matched override contributes extra scopes the principal must also hold
//! (e.g. `executeApprovedActions` → `actions:execute`). Overrides only ever
//! tighten, never loosen, the requirement.

use std::collections::BTreeSet;

use crate::classify::{Classification, Scope};
use crate::config::{Override, Policy};
use crate::principal::Principal;

/// A denied authorization decision, carrying enough detail for a `403` body and
/// an audit record without leaking which tokens exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// The full set of scopes the request required.
    pub required: Vec<String>,
    /// The subset the principal was missing.
    pub missing: Vec<String>,
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "insufficient scope: missing [{}] (required [{}])",
            self.missing.join(", "),
            self.required.join(", ")
        )
    }
}

/// Decide whether `principal` may invoke the classified request under `policy`.
///
/// Returns `Ok(required_scopes)` on success (for audit) or `Err(Denied)` listing
/// what was required and what was missing.
pub fn authorize(
    principal: &Principal,
    classification: &Classification,
    policy: &Policy,
) -> Result<Vec<String>, Denied> {
    // A BTreeSet keeps the required list deterministic for tests and audit.
    let mut required: BTreeSet<String> = BTreeSet::new();

    // Base scope from structural classification.
    required.insert(base_scope(classification.scope).to_string());

    // Fine-grained additions from matching overrides.
    for op in &classification.operations {
        for ov in &policy.overrides {
            if override_matches(ov, op) {
                required.extend(ov.require_scopes.iter().cloned());
            }
        }
    }

    let missing: Vec<String> = required
        .iter()
        .filter(|scope| !principal.satisfies(scope))
        .cloned()
        .collect();

    let required: Vec<String> = required.into_iter().collect();
    if missing.is_empty() {
        Ok(required)
    } else {
        Err(Denied { required, missing })
    }
}

fn base_scope(scope: Scope) -> &'static str {
    match scope {
        Scope::Read => "read",
        Scope::Write => "write",
    }
}

/// An override matches an operation when every constraint it sets holds. A
/// `field` constraint requires that field to be selected at the operation root;
/// an `operation` constraint requires the operation name to match. An override
/// with neither constraint matches nothing (it would otherwise apply globally,
/// which is surprising and almost certainly a config mistake).
fn override_matches(ov: &Override, op: &crate::classify::OperationInfo) -> bool {
    if ov.field.is_none() && ov.operation.is_none() {
        return false;
    }
    let field_ok = match &ov.field {
        Some(f) => op.top_level_fields.iter().any(|sel| sel == f),
        None => true,
    };
    let op_ok = match &ov.operation {
        Some(o) => op.name.as_deref() == Some(o.as_str()),
        None => true,
    };
    field_ok && op_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{OperationInfo, OperationKind};

    fn principal(scopes: &[&str]) -> Principal {
        Principal::new("test", scopes.iter().map(|s| s.to_string()))
    }

    fn read_request() -> Classification {
        Classification {
            scope: Scope::Read,
            operations: vec![OperationInfo {
                name: None,
                kind: OperationKind::Query,
                top_level_fields: vec!["indexingRules".to_string()],
            }],
        }
    }

    fn write_request(field: &str, op_name: Option<&str>) -> Classification {
        Classification {
            scope: Scope::Write,
            operations: vec![OperationInfo {
                name: op_name.map(|s| s.to_string()),
                kind: OperationKind::Mutation,
                top_level_fields: vec![field.to_string()],
            }],
        }
    }

    // --- The scope × operation matrix --------------------------------------

    #[test]
    fn read_principal_may_read() {
        assert!(authorize(&principal(&["read"]), &read_request(), &Policy::default()).is_ok());
    }

    #[test]
    fn read_principal_may_not_write() {
        let err = authorize(
            &principal(&["read"]),
            &write_request("setIndexingRule", None),
            &Policy::default(),
        )
        .unwrap_err();
        assert_eq!(err.missing, vec!["write"]);
    }

    #[test]
    fn write_principal_may_read() {
        // write implies read
        assert!(authorize(&principal(&["write"]), &read_request(), &Policy::default()).is_ok());
    }

    #[test]
    fn write_principal_may_write() {
        assert!(authorize(
            &principal(&["read", "write"]),
            &write_request("setIndexingRule", None),
            &Policy::default()
        )
        .is_ok());
    }

    // --- Fine-grained overrides --------------------------------------------

    fn execute_policy() -> Policy {
        Policy {
            fail_closed_on_parse_error: true,
            overrides: vec![Override {
                field: Some("executeApprovedActions".to_string()),
                operation: None,
                require_scopes: vec!["actions:execute".to_string()],
            }],
        }
    }

    #[test]
    fn override_requires_fine_grained_scope() {
        // write alone is not enough for the gated field.
        let err = authorize(
            &principal(&["write"]),
            &write_request("executeApprovedActions", None),
            &execute_policy(),
        )
        .unwrap_err();
        assert_eq!(err.missing, vec!["actions:execute"]);
    }

    #[test]
    fn override_satisfied_when_fine_grained_scope_held() {
        let granted = authorize(
            &principal(&["write", "actions:execute"]),
            &write_request("executeApprovedActions", None),
            &execute_policy(),
        )
        .unwrap();
        assert_eq!(granted, vec!["actions:execute", "write"]);
    }

    #[test]
    fn override_does_not_apply_to_unrelated_field() {
        // A different mutation is unaffected by the executeApprovedActions rule.
        assert!(authorize(
            &principal(&["write"]),
            &write_request("setIndexingRule", None),
            &execute_policy(),
        )
        .is_ok());
    }

    #[test]
    fn operation_name_scoped_override_matches_by_name() {
        let policy = Policy {
            fail_closed_on_parse_error: true,
            overrides: vec![Override {
                field: None,
                operation: Some("DangerousOp".to_string()),
                require_scopes: vec!["actions:execute".to_string()],
            }],
        };
        let err = authorize(
            &principal(&["write"]),
            &write_request("queueActions", Some("DangerousOp")),
            &policy,
        )
        .unwrap_err();
        assert_eq!(err.missing, vec!["actions:execute"]);
    }

    #[test]
    fn anonymous_principal_is_read_only() {
        assert!(authorize(&Principal::anonymous(), &read_request(), &Policy::default()).is_ok());
        assert!(authorize(
            &Principal::anonymous(),
            &write_request("setIndexingRule", None),
            &Policy::default()
        )
        .is_err());
    }
}
