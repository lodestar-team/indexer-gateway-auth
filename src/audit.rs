//! Audit logging.
//!
//! Every mutating call (and, optionally, every read) is recorded as a single
//! JSON line: who did what, to which operation, with what outcome, and how the
//! upstream responded. Variables are recorded as a SHA-256 fingerprint by
//! default — the raw values (which may carry addresses or keys) are only emitted
//! when verbose logging is explicitly enabled.
//!
//! Records are pure data; emission goes through an [`AuditSink`] so the
//! serialised shape can be tested without touching IO.

use std::io::Write;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::classify::{OperationKind, Scope};

/// The outcome of a request, as seen by the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum Outcome {
    /// Authorized and forwarded upstream.
    Allowed,
    /// Authentication failed (`401`).
    AuthFailed { reason: String },
    /// Authenticated but insufficient scope (`403`).
    Denied { reason: String },
    /// Body could not be classified and was rejected (`400`).
    Rejected { reason: String },
}

/// One audit record. Optional fields are omitted from the JSON when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Principal name, or `"-"` when authentication failed before identifying one.
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub operation_kinds: Vec<OperationKind>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub top_level_fields: Vec<String>,
    /// SHA-256 (hex) fingerprint of the request variables, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables_hash: Option<String>,
    /// Raw variables — present only when verbose variable logging is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<serde_json::Value>,
    #[serde(flatten)]
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

impl AuditRecord {
    /// Serialise to a single-line JSON string (no trailing newline).
    pub fn to_json_line(&self) -> String {
        // Serialization of a fixed struct cannot fail; fall back defensively.
        serde_json::to_string(self)
            .unwrap_or_else(|_| "{\"audit\":\"serialize_error\"}".to_string())
    }
}

/// Current time as an RFC 3339 string. Separated so callers can inject time in
/// tests by constructing [`AuditRecord`] directly.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// SHA-256 (hex) fingerprint of request variables. Stable for identical input.
pub fn hash_variables(variables: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(variables).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

/// Where audit records are written.
#[derive(Clone)]
pub enum AuditSink {
    /// Write each record as a line to stdout.
    Stdout,
    /// Append each record as a line to an open file.
    File(Arc<Mutex<std::fs::File>>),
    /// Discard records (disabled, or for tests).
    Null,
}

impl AuditSink {
    /// Open a file sink in append mode.
    pub fn file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(AuditSink::File(Arc::new(Mutex::new(file))))
    }

    /// Emit a record. IO errors are logged but never propagated — a failing
    /// audit sink must not take down request handling (it is logged via
    /// `tracing` so the failure itself is observable).
    pub fn emit(&self, record: &AuditRecord) {
        let line = record.to_json_line();
        match self {
            AuditSink::Stdout => {
                let mut out = std::io::stdout().lock();
                if let Err(e) = writeln!(out, "{line}") {
                    tracing::error!(error = %e, "failed to write audit record to stdout");
                }
            }
            AuditSink::File(file) => {
                if let Ok(mut f) = file.lock() {
                    if let Err(e) = writeln!(f, "{line}") {
                        tracing::error!(error = %e, "failed to write audit record to file");
                    }
                }
            }
            AuditSink::Null => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_record() -> AuditRecord {
        AuditRecord {
            timestamp: "2026-06-01T12:00:00+00:00".to_string(),
            principal: "operator".to_string(),
            source_ip: Some("10.0.0.5".to_string()),
            scope: Some(Scope::Write),
            operation_name: Some("SetRule".to_string()),
            operation_kinds: vec![OperationKind::Mutation],
            top_level_fields: vec!["setIndexingRule".to_string()],
            variables_hash: None,
            variables: None,
            outcome: Outcome::Allowed,
            upstream_status: Some(200),
            latency_ms: Some(12),
        }
    }

    #[test]
    fn allowed_record_serialises_expected_shape() {
        let line = base_record().to_json_line();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["principal"], "operator");
        assert_eq!(v["scope"], "write");
        assert_eq!(v["operation_kinds"][0], "mutation");
        assert_eq!(v["outcome"], "allowed");
        assert_eq!(v["upstream_status"], 200);
        // Single line, no embedded newline.
        assert!(!line.contains('\n'));
    }

    #[test]
    fn absent_optionals_are_omitted() {
        let mut rec = base_record();
        rec.source_ip = None;
        rec.upstream_status = None;
        rec.latency_ms = None;
        let v: serde_json::Value = serde_json::from_str(&rec.to_json_line()).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("source_ip"));
        assert!(!obj.contains_key("upstream_status"));
        assert!(!obj.contains_key("variables"));
    }

    #[test]
    fn denied_outcome_carries_reason() {
        let mut rec = base_record();
        rec.outcome = Outcome::Denied {
            reason: "missing [write]".to_string(),
        };
        let v: serde_json::Value = serde_json::from_str(&rec.to_json_line()).unwrap();
        assert_eq!(v["outcome"], "denied");
        assert_eq!(v["reason"], "missing [write]");
    }

    #[test]
    fn variable_hash_is_stable_and_distinct() {
        let a = hash_variables(&json!({ "deployment": "Qm123", "amount": "100" }));
        let a_again = hash_variables(&json!({ "deployment": "Qm123", "amount": "100" }));
        let b = hash_variables(&json!({ "deployment": "Qm999", "amount": "100" }));
        assert_eq!(a, a_again);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn null_sink_does_not_panic() {
        AuditSink::Null.emit(&base_record());
    }
}
