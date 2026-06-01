//! mTLS backend: map a verified client-certificate identity to a principal.
//!
//! Certificate *verification* (chain, validity, revocation) is the TLS layer's
//! job; by the time a [`ClientCert`] reaches this backend it has already been
//! validated against the configured CA. This backend only performs the
//! identity → principal mapping, matching the certificate CN or any SAN value
//! against the configured subjects.

use super::AuthError;
use crate::config::MtlsMapping;
use crate::principal::Principal;

/// The identity extracted from a verified client certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientCert {
    /// Subject Common Name, if present.
    pub subject_cn: Option<String>,
    /// Subject Alternative Names (DNS/URI/email values).
    pub sans: Vec<String>,
}

struct Mapping {
    subject: String,
    name: String,
    scopes: Vec<String>,
}

pub struct MtlsBackend {
    mappings: Vec<Mapping>,
}

impl MtlsBackend {
    pub fn new(mappings: &[MtlsMapping]) -> Self {
        MtlsBackend {
            mappings: mappings
                .iter()
                .map(|m| Mapping {
                    subject: m.subject.clone(),
                    name: m.name.clone(),
                    scopes: m.scopes.clone(),
                })
                .collect(),
        }
    }

    /// Map a verified certificate to its principal, or reject if no mapping
    /// matches the CN or any SAN.
    pub fn verify(&self, cert: &ClientCert) -> Result<Principal, AuthError> {
        for m in &self.mappings {
            let cn_match = cert.subject_cn.as_deref() == Some(m.subject.as_str());
            let san_match = cert.sans.iter().any(|s| s == &m.subject);
            if cn_match || san_match {
                return Ok(Principal::new(m.name.clone(), m.scopes.clone()));
            }
        }
        Err(AuthError::InvalidClientCert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(subject: &str, name: &str, scopes: &[&str]) -> MtlsMapping {
        MtlsMapping {
            subject: subject.to_string(),
            name: name.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn matches_by_common_name() {
        let backend = MtlsBackend::new(&[mapping("operator.indexer.eth", "operator", &["write"])]);
        let cert = ClientCert {
            subject_cn: Some("operator.indexer.eth".to_string()),
            sans: vec![],
        };
        let p = backend.verify(&cert).unwrap();
        assert_eq!(p.name, "operator");
    }

    #[test]
    fn matches_by_san() {
        let backend = MtlsBackend::new(&[mapping("ci.indexer.eth", "ci", &["read"])]);
        let cert = ClientCert {
            subject_cn: Some("irrelevant".to_string()),
            sans: vec!["ci.indexer.eth".to_string()],
        };
        assert_eq!(backend.verify(&cert).unwrap().name, "ci");
    }

    #[test]
    fn unmapped_certificate_is_rejected() {
        let backend = MtlsBackend::new(&[mapping("known", "k", &["read"])]);
        let cert = ClientCert {
            subject_cn: Some("stranger".to_string()),
            sans: vec![],
        };
        assert!(matches!(
            backend.verify(&cert),
            Err(AuthError::InvalidClientCert)
        ));
    }
}
