//! JWT backend.
//!
//! Verifies signature, `exp`, `nbf`, issuer and audience, then reads the
//! principal's scopes from a configured claim. HS256 (shared secret) backends
//! build synchronously from config; RS256/ES256 verification keys fetched from a
//! JWKS endpoint are supplied at async startup via [`JwtBackend::with_keys`].

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use super::AuthError;
use crate::config::JwtConfig;
use crate::principal::Principal;

pub struct JwtBackend {
    /// One or more candidate verification keys (multiple when a JWKS publishes
    /// several). The token verifies if any key accepts it under `validation`.
    keys: Vec<DecodingKey>,
    validation: Validation,
    scopes_claim: String,
}

impl JwtBackend {
    /// Build from config. Requires `hs256_secret` to be set; a JWKS-only config
    /// must be completed asynchronously via [`JwtBackend::with_keys`].
    pub fn from_config(cfg: &JwtConfig) -> Result<Self, AuthError> {
        let secret = cfg.hs256_secret.as_ref().ok_or_else(|| {
            AuthError::Misconfigured(
                "JWT backend needs hs256_secret (JWKS requires async startup)".into(),
            )
        })?;
        let validation = build_validation(cfg, Algorithm::HS256);
        Ok(JwtBackend {
            keys: vec![DecodingKey::from_secret(secret.as_bytes())],
            validation,
            scopes_claim: cfg.scopes_claim.clone(),
        })
    }

    /// Build with externally-supplied decoding keys (e.g. fetched from JWKS),
    /// for the given asymmetric algorithm.
    pub fn with_keys(cfg: &JwtConfig, keys: Vec<DecodingKey>, algorithm: Algorithm) -> Self {
        JwtBackend {
            keys,
            validation: build_validation(cfg, algorithm),
            scopes_claim: cfg.scopes_claim.clone(),
        }
    }

    pub fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let mut last_err: Option<jsonwebtoken::errors::Error> = None;
        for key in &self.keys {
            match decode::<Value>(token, key, &self.validation) {
                Ok(data) => return Ok(self.principal_from_claims(&data.claims)),
                Err(e) => last_err = Some(e),
            }
        }
        Err(AuthError::Jwt(
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no verification keys configured".to_string()),
        ))
    }

    fn principal_from_claims(&self, claims: &Value) -> Principal {
        let name = claims
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or("jwt")
            .to_string();
        let scopes = extract_scopes(claims, &self.scopes_claim);
        Principal::new(name, scopes)
    }
}

fn build_validation(cfg: &JwtConfig, algorithm: Algorithm) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(std::slice::from_ref(&cfg.issuer));
    validation.set_audience(std::slice::from_ref(&cfg.audience));
    validation.validate_nbf = true;
    validation
}

/// Read scopes from a claim that may be a JSON array of strings or an
/// OAuth-style space-delimited string. Anything else yields no scopes.
fn extract_scopes(claims: &Value, claim: &str) -> Vec<String> {
    match claims.get(claim) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        Some(Value::String(s)) => s.split_whitespace().map(String::from).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, get_current_timestamp, EncodingKey, Header};
    use serde_json::json;

    const SECRET: &[u8] = b"super-secret-signing-key";

    fn config() -> JwtConfig {
        JwtConfig {
            issuer: "https://auth.example.com/".to_string(),
            audience: "indexer-management".to_string(),
            jwks_url: None,
            hs256_secret: Some(String::from_utf8(SECRET.to_vec()).unwrap()),
            scopes_claim: "scopes".to_string(),
        }
    }

    fn mint(claims: Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap()
    }

    #[test]
    fn valid_token_yields_principal_with_scopes() {
        let token = mint(json!({
            "iss": "https://auth.example.com/",
            "aud": "indexer-management",
            "sub": "operator@indexer",
            "exp": get_current_timestamp() + 3600,
            "scopes": ["read", "write"],
        }));
        let backend = JwtBackend::from_config(&config()).unwrap();
        let p = backend.verify(&token).unwrap();
        assert_eq!(p.name, "operator@indexer");
        assert!(p.scopes.contains("read") && p.scopes.contains("write"));
    }

    #[test]
    fn space_delimited_scopes_are_parsed() {
        let token = mint(json!({
            "iss": "https://auth.example.com/",
            "aud": "indexer-management",
            "exp": get_current_timestamp() + 3600,
            "scopes": "read write actions:execute",
        }));
        let backend = JwtBackend::from_config(&config()).unwrap();
        let p = backend.verify(&token).unwrap();
        assert!(p.scopes.contains("actions:execute"));
        assert_eq!(p.name, "jwt"); // no sub claim → default
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let token = mint(json!({
            "iss": "https://auth.example.com/",
            "aud": "some-other-service",
            "exp": get_current_timestamp() + 3600,
            "scopes": ["read"],
        }));
        let backend = JwtBackend::from_config(&config()).unwrap();
        assert!(matches!(backend.verify(&token), Err(AuthError::Jwt(_))));
    }

    #[test]
    fn expired_token_is_rejected() {
        let token = mint(json!({
            "iss": "https://auth.example.com/",
            "aud": "indexer-management",
            // Well past the default 60s leeway so it is unambiguously expired.
            "exp": get_current_timestamp() - 3600,
            "scopes": ["read"],
        }));
        let backend = JwtBackend::from_config(&config()).unwrap();
        assert!(matches!(backend.verify(&token), Err(AuthError::Jwt(_))));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut token = mint(json!({
            "iss": "https://auth.example.com/",
            "aud": "indexer-management",
            "exp": get_current_timestamp() + 3600,
            "scopes": ["write"],
        }));
        token.push('x'); // corrupt the signature segment
        let backend = JwtBackend::from_config(&config()).unwrap();
        assert!(backend.verify(&token).is_err());
    }

    #[test]
    fn missing_scopes_claim_yields_no_scopes() {
        let token = mint(json!({
            "iss": "https://auth.example.com/",
            "aud": "indexer-management",
            "exp": get_current_timestamp() + 3600,
        }));
        let backend = JwtBackend::from_config(&config()).unwrap();
        let p = backend.verify(&token).unwrap();
        assert!(p.scopes.is_empty());
    }

    #[test]
    fn jwks_only_config_cannot_build_synchronously() {
        let mut cfg = config();
        cfg.hs256_secret = None;
        cfg.jwks_url = Some("https://auth.example.com/.well-known/jwks.json".to_string());
        assert!(matches!(
            JwtBackend::from_config(&cfg),
            Err(AuthError::Misconfigured(_))
        ));
    }
}
