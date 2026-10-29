use crate::auth::jwt::{JwtValidator, VerifyKey};
use crate::http_client::HttpClient;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::warn;

/// Ошибки получения и разбора JWKS, а также некорректных ключей.
#[derive(Debug, Error)]
pub enum JwksError {
    #[error("{0}")]
    Http(String),

    #[error("invalid JWKS JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("invalid JWKS: missing keys array")]
    MissingKeys,

    #[error("duplicate kid in JWKS: {kid}")]
    DuplicateKid { kid: String },

    #[error("jwks contains no usable keys")]
    NoUsableKeys,
}

pub struct HttpJwksSource {
    http: HttpClient,
    url: String,
    allowed: Vec<Algorithm>,
    validator: JwtValidator,
}
impl HttpJwksSource {
    pub fn new(
        http: HttpClient,
        url: String,
        allowed: Vec<Algorithm>,
        validator: JwtValidator,
    ) -> Self {
        HttpJwksSource {
            http,
            url,
            allowed,
            validator,
        }
    }
}
pub trait JwksSource {
    fn fetch(&self) -> impl Future<Output = Result<HashMap<String, VerifyKey>, JwksError>> + Send;
}
impl JwksSource for HttpJwksSource {
    async fn fetch(&self) -> Result<HashMap<String, VerifyKey>, JwksError> {
        let body = self
            .http
            .get_text("jwks source", &self.url)
            .await
            .map_err(JwksError::Http)?;

        parse_jwks(&body, &self.allowed, &self.validator)
    }
}

pub fn parse_jwks(
    body: &str,
    allowed: &[Algorithm],
    validator: &JwtValidator,
) -> Result<HashMap<String, VerifyKey>, JwksError> {
    let mut document: Value = serde_json::from_str(body)?;

    let keys = document
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .ok_or(JwksError::MissingKeys)?;

    let mut result = HashMap::new();
    let mut seen_kids = HashSet::new();

    for value in std::mem::take(keys) {
        let kid = match value
            .get("kid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            Some(kid) => kid.to_string(),
            None => {
                warn!(kid = "<missing>", reason = "missing kid", "skipping JWK");
                continue;
            }
        };

        if !seen_kids.insert(kid.clone()) {
            return Err(JwksError::DuplicateKid { kid });
        }

        let Some(alg_name) = value.get("alg").and_then(Value::as_str) else {
            warn!(kid, reason = "missing alg", "skipping JWK");
            continue;
        };

        let alg = match alg_name.parse::<Algorithm>() {
            Ok(alg) if allowed.contains(&alg) => alg,
            _ => {
                warn!(
                    kid,
                    alg = alg_name,
                    reason = "algorithm is unsupported or not allowed",
                    "skipping JWK"
                );
                continue;
            }
        };

        if value.get("use").is_some_and(|v| v.as_str() != Some("sig")) {
            warn!(kid, reason = "use is not sig", "skipping JWK");
            continue;
        }

        if value.get("kty").and_then(Value::as_str) == Some("oct") {
            warn!(
                kid,
                reason = "symmetric keys are not supported",
                "skipping JWK"
            );
            continue;
        }

        let Ok(jwk) = serde_json::from_value::<Jwk>(value) else {
            warn!(kid, reason = "invalid JWK structure", "skipping JWK");
            continue;
        };

        let Ok(key) = DecodingKey::from_jwk(&jwk) else {
            warn!(
                kid,
                reason = "failed to construct decoding key",
                "skipping JWK"
            );
            continue;
        };

        result.insert(kid, validator.bind(alg, key));
    }

    if result.is_empty() {
        return Err(JwksError::NoUsableKeys);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn validator() -> JwtValidator {
        JwtValidator::new("test-issuer", "test-audience")
    }

    fn rsa_jwk(kid: &str) -> serde_json::Value {
        json!({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": "sXchDaQebHaa6F6P2k7y9L9F4kY7e3n8rZ3h5V6vY3v0Y2s8xV4r7b8q5w2n1m0p",
            "e": "AQAB"
        })
    }

    fn jwks(keys: Vec<serde_json::Value>) -> String {
        json!({ "keys": keys }).to_string()
    }

    #[test]
    fn parses_valid_rsa_key() {
        let body = jwks(vec![rsa_jwk("key-1")]);

        let result = parse_jwks(&body, &[Algorithm::RS256], &validator()).unwrap();

        assert!(result.contains_key("key-1"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn skips_key_without_kid() {
        let mut key = rsa_jwk("key-1");
        key.as_object_mut().unwrap().remove("kid");

        let body = jwks(vec![key, rsa_jwk("key-2")]);
        let result = parse_jwks(&body, &[Algorithm::RS256], &validator()).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("key-2"));
    }

    #[test]
    fn skips_key_without_alg() {
        let mut key = rsa_jwk("key-1");
        key.as_object_mut().unwrap().remove("alg");

        let body = jwks(vec![key, rsa_jwk("key-2")]);
        let result = parse_jwks(&body, &[Algorithm::RS256], &validator()).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("key-2"));
    }

    #[test]
    fn skips_key_with_non_signature_use() {
        let mut key = rsa_jwk("key-1");
        key["use"] = json!("enc");

        let body = jwks(vec![key, rsa_jwk("key-2")]);
        let result = parse_jwks(&body, &[Algorithm::RS256], &validator()).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("key-2"));
    }

    #[test]
    fn skips_key_with_disallowed_algorithm() {
        let mut key = rsa_jwk("key-1");
        key["alg"] = json!("RS384");

        let body = jwks(vec![key, rsa_jwk("key-2")]);
        let result = parse_jwks(&body, &[Algorithm::RS256], &validator()).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("key-2"));
    }

    #[test]
    fn skips_symmetric_key() {
        let key = json!({
            "kty": "oct",
            "kid": "symmetric-key",
            "alg": "HS256",
            "use": "sig",
            "k": "c2VjcmV0"
        });

        let body = jwks(vec![key, rsa_jwk("key-2")]);
        let result = parse_jwks(&body, &[Algorithm::RS256], &validator()).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("key-2"));
    }

    #[test]
    fn returns_error_for_duplicate_kid() {
        let body = jwks(vec![rsa_jwk("duplicate"), rsa_jwk("duplicate")]);

        let error = parse_jwks_error(&body);

        assert!(error.contains("duplicate kid"));
    }

    #[test]
    fn returns_error_for_empty_keys() {
        let error = parse_jwks_error(&jwks(vec![]));

        assert_eq!(error, "jwks contains no usable keys");
    }

    #[test]
    fn returns_error_when_all_keys_are_unusable() {
        let mut key = rsa_jwk("key-1");
        key.as_object_mut().unwrap().remove("alg");

        let error = parse_jwks_error(&jwks(vec![key]));

        assert_eq!(error, "jwks contains no usable keys");
    }

    #[test]
    fn returns_error_for_invalid_json() {
        let error = parse_jwks_error("{invalid json");

        assert!(error.starts_with("invalid JWKS JSON:"));
    }

    #[test]
    fn returns_error_when_keys_field_is_missing() {
        let error = parse_jwks_error("{}");

        assert_eq!(error, "invalid JWKS: missing keys array");
    }

    #[test]
    fn returns_error_for_duplicate_kid_when_first_key_is_not_for_signature() {
        let mut encryption_key = rsa_jwk("duplicate");
        encryption_key["use"] = json!("enc");

        let body = jwks(vec![encryption_key, rsa_jwk("duplicate")]);

        let error = parse_jwks_error(&body);

        assert!(error.contains("duplicate kid"));
    }

    fn parse_jwks_error(body: &str) -> String {
        match parse_jwks(body, &[Algorithm::RS256], &validator()) {
            Ok(_) => panic!("expected parse_jwks to return an error"),
            Err(error) => error.to_string(),
        }
    }
}
