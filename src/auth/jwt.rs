use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, errors::Error as JwtError};
use serde::Deserialize;
use std::fmt::{Debug, Formatter};

const REQUIRED_CLAIMS: &[&str] = &["exp", "iss", "aud"];
const BEARER: &str = "Bearer";
const SPACE: char = ' ';

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub roles: Vec<String>,
}

pub struct JwtValidator {
    issuer: String,
    audience: String,
}

pub struct VerifyKey {
    key: DecodingKey,
    validation: Validation,
}

impl VerifyKey {
    pub fn validate(&self, token: &BearerToken) -> Result<Claims, JwtError> {
        Ok(decode::<Claims>(token.as_str(), &self.key, &self.validation)?.claims)
    }
}

impl JwtValidator {
    pub fn new(issuer: &str, audience: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        }
    }

    pub fn bind(&self, alg: Algorithm, key: DecodingKey) -> VerifyKey {
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(REQUIRED_CLAIMS);
        validation.leeway = 30;
        VerifyKey { validation, key }
    }
}

pub struct BearerToken(String);

impl BearerToken {
    pub fn from_header(value: &str) -> Option<Self> {
        let (scheme, token) = value.split_once(SPACE)?;

        if !scheme.eq_ignore_ascii_case(BEARER) {
            return None;
        }

        let token = token.trim();
        if token.is_empty() {
            return None;
        }

        Some(BearerToken(token.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for BearerToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::Serialize;
    use serde_json::Value;

    const SECRET: &[u8] = b"test-secret-key-for-jwt-validation";
    const ISSUER: &str = "test-issuer";
    const AUDIENCE: &str = "test-audience";

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        roles: Vec<String>,
        exp: u64,
        iss: String,
        aud: String,
    }

    fn make_token(alg: Algorithm, issuer: &str, audience: &str, exp: u64) -> String {
        let claims = TestClaims {
            sub: "user-123".into(),
            roles: vec!["admin".into()],
            exp,
            iss: issuer.into(),
            aud: audience.into(),
        };

        encode(
            &Header::new(alg),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap()
    }

    fn validator() -> VerifyKey {
        JwtValidator::new(ISSUER, AUDIENCE).bind(Algorithm::HS256, DecodingKey::from_secret(SECRET))
    }

    fn valid_token() -> String {
        make_token(
            Algorithm::HS256,
            ISSUER,
            AUDIENCE,
            jsonwebtoken::get_current_timestamp() + 3600,
        )
    }

    fn bearer_token(token: &str) -> BearerToken {
        BearerToken::from_header(&format!("Bearer {token}")).unwrap()
    }

    // ---------- BearerToken ----------

    #[test]
    fn bearer_token_parses_valid_header() {
        let token = BearerToken::from_header("Bearer abc.def.ghi").unwrap();
        assert_eq!(token.as_str(), "abc.def.ghi");
    }

    #[test]
    fn bearer_token_trims_whitespace_after_scheme() {
        let token = BearerToken::from_header("Bearer   abc.def.ghi  ").unwrap();
        assert_eq!(token.as_str(), "abc.def.ghi");
    }

    #[test]
    fn bearer_token_rejects_missing_bearer_scheme() {
        assert!(BearerToken::from_header("abc.def.ghi").is_none());
    }

    #[test]
    fn bearer_token_rejects_empty_value() {
        assert!(BearerToken::from_header("Bearer   ").is_none());
    }

    #[test]
    fn bearer_token_debug_redacts_secret() {
        let token = BearerToken::from_header("Bearer secret-token").unwrap();
        let debug = format!("{token:?}");

        assert_eq!(debug, "BearerToken([REDACTED])");
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn bearer_token_accepts_lowercase_scheme() {
        let token = BearerToken::from_header("bearer abc").unwrap();
        assert_eq!(token.as_str(), "abc");
    }

    #[test]
    fn bearer_token_rejects_basic_scheme() {
        assert!(BearerToken::from_header("Basic abc").is_none());
    }

    // ---------- VerifyKey ----------

    #[test]
    fn jwt_validator_accepts_valid_token() {
        let claims = validator().validate(&bearer_token(&valid_token())).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.roles, vec!["admin"]);
    }

    #[test]
    fn jwt_validator_rejects_expired_token() {
        let token = make_token(
            Algorithm::HS256,
            ISSUER,
            AUDIENCE,
            jsonwebtoken::get_current_timestamp() - 3600,
        );

        assert!(validator().validate(&bearer_token(&token)).is_err());
    }

    #[test]
    fn jwt_validator_rejects_invalid_signature() {
        let key = JwtValidator::new(ISSUER, AUDIENCE).bind(
            Algorithm::HS256,
            DecodingKey::from_secret(b"another-secret"),
        );

        assert!(key.validate(&bearer_token(&valid_token())).is_err());
    }

    #[test]
    fn jwt_validator_rejects_wrong_issuer() {
        let token = make_token(
            Algorithm::HS256,
            "wrong-issuer",
            AUDIENCE,
            jsonwebtoken::get_current_timestamp() + 3600,
        );

        assert!(validator().validate(&bearer_token(&token)).is_err());
    }

    #[test]
    fn jwt_validator_rejects_wrong_audience() {
        let token = make_token(
            Algorithm::HS256,
            ISSUER,
            "wrong-audience",
            jsonwebtoken::get_current_timestamp() + 3600,
        );

        assert!(validator().validate(&bearer_token(&token)).is_err());
    }

    #[test]
    fn jwt_validator_rejects_malformed_token() {
        assert!(validator().validate(&bearer_token("not-a-jwt")).is_err());
    }

    #[test]
    fn jwt_validator_rejects_missing_exp() {
        let mut claims = get_claims();
        claims.as_object_mut().unwrap().remove("exp");

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();

        assert!(validator().validate(&bearer_token(&token)).is_err());
    }

    #[test]
    fn jwt_validator_rejects_different_algorithm() {
        let token = make_token(
            Algorithm::HS384,
            ISSUER,
            AUDIENCE,
            jsonwebtoken::get_current_timestamp() + 3600,
        );

        assert!(validator().validate(&bearer_token(&token)).is_err());
    }

    #[test]
    fn jwt_validator_rejects_missing_roles() {
        let mut claims = get_claims();
        claims.as_object_mut().unwrap().remove("roles");

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();

        assert!(validator().validate(&bearer_token(&token)).is_err());
    }

    fn get_claims() -> Value {
        serde_json::to_value(TestClaims {
            sub: "user-123".into(),
            roles: vec!["admin".into()],
            exp: jsonwebtoken::get_current_timestamp() + 3600,
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
        })
        .unwrap()
    }
}
