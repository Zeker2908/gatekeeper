use crate::auth::cache::JwksCache;
use crate::auth::jwt::{BearerToken, Claims};
use crate::rbac::cache::RulesCache;
use crate::rbac::path::validate_path;
use http::{Method, StatusCode};
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    BadPath,      // 400
    Unauthorized, // 401
    Forbidden,    // 403
    Unavailable,  // 503
}

impl Reject {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadPath => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub fn authorize(
    rules: &RulesCache,
    jwks: &JwksCache,
    method: &Method,
    path: &str,
    authorization: Option<&str>,
) -> Result<Option<Claims>, Reject> {
    validate_path(path).map_err(|e| {
        warn!(error = %e, "invalid request path");
        Reject::BadPath
    })?;

    let rules = rules.get().ok_or_else(|| {
        warn!("rules cache is not initialized");
        Reject::Unavailable
    })?;

    if rules.is_public(method, path) {
        return Ok(None);
    }

    let authorization = authorization.ok_or_else(|| {
        warn!("Authorization header missing");
        Reject::Unauthorized
    })?;

    let jwt_token = BearerToken::from_header(authorization).ok_or_else(|| {
        warn!("Bearer token missing or malformed");
        Reject::Unauthorized
    })?;

    let kid = jsonwebtoken::decode_header(jwt_token.as_str())
        .map_err(|e| {
            warn!(error = %e, "failed to decode JWT header");
            Reject::Unauthorized
        })?
        .kid
        .ok_or_else(|| {
            warn!("JWT kid header missing");
            Reject::Unauthorized
        })?;

    let verify_key = jwks.find(&kid).ok_or_else(|| {
        warn!(kid = ?kid, "kid not found in jwks store");
        Reject::Unauthorized
    })?;

    let claims = verify_key.validate(&jwt_token).map_err(|e| {
        warn!(error = %e, "JWT validation failed");
        Reject::Unauthorized
    })?;

    if !rules.is_allowed(&claims.roles, method, path) {
        warn!(path, method = %method, "access denied");
        return Err(Reject::Forbidden);
    }

    Ok(Some(claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtValidator;
    use crate::rbac::model::RuleSet;
    use crate::rbac::source::{EndpointDto, RulesDto};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::collections::HashMap;

    const SECRET: &[u8] = b"guard-test-secret";
    const ISSUER: &str = "guard-issuer";
    const AUDIENCE: &str = "guard-audience";
    const KID: &str = "key-1";

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        roles: Vec<String>,
        exp: u64,
        iss: String,
        aud: String,
    }

    fn future_exp() -> u64 {
        jsonwebtoken::get_current_timestamp() + 3600
    }

    fn claims(roles: &[&str], exp: u64) -> TestClaims {
        TestClaims {
            sub: "user-1".into(),
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            exp,
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
        }
    }

    fn encode_token(kid: Option<&str>, secret: &[u8], claims: TestClaims) -> String {
        encode_token_with_alg(Algorithm::HS256, kid, secret, claims)
    }

    fn encode_token_with_alg(
        alg: Algorithm,
        kid: Option<&str>,
        secret: &[u8],
        claims: TestClaims,
    ) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);

        encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    fn token(roles: &[&str]) -> String {
        encode_token(Some(KID), SECRET, claims(roles, future_exp()))
    }

    fn auth_header(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn jwks() -> JwksCache {
        let cache = JwksCache::default();
        cache.set(HashMap::from([(
            KID.to_string(),
            JwtValidator::new(ISSUER, AUDIENCE)
                .bind(Algorithm::HS256, DecodingKey::from_secret(SECRET)),
        )]));
        cache
    }

    fn ep(method: &str, path: &str) -> EndpointDto {
        EndpointDto {
            method: method.into(),
            path: path.into(),
        }
    }

    fn rules(public: Vec<EndpointDto>, roles: &[(&str, &[(&str, &str)])]) -> RulesCache {
        let dto = RulesDto {
            public,
            rules: roles
                .iter()
                .map(|(role, endpoints)| {
                    (
                        (*role).to_string(),
                        endpoints
                            .iter()
                            .map(|(method, path)| ep(method, path))
                            .collect(),
                    )
                })
                .collect(),
        };

        let cache = RulesCache::default();
        cache.set(RuleSet::try_from(dto).expect("test rules must be valid"));
        cache
    }

    fn default_rules() -> RulesCache {
        rules(
            vec![ep("GET", "/health/live")],
            &[
                ("admin", &[("*", "/api/**")]),
                ("viewer", &[("GET", "/api/items")]),
            ],
        )
    }

    // ---------- Reject ----------

    #[test]
    fn reject_status_maps_to_http_codes() {
        assert_eq!(Reject::BadPath.status(), StatusCode::BAD_REQUEST);
        assert_eq!(Reject::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Reject::Forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            Reject::Unavailable.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    // ---------- публичные эндпоинты ----------

    #[test]
    fn public_endpoint_passes_without_token() {
        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/health/live",
            None,
        );

        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn public_endpoint_ignores_invalid_authorization() {
        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/health/live",
            Some("Basic garbage"),
        );

        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn public_endpoint_with_other_method_requires_token() {
        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::POST,
            "/health/live",
            None,
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    // ---------- валидация пути ----------

    #[test]
    fn invalid_path_is_rejected_before_auth() {
        let token = token(&["admin"]);
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/../admin",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::BadPath);
    }

    #[test]
    fn unsafe_paths_are_rejected_even_for_public_rules() {
        let paths = [
            "/api/.",
            "/api/..",
            "/api//items",
            "/api\\items",
            "/api/%2e%2e",
            "/api/;drop",
        ];

        for path in paths {
            let result = authorize(&default_rules(), &jwks(), &Method::GET, path, None);

            assert_eq!(result.unwrap_err(), Reject::BadPath, "path: {path:?}");
        }
    }

    // ---------- аутентификация ----------

    #[test]
    fn missing_authorization_is_unauthorized() {
        let result = authorize(&default_rules(), &jwks(), &Method::GET, "/api/items", None);

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    #[test]
    fn malformed_authorization_header_is_unauthorized() {
        let headers = ["Basic abc", "Bearer", "Bearer    ", "bearer", "Token abc"];

        for header in headers {
            let result = authorize(
                &default_rules(),
                &jwks(),
                &Method::GET,
                "/api/items",
                Some(header),
            );

            assert_eq!(
                result.unwrap_err(),
                Reject::Unauthorized,
                "header: {header:?}"
            );
        }
    }

    #[test]
    fn token_without_kid_is_unauthorized() {
        let token = encode_token(None, SECRET, claims(&["admin"], future_exp()));
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    #[test]
    fn unknown_kid_is_unauthorized() {
        let token = encode_token(
            Some("unknown-key"),
            SECRET,
            claims(&["admin"], future_exp()),
        );
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    #[test]
    fn malformed_token_is_unauthorized() {
        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some("Bearer not-a-jwt"),
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    #[test]
    fn expired_token_is_unauthorized() {
        let expired = jsonwebtoken::get_current_timestamp() - 3600;
        let token = encode_token(Some(KID), SECRET, claims(&["admin"], expired));
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    #[test]
    fn token_with_wrong_signature_is_unauthorized() {
        let token = encode_token(
            Some(KID),
            b"another-secret",
            claims(&["admin"], future_exp()),
        );
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    #[test]
    fn token_with_algorithm_not_bound_to_key_is_unauthorized() {
        let hs384 = encode_token_with_alg(
            Algorithm::HS384,
            Some(KID),
            SECRET,
            claims(&["admin"], future_exp()),
        );
        let auth = auth_header(&hs384);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);

        // Контроль: те же claims и секрет, но HS256 из JWKS, проходят.
        let control = auth_header(&token(&["admin"]));
        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&control),
        );

        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn token_with_wrong_issuer_is_unauthorized() {
        let mut claims = claims(&["admin"], future_exp());
        claims.iss = "other-issuer".into();

        let token = encode_token(Some(KID), SECRET, claims);
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Unauthorized);
    }

    // ---------- авторизация ----------

    #[test]
    fn allowed_role_returns_claims() {
        let token = token(&["viewer"]);
        let auth = auth_header(&token);

        let claims = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        )
        .expect("viewer must be allowed")
        .expect("authenticated request must carry claims");

        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.roles, vec!["viewer".to_string()]);
    }

    #[test]
    fn unknown_role_is_forbidden() {
        let token = token(&["guest"]);
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Forbidden);
    }

    #[test]
    fn token_without_roles_is_forbidden() {
        let token = token(&[]);
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::GET,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Forbidden);
    }

    #[test]
    fn method_mismatch_is_forbidden() {
        let token = token(&["viewer"]);
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::POST,
            "/api/items",
            Some(&auth),
        );

        assert_eq!(result.unwrap_err(), Reject::Forbidden);
    }

    #[test]
    fn any_matching_role_grants_access() {
        let token = token(&["guest", "admin"]);
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::POST,
            "/api/orders/42",
            Some(&auth),
        );

        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn wildcard_rule_matches_deep_path() {
        let token = token(&["admin"]);
        let auth = auth_header(&token);

        let result = authorize(
            &default_rules(),
            &jwks(),
            &Method::DELETE,
            "/api/a/b/c",
            Some(&auth),
        );

        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn missing_rules_snapshot_is_unavailable() {
        let rules = RulesCache::default();

        let result = authorize(&rules, &jwks(), &Method::GET, "/api/items", None);

        assert_eq!(result.unwrap_err(), Reject::Unavailable);
    }
}
