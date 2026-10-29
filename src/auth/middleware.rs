use crate::auth::guard::authorize;
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderValue, StatusCode};

pub async fn auth_layer(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let method = req.method();
    let path = req.uri().path();
    let auth = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let result = authorize(&state.rules, &state.jwks, method, path, auth);

    match result {
        Err(reject) => {
            let status = reject.status();
            let mut response = status.into_response();

            if status == StatusCode::UNAUTHORIZED {
                response
                    .headers_mut()
                    .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }

            response
        }
        Ok(Some(claims)) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Ok(None) => next.run(req).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::cache::JwksCache;
    use crate::auth::jwt::{Claims, JwtValidator};
    use crate::config::Config;
    use crate::http_client::HttpClient;
    use crate::rbac::cache::RulesCache;
    use crate::rbac::model::RuleSet;
    use crate::rbac::source::{EndpointDto, RulesDto};
    use axum::body::{Body, to_bytes};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::{Extension, Router};
    use http::{Method, Request};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tower::ServiceExt;

    const SECRET: &[u8] = b"middleware-test-secret";
    const ISSUER: &str = "middleware-issuer";
    const AUDIENCE: &str = "middleware-audience";
    const KID: &str = "key-1";

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        roles: Vec<String>,
        exp: u64,
        iss: String,
        aud: String,
    }

    fn token(roles: &[&str]) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_string());

        let claims = TestClaims {
            sub: "user-1".into(),
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            exp: jsonwebtoken::get_current_timestamp() + 3600,
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
        };

        encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn ep(method: &str, path: &str) -> EndpointDto {
        EndpointDto {
            method: method.into(),
            path: path.into(),
        }
    }

    fn state() -> AppState {
        let rules = RulesDto {
            public: vec![ep("GET", "/public")],
            rules: HashMap::from([
                ("admin".to_string(), vec![ep("*", "/api/**")]),
                ("viewer".to_string(), vec![ep("GET", "/api/items")]),
            ]),
        };

        let rules_cache = RulesCache::default();
        rules_cache.set(RuleSet::try_from(rules).expect("test rules must be valid"));

        let jwks_cache = JwksCache::default();
        jwks_cache.set(HashMap::from([(
            KID.to_string(),
            JwtValidator::new(ISSUER, AUDIENCE)
                .bind(Algorithm::HS256, DecodingKey::from_secret(SECRET)),
        )]));

        AppState {
            config: Arc::new(Config {
                bind_addr: "127.0.0.1:0".into(),
                jwks_url: "http://localhost/jwks".into(),
                rules_url: "http://localhost/rules".into(),
                upstream_url: "http://localhost".into(),
                jwt_issuer: ISSUER.into(),
                jwt_audience: AUDIENCE.into(),
                rules_refresh_secs: 60,
                jwks_refresh_secs: 300,
                jwt_algorithms: vec![Algorithm::HS256],
                max_body_bytes: 1024,
            }),
            rules: Arc::new(rules_cache),
            jwks: Arc::new(jwks_cache),
            http: HttpClient::new().expect("test HTTP client"),
        }
    }

    async fn echo_sub(claims: Option<Extension<Claims>>) -> String {
        claims
            .map(|Extension(claims)| claims.sub)
            .unwrap_or_else(|| "anonymous".to_string())
    }

    fn protected(state: AppState) -> Router {
        Router::new()
            .route("/public", get(echo_sub))
            .route("/api/items", get(echo_sub))
            .route("/api/admin", get(echo_sub))
            .layer(from_fn_with_state(state, auth_layer))
    }

    async fn call(app: Router, method: Method, path: &str, auth: Option<&str>) -> Response {
        let mut builder = Request::builder().method(method).uri(path);

        if let Some(value) = auth {
            builder = builder.header(AUTHORIZATION, value);
        }

        let request = builder.body(Body::empty()).expect("valid request");
        app.oneshot(request).await.expect("infallible")
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");

        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    #[tokio::test]
    async fn missing_token_returns_401_with_challenge() {
        let response = call(protected(state()), Method::GET, "/api/items", None).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static("Bearer")
        );
        assert!(body_text(response).await.is_empty());
    }

    #[tokio::test]
    async fn insufficient_role_returns_403_without_challenge() {
        let auth = bearer(&token(&["viewer"]));

        let response = call(protected(state()), Method::GET, "/api/admin", Some(&auth)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[tokio::test]
    async fn valid_token_reaches_handler_with_claims() {
        let auth = bearer(&token(&["viewer"]));

        let response = call(protected(state()), Method::GET, "/api/items", Some(&auth)).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "user-1");
    }

    #[tokio::test]
    async fn public_path_passes_without_token_and_claims() {
        let response = call(protected(state()), Method::GET, "/public", None).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "anonymous");
    }

    #[tokio::test]
    async fn invalid_path_returns_400() {
        let auth = bearer(&token(&["admin"]));

        let response = call(
            protected(state()),
            Method::GET,
            "/api/../admin",
            Some(&auth),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn uninitialized_rules_return_503() {
        let mut state = state();
        state.rules = Arc::new(RulesCache::default());

        let response = call(protected(state), Method::GET, "/api/items", None).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }
}
