use crate::SEP;
use crate::auth::jwt::Claims;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderName, HeaderValue, header};
use tracing::warn;

const USER_ID: HeaderName = HeaderName::from_static("x-user-id");
const USER_ROLES: HeaderName = HeaderName::from_static("x-user-roles");
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const HOP_BY_HOP_HEADERS: [HeaderName; 8] = [
    header::CONNECTION,
    KEEP_ALIVE,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

const ROLE_SEPARATOR: &str = ",";
const EMPTY: &str = "";
const CONNECTION_SPLITTER: char = ',';
const SLASH: &str = "/";

pub async fn proxy(State(state): State<AppState>, req: Request<Body>) -> Response {
    proxy_request(state.http.inner(), &state.config.upstream_url, req).await
}

async fn proxy_request(
    client: &reqwest::Client,
    upstream_url: &str,
    req: Request<Body>,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let claims = parts.extensions.get::<Claims>();

    if let Err(e) = prepare_headers(&mut parts.headers, claims) {
        warn!("Failed to prepare proxy request headers: {e}");
        return StatusCode::BAD_GATEWAY.into_response();
    }

    let url = build_upstream_url(
        upstream_url,
        parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or(SLASH),
    );

    let body = reqwest::Body::wrap_stream(body.into_data_stream());

    let upstream = match client
        .request(parts.method, url)
        .headers(parts.headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            warn!("Failed to send proxy request: {e}");
            return if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT.into_response()
            } else {
                StatusCode::BAD_GATEWAY.into_response()
            };
        }
    };

    let status = upstream.status();
    let mut headers: HeaderMap = upstream.headers().clone();
    remove_hop_by_hop(&mut headers);

    let mut response = Response::new(Body::from_stream(upstream.bytes_stream()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

pub fn build_upstream_url(base: &str, path_and_query: &str) -> String {
    format!("{}{path_and_query}", base.trim_end_matches(SEP))
}

pub fn prepare_headers(headers: &mut HeaderMap, claims: Option<&Claims>) -> Result<(), String> {
    remove_hop_by_hop(headers);
    headers.remove(header::HOST);
    headers.remove(header::AUTHORIZATION);
    headers.remove(USER_ID);
    headers.remove(USER_ROLES);

    if let Some(claims) = claims {
        let user_id = HeaderValue::from_str(&claims.sub)
            .map_err(|e| format!("invalid user ID header: {e}"))?;

        if claims
            .roles
            .iter()
            .any(|role| role.contains(ROLE_SEPARATOR))
        {
            return Err("role contains invalid separator".to_string());
        }

        let roles = HeaderValue::from_str(&claims.roles.join(ROLE_SEPARATOR))
            .map_err(|e| format!("invalid roles header: {e}"))?;

        headers.insert(USER_ID, user_id);
        headers.insert(USER_ROLES, roles);
    }

    Ok(())
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let mut headers_to_remove: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.to_str().unwrap_or(EMPTY).split(CONNECTION_SPLITTER))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();

    headers_to_remove.extend(HOP_BY_HOP_HEADERS);

    for name in headers_to_remove {
        headers.remove(name);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::to_bytes,
        routing::{get, post},
    };
    use http::header;
    use std::sync::{Arc, Mutex};
    use tokio::{net::TcpListener, task::JoinHandle};

    fn claims(sub: &str, roles: &[&str]) -> Claims {
        Claims {
            sub: sub.to_string(),
            roles: roles.iter().map(|role| role.to_string()).collect(),
        }
    }

    #[test]
    fn build_upstream_url_concatenates_base_and_path_and_query() {
        assert_eq!(
            build_upstream_url("https://example.com", "/api/users?page=1&size=10"),
            "https://example.com/api/users?page=1&size=10"
        );
    }

    #[test]
    fn build_upstream_url_removes_trailing_slashes_from_base() {
        assert_eq!(
            build_upstream_url("https://example.com///", "/api/users"),
            "https://example.com/api/users"
        );
    }

    #[test]
    fn build_upstream_url_preserves_path_and_query() {
        assert_eq!(
            build_upstream_url("https://example.com/", "/api/users%20123?name=John%20Doe"),
            "https://example.com/api/users%20123?name=John%20Doe"
        );
    }

    #[test]
    fn build_upstream_url_supports_empty_path() {
        assert_eq!(
            build_upstream_url("https://example.com///", ""),
            "https://example.com"
        );
    }

    #[test]
    fn prepare_headers_inserts_user_id_and_roles() {
        let claims = claims("user-123", &["admin", "user"]);
        let mut headers = HeaderMap::new();

        prepare_headers(&mut headers, Some(&claims)).unwrap();

        assert_eq!(headers.get(USER_ID).unwrap(), "user-123");
        assert_eq!(headers.get(USER_ROLES).unwrap(), "admin,user");
    }

    #[test]
    fn prepare_headers_supports_empty_roles() {
        let claims = claims("user-123", &[]);
        let mut headers = HeaderMap::new();

        prepare_headers(&mut headers, Some(&claims)).unwrap();

        assert_eq!(headers.get(USER_ID).unwrap(), "user-123");
        assert_eq!(headers.get(USER_ROLES).unwrap(), "");
    }

    #[test]
    fn prepare_headers_removes_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();

        for name in [
            header::CONNECTION,
            KEEP_ALIVE,
            header::PROXY_AUTHENTICATE,
            header::PROXY_AUTHORIZATION,
            header::TE,
            header::TRAILER,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
            header::HOST,
            header::AUTHORIZATION,
        ] {
            headers.insert(name, HeaderValue::from_static("test"));
        }

        let claims = claims("user-123", &["admin"]);
        prepare_headers(&mut headers, Some(&claims)).unwrap();

        for name in &[
            header::CONNECTION,
            KEEP_ALIVE,
            header::PROXY_AUTHENTICATE,
            header::PROXY_AUTHORIZATION,
            header::TE,
            header::TRAILER,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
            header::HOST,
            header::AUTHORIZATION,
        ] {
            assert!(headers.get(name).is_none(), "header {name} was not removed");
        }
    }

    #[test]
    fn prepare_headers_removes_headers_listed_in_connection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("x-internal-header, x-another-header"),
        );
        headers.insert(
            HeaderName::from_static("x-internal-header"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(
            HeaderName::from_static("x-another-header"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(
            HeaderName::from_static("x-keep-header"),
            HeaderValue::from_static("keep"),
        );

        prepare_headers(&mut headers, None).unwrap();

        assert!(headers.get("connection").is_none());
        assert!(headers.get("x-internal-header").is_none());
        assert!(headers.get("x-another-header").is_none());
        assert_eq!(headers.get("x-keep-header").unwrap(), "keep");
    }

    #[test]
    fn prepare_headers_removes_headers_listed_in_multiple_connection_values() {
        let mut headers = HeaderMap::new();
        headers.append(header::CONNECTION, HeaderValue::from_static("x-first"));
        headers.append(header::CONNECTION, HeaderValue::from_static("x-second"));
        headers.insert(
            HeaderName::from_static("x-first"),
            HeaderValue::from_static("1"),
        );
        headers.insert(
            HeaderName::from_static("x-second"),
            HeaderValue::from_static("2"),
        );

        prepare_headers(&mut headers, None).unwrap();

        assert!(headers.get("x-first").is_none());
        assert!(headers.get("x-second").is_none());
    }

    #[test]
    fn prepare_headers_removes_client_identity_headers_without_claims() {
        let mut headers = HeaderMap::new();
        headers.insert(USER_ID, HeaderValue::from_static("fake-user"));
        headers.insert(USER_ROLES, HeaderValue::from_static("admin"));

        prepare_headers(&mut headers, None).unwrap();

        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_replaces_client_identity_headers_with_claims() {
        let claims = claims("real-user", &["user"]);
        let mut headers = HeaderMap::new();
        headers.insert(USER_ID, HeaderValue::from_static("fake-user"));
        headers.insert(USER_ROLES, HeaderValue::from_static("admin"));

        prepare_headers(&mut headers, Some(&claims)).unwrap();

        assert_eq!(headers.get(USER_ID).unwrap(), "real-user");
        assert_eq!(headers.get(USER_ROLES).unwrap(), "user");
    }

    #[test]
    fn prepare_headers_preserves_regular_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));

        prepare_headers(&mut headers, None).unwrap();

        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(headers.get(header::ACCEPT).unwrap(), "application/json");
    }

    #[test]
    fn prepare_headers_returns_error_for_invalid_user_id() {
        let claims = claims("invalid\nuser", &["admin"]);
        let mut headers = HeaderMap::new();

        let result = prepare_headers(&mut headers, Some(&claims));

        assert!(result.unwrap_err().starts_with("invalid user ID header:"));
        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_returns_error_for_invalid_roles() {
        let claims = claims("user-123", &["admin\nuser"]);
        let mut headers = HeaderMap::new();

        let result = prepare_headers(&mut headers, Some(&claims));

        assert!(result.unwrap_err().starts_with("invalid roles header:"));
        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_returns_error_for_role_containing_separator() {
        let claims = claims("user-123", &["admin,user"]);
        let mut headers = HeaderMap::new();

        let result = prepare_headers(&mut headers, Some(&claims));

        assert_eq!(result.unwrap_err(), "role contains invalid separator");
        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_removes_multiple_user_id_headers_without_claims() {
        let mut headers = HeaderMap::new();
        headers.append(USER_ID, HeaderValue::from_static("fake-user-1"));
        headers.append(USER_ID, HeaderValue::from_static("fake-user-2"));

        prepare_headers(&mut headers, None).unwrap();

        assert!(headers.get(USER_ID).is_none());
    }

    async fn start_upstream(app: Router) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn proxy_forwards_post_body() {
        let received = Arc::new(Mutex::new(None::<Vec<u8>>));
        let captured = received.clone();

        async fn receive_body(
            State(captured): State<Arc<Mutex<Option<Vec<u8>>>>>,
            req: Request<Body>,
        ) -> &'static str {
            let body = to_bytes(req.into_body(), usize::MAX).await.unwrap();
            *captured.lock().unwrap() = Some(body.to_vec());
            "ok"
        }

        let app = Router::new()
            .route("/echo", post(receive_body))
            .with_state(captured);

        let (url, server) = start_upstream(app).await;
        let client = reqwest::Client::new();
        let payload = br#"{"message":"hello","value":42}"#.to_vec();

        let req = Request::builder()
            .method("POST")
            .uri("/echo")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, payload.len())
            .body(Body::from(payload.clone()))
            .unwrap();

        let response = proxy_request(&client, &url, req).await;
        let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

        assert_eq!(&response_body[..], b"ok");
        assert_eq!(
            received.lock().unwrap().as_deref(),
            Some(payload.as_slice())
        );

        server.abort();
    }

    #[tokio::test]
    async fn proxy_preserves_compressed_response_body_and_headers() {
        // Gzip-представление строки "hello".
        let payload: Vec<u8> = vec![
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9,
            0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
        ];

        let upstream_payload = payload.clone();
        let app = Router::new().route(
            "/compressed",
            get(move || {
                let payload = upstream_payload.clone();
                async move {
                    let mut response = Response::new(Body::from(payload.clone()));
                    response
                        .headers_mut()
                        .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                    response.headers_mut().insert(
                        header::CONTENT_LENGTH,
                        HeaderValue::from_str(&payload.len().to_string()).unwrap(),
                    );
                    response
                }
            }),
        );

        let (url, server) = start_upstream(app).await;
        let client = reqwest::Client::new();
        let req = Request::builder()
            .uri("/compressed")
            .body(Body::empty())
            .unwrap();

        let response = proxy_request(&client, &url, req).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            payload.len().to_string()
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], payload.as_slice());

        server.abort();
    }
}
