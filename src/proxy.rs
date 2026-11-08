use crate::SEP;
use crate::auth::jwt::Claims;
use crate::cidr::Cidr;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderName, HeaderValue, header};
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, warn};

const USER_ID: HeaderName = HeaderName::from_static("x-user-id");
const USER_ROLES: HeaderName = HeaderName::from_static("x-user-roles");
const REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
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

pub async fn proxy(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response {
    let client_ip = resolve_client_ip(peer.ip(), req.headers(), &state.config.trusted_proxies);

    proxy_request(
        state.http.inner(),
        &state.config.upstream_url,
        client_ip,
        req,
    )
    .await
}

async fn proxy_request(
    client: &reqwest::Client,
    upstream_url: &str,
    client_ip: IpAddr,
    req: Request<Body>,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let claims = parts.extensions.get::<Claims>();

    if let Err(e) = prepare_headers(&mut parts.headers, claims, Some(client_ip)) {
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

/// Определяет IP клиента с учётом доверенных прокси.
///
/// Если непосредственный peer не входит в `trusted`, его адрес и есть адрес
/// клиента, а `X-Forwarded-For` игнорируется. Иначе цепочка разбирается справа
/// налево: доверенные адреса пропускаются, первый недоверенный считается
/// клиентом. Некорректный элемент цепочки обрывает разбор — дальше влево
/// доверять нельзя.
pub fn resolve_client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[Cidr]) -> IpAddr {
    let peer = normalize_ip(peer);
    let trusted_proxy = is_trusted(peer, trusted);

    let client_ip = if trusted_proxy {
        resolve_forwarded_for(peer, headers, trusted)
    } else {
        peer
    };

    debug!(
        %peer,
        trusted_proxy,
        %client_ip,
        "client ip resolved"
    );

    client_ip
}

fn resolve_forwarded_for(peer: IpAddr, headers: &HeaderMap, trusted: &[Cidr]) -> IpAddr {
    let mut current = peer;

    for value in headers.get_all(FORWARDED_FOR).iter().rev() {
        let Ok(value) = value.to_str() else {
            return current;
        };

        for part in value.split(',').rev() {
            let part = part.trim();

            if part.is_empty() {
                continue;
            }

            let Ok(ip) = part.parse::<IpAddr>() else {
                return current;
            };

            let ip = normalize_ip(ip);

            if !is_trusted(ip, trusted) {
                return ip;
            }

            current = ip;
        }
    }

    current
}

/// Приводит IPv4-mapped IPv6 (`::ffff:192.0.2.1`) к обычному IPv4,
/// чтобы адрес совпадал с IPv4-подсетями из `TRUSTED_PROXIES`.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => IpAddr::V4(ip),
            None => IpAddr::V6(ip),
        },
        IpAddr::V4(_) => ip,
    }
}

fn is_trusted(ip: IpAddr, trusted: &[Cidr]) -> bool {
    trusted.iter().any(|cidr| cidr.contains(ip))
}

pub fn prepare_headers(
    headers: &mut HeaderMap,
    claims: Option<&Claims>,
    client_ip: Option<IpAddr>,
) -> Result<(), String> {
    remove_hop_by_hop(headers);
    headers.remove(header::HOST);
    headers.remove(header::AUTHORIZATION);
    headers.remove(USER_ID);
    headers.remove(USER_ROLES);
    headers.remove(REAL_IP);
    headers.remove(FORWARDED_FOR);

    if let Some(ip) = client_ip {
        let value = HeaderValue::from_str(&ip.to_string())
            .map_err(|e| format!("invalid client IP header: {e}"))?;

        headers.insert(FORWARDED_FOR, value);
    }

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

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn trusted(values: &[&str]) -> Vec<Cidr> {
        values
            .iter()
            .map(|value| Cidr::parse(value).unwrap())
            .collect()
    }

    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();

        for value in values {
            headers.append(FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }

        headers
    }

    #[test]
    fn resolve_client_ip_uses_peer_when_proxy_is_not_trusted() {
        let headers = forwarded(&["203.0.113.7"]);

        let client_ip = resolve_client_ip(ip("198.51.100.9"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("198.51.100.9"));
    }

    #[test]
    fn resolve_client_ip_uses_forwarded_for_from_trusted_proxy() {
        let headers = forwarded(&["203.0.113.7"]);

        let client_ip = resolve_client_ip(ip("10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("203.0.113.7"));
    }

    #[test]
    fn resolve_client_ip_skips_trusted_hops() {
        let headers = forwarded(&["203.0.113.7, 10.0.0.3"]);

        let client_ip = resolve_client_ip(ip("10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("203.0.113.7"));
    }

    #[test]
    fn resolve_client_ip_returns_rightmost_untrusted_hop() {
        let headers = forwarded(&["203.0.113.7, 198.51.100.9, 10.0.0.3"]);

        let client_ip = resolve_client_ip(ip("10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("198.51.100.9"));
    }

    #[test]
    fn resolve_client_ip_returns_leftmost_when_all_hops_are_trusted() {
        let headers = forwarded(&["10.0.0.4, 10.0.0.3"]);

        let client_ip = resolve_client_ip(ip("10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("10.0.0.4"));
    }

    #[test]
    fn resolve_client_ip_falls_back_to_peer_without_forwarded_for() {
        let client_ip =
            resolve_client_ip(ip("10.0.0.2"), &HeaderMap::new(), &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("10.0.0.2"));
    }

    #[test]
    fn resolve_client_ip_stops_at_malformed_hop() {
        let headers = forwarded(&["203.0.113.7, garbage, 10.0.0.3"]);

        let client_ip = resolve_client_ip(ip("10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("10.0.0.3"));
    }

    #[test]
    fn resolve_client_ip_reads_multiple_forwarded_for_headers() {
        let headers = forwarded(&["203.0.113.7", "10.0.0.3"]);

        let client_ip = resolve_client_ip(ip("10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("203.0.113.7"));
    }

    #[test]
    fn resolve_client_ip_supports_ipv6_trusted_proxies() {
        let headers = forwarded(&["2001:db8::7"]);

        let client_ip =
            resolve_client_ip(ip("2001:db8::2"), &headers, &trusted(&["2001:db8::/32"]));

        assert_eq!(client_ip, ip("2001:db8::7"));
    }

    #[test]
    fn resolve_client_ip_normalizes_ipv4_mapped_peer() {
        let headers = forwarded(&["203.0.113.7"]);

        let client_ip =
            resolve_client_ip(ip("::ffff:10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("203.0.113.7"));
    }

    #[test]
    fn resolve_client_ip_normalizes_ipv4_mapped_forwarded_for() {
        let headers = forwarded(&["::ffff:203.0.113.7"]);

        let client_ip = resolve_client_ip(ip("10.0.0.2"), &headers, &trusted(&["10.0.0.0/8"]));

        assert_eq!(client_ip, ip("203.0.113.7"));
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

        prepare_headers(&mut headers, Some(&claims), None).unwrap();

        assert_eq!(headers.get(USER_ID).unwrap(), "user-123");
        assert_eq!(headers.get(USER_ROLES).unwrap(), "admin,user");
    }

    #[test]
    fn prepare_headers_supports_empty_roles() {
        let claims = claims("user-123", &[]);
        let mut headers = HeaderMap::new();

        prepare_headers(&mut headers, Some(&claims), None).unwrap();

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
        prepare_headers(&mut headers, Some(&claims), None).unwrap();

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

        prepare_headers(&mut headers, None, None).unwrap();

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

        prepare_headers(&mut headers, None, None).unwrap();

        assert!(headers.get("x-first").is_none());
        assert!(headers.get("x-second").is_none());
    }

    #[test]
    fn prepare_headers_removes_client_identity_headers_without_claims() {
        let mut headers = HeaderMap::new();
        headers.insert(USER_ID, HeaderValue::from_static("fake-user"));
        headers.insert(USER_ROLES, HeaderValue::from_static("admin"));

        prepare_headers(&mut headers, None, None).unwrap();

        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_replaces_client_identity_headers_with_claims() {
        let claims = claims("real-user", &["user"]);
        let mut headers = HeaderMap::new();
        headers.insert(USER_ID, HeaderValue::from_static("fake-user"));
        headers.insert(USER_ROLES, HeaderValue::from_static("admin"));

        prepare_headers(&mut headers, Some(&claims), None).unwrap();

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

        prepare_headers(&mut headers, None, None).unwrap();

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

        let result = prepare_headers(&mut headers, Some(&claims), None);

        assert!(result.unwrap_err().starts_with("invalid user ID header:"));
        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_returns_error_for_invalid_roles() {
        let claims = claims("user-123", &["admin\nuser"]);
        let mut headers = HeaderMap::new();

        let result = prepare_headers(&mut headers, Some(&claims), None);

        assert!(result.unwrap_err().starts_with("invalid roles header:"));
        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_returns_error_for_role_containing_separator() {
        let claims = claims("user-123", &["admin,user"]);
        let mut headers = HeaderMap::new();

        let result = prepare_headers(&mut headers, Some(&claims), None);

        assert_eq!(result.unwrap_err(), "role contains invalid separator");
        assert!(headers.get(USER_ID).is_none());
        assert!(headers.get(USER_ROLES).is_none());
    }

    #[test]
    fn prepare_headers_inserts_forwarded_for() {
        let ip = IpAddr::from([203, 0, 113, 7]);
        let mut headers = HeaderMap::new();

        prepare_headers(&mut headers, None, Some(ip)).unwrap();

        assert_eq!(headers.get(FORWARDED_FOR).unwrap(), "203.0.113.7");
        assert!(headers.get(REAL_IP).is_none());
    }

    #[test]
    fn prepare_headers_replaces_spoofed_client_ip_headers() {
        let ip = IpAddr::from([203, 0, 113, 7]);
        let mut headers = HeaderMap::new();
        headers.insert(REAL_IP, HeaderValue::from_static("10.0.0.1"));
        headers.insert(
            FORWARDED_FOR,
            HeaderValue::from_static("10.0.0.1, 10.0.0.2"),
        );

        prepare_headers(&mut headers, None, Some(ip)).unwrap();

        assert_eq!(headers.get(FORWARDED_FOR).unwrap(), "203.0.113.7");
        assert!(headers.get(REAL_IP).is_none());
    }

    #[test]
    fn prepare_headers_removes_client_ip_headers_when_ip_is_unknown() {
        let mut headers = HeaderMap::new();
        headers.insert(REAL_IP, HeaderValue::from_static("10.0.0.1"));
        headers.insert(FORWARDED_FOR, HeaderValue::from_static("10.0.0.1"));

        prepare_headers(&mut headers, None, None).unwrap();

        assert!(headers.get(REAL_IP).is_none());
        assert!(headers.get(FORWARDED_FOR).is_none());
    }

    #[test]
    fn prepare_headers_removes_multiple_user_id_headers_without_claims() {
        let mut headers = HeaderMap::new();
        headers.append(USER_ID, HeaderValue::from_static("fake-user-1"));
        headers.append(USER_ID, HeaderValue::from_static("fake-user-2"));

        prepare_headers(&mut headers, None, None).unwrap();

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

        let response = proxy_request(&client, &url, IpAddr::from([127, 0, 0, 1]), req).await;
        let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

        assert_eq!(&response_body[..], b"ok");
        assert_eq!(
            received.lock().unwrap().as_deref(),
            Some(payload.as_slice())
        );

        server.abort();
    }

    #[tokio::test]
    async fn proxy_forwards_client_ip_and_drops_spoofed_values() {
        async fn echo_ip(req: Request<Body>) -> String {
            let header = |name: &HeaderName| {
                req.headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            };

            format!("{}|{}", header(&FORWARDED_FOR), header(&REAL_IP))
        }

        let app = Router::new().route("/ip", get(echo_ip));
        let (url, server) = start_upstream(app).await;
        let client = reqwest::Client::new();

        let req = Request::builder()
            .uri("/ip")
            .header(REAL_IP, "10.0.0.1")
            .header(FORWARDED_FOR, "10.0.0.1, 10.0.0.2")
            .body(Body::empty())
            .unwrap();

        let response = proxy_request(&client, &url, IpAddr::from([198, 51, 100, 9]), req).await;
        let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

        assert_eq!(&response_body[..], b"198.51.100.9|");

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

        let response = proxy_request(&client, &url, IpAddr::from([127, 0, 0, 1]), req).await;

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
