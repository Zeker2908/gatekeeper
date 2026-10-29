mod auth;
mod config;
mod http_client;
mod proxy;
mod rbac;
mod refresh;
mod state;

use crate::auth::auth_layer;
use crate::auth::cache::{JwksCache, spawn_refresh_loop_jwks};
use crate::auth::jwks::HttpJwksSource;
use crate::auth::jwt::JwtValidator;
use crate::config::Config;
use crate::http_client::HttpClient;
use crate::proxy::proxy;
use crate::rbac::cache::{RulesCache, spawn_refresh_loop};
use crate::rbac::source::HttpRulesSource;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::middleware::{from_fn_with_state, map_request};
use axum::routing::get;
use axum::{Json, Router, serve};
use http::{HeaderName, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::{Level, info_span};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

pub const SEP: char = '/';
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(Config::from_env().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    }));
    let http = HttpClient::new().expect("cannot create HTTP client");
    let rules_source = HttpRulesSource::new(http.clone(), config.rules_url.clone());
    let jwks_source = HttpJwksSource::new(
        http.clone(),
        config.jwks_url.clone(),
        config.jwt_algorithms.clone(),
        JwtValidator::new(&config.jwt_issuer, &config.jwt_audience),
    );

    let (rules, jwks) = tokio::join!(
        RulesCache::load(&rules_source),
        JwksCache::load(&jwks_source),
    );

    let (rules, jwks) = match (rules, jwks) {
        (Ok(rules), Ok(jwks)) => (Arc::new(rules), Arc::new(jwks)),
        (rules, jwks) => {
            if let Err(e) = rules {
                error!(error = %e, "initial rules load failed");
            }
            if let Err(e) = jwks {
                error!(error = %e, "initial jwks load failed");
            }
            std::process::exit(1);
        }
    };

    let _refresh_rules = spawn_refresh_loop(
        rules.clone(),
        Arc::new(rules_source),
        Duration::from_secs(config.rules_refresh_secs),
    );

    let _refresh_jwks = spawn_refresh_loop_jwks(
        jwks.clone(),
        Arc::new(jwks_source),
        Duration::from_secs(config.jwks_refresh_secs),
    );

    let state = AppState {
        config,
        rules,
        jwks,
        http,
    };

    let bind_addr = state.config.bind_addr.clone();
    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {bind_addr}: {e}"));

    let addr = listener.local_addr().unwrap();
    info!(%addr, "Server started");

    serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

fn build_app(state: AppState) -> Router {
    let trace = ServiceBuilder::new()
        .layer(SetRequestIdLayer::new(REQUEST_ID, MakeRequestUuid))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &http::Request<_>| {
                    info_span!(
                        "http",
                        method = %req.method(),
                        path = ?req.uri().path(),
                        request_id = %req.headers()
                            .get(REQUEST_ID)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("unknown"),
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::new(REQUEST_ID));

    let protected = Router::new()
        .fallback(proxy)
        .layer(RequestBodyLimitLayer::new(state.config.max_body_bytes))
        .layer(from_fn_with_state(state.clone(), auth_layer));

    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .merge(protected)
        .with_state(state)
        .layer(trace)
        .layer(map_request(strip_request_id))
}

async fn strip_request_id(mut req: http::Request<Body>) -> http::Request<Body> {
    req.headers_mut().remove(REQUEST_ID);
    req
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}

async fn live() -> Json<Value> {
    Json(json!({"status":"UP"}))
}

async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    if !state.rules.is_loaded() || !state.jwks.is_loaded() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "DOWN"})),
        );
    }
    (StatusCode::OK, Json(json!({"status": "UP"})))
}
