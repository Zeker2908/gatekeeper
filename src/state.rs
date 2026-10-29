use crate::auth::cache::JwksCache;
use crate::config::Config;
use crate::http_client::HttpClient;
use crate::rbac::cache::RulesCache;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub rules: Arc<RulesCache>,
    pub jwks: Arc<JwksCache>,
    pub http: HttpClient,
}
