use std::time::Duration;
use tracing::debug;

/// Клиент для загрузки внешних документов (JWKS, rules).
///
/// Конфигурация HTTP-клиента живёт в одном месте. `reqwest::Client` внутри —
/// `Arc`, поэтому клонирование дешёвое: инстанс создаётся один раз в `main`
/// и раздаётся клонами, что даёт общий пул соединений и DNS-кэш.
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("gatekeeper/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("failed to create HTTP client: {e}"))?;

        Ok(Self { inner })
    }

    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }

    /// Загружает тело ответа как текст. `label` попадает в логи и ошибки;
    /// URL в текст ошибки не включается, потому что в query могут быть секреты.
    pub async fn get_text(&self, label: &str, url: &str) -> Result<String, String> {
        let resp = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(http_err(label, "request"))?
            .error_for_status()
            .map_err(http_err(label, "status"))?;

        let status = resp.status();
        let body = resp.text().await.map_err(http_err(label, "body"))?;
        debug!(%status, bytes = body.len(), source = label, "http document fetched");

        Ok(body)
    }
}

fn http_err<'a>(label: &'a str, stage: &'static str) -> impl Fn(reqwest::Error) -> String + 'a {
    move |e| format!("{label} {stage} failed: {}", e.without_url())
}
