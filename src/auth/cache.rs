use crate::auth::jwks::{JwksError, JwksSource};
use crate::auth::jwt::VerifyKey;
use crate::refresh::spawn_every;
use arc_swap::ArcSwapOption;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Default)]
pub struct JwksCache {
    keys: ArcSwapOption<HashMap<String, Arc<VerifyKey>>>,
}

impl JwksCache {
    /// Загружает набор ключей до старта сервера: возвращает кэш только
    /// в полностью инициализированном состоянии, либо ошибку загрузки.
    pub async fn load<S: JwksSource>(source: &S) -> Result<Self, JwksError> {
        let cache = Self::default();
        refresh(&cache, source).await?;
        Ok(cache)
    }

    pub fn find(&self, kid: &str) -> Option<Arc<VerifyKey>> {
        self.keys.load().as_ref()?.get(kid).cloned()
    }
    pub fn is_loaded(&self) -> bool {
        self.keys.load().is_some()
    }
    pub fn set(&self, keys: HashMap<String, VerifyKey>) {
        let keys: HashMap<String, Arc<VerifyKey>> = keys
            .into_iter()
            .map(|(kid, key)| (kid, Arc::new(key)))
            .collect();
        self.keys.store(Some(Arc::new(keys)))
    }

    #[cfg(test)]
    fn snapshot(&self) -> Option<Arc<HashMap<String, Arc<VerifyKey>>>> {
        self.keys.load_full()
    }
}
pub async fn refresh<S: JwksSource>(cache: &JwksCache, source: &S) -> Result<(), JwksError> {
    let started = std::time::Instant::now();

    let jwks = source
        .fetch()
        .await
        .inspect_err(|e| {
            warn!(error = %e, had_snapshot = cache.is_loaded(), "jwks refresh failed, keeping previous snapshot");
        })?;

    let keys_count = jwks.len();

    cache.set(jwks);
    info!(
        keys_count,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "jwks refreshed"
    );

    Ok(())
}

pub fn spawn_refresh_loop_jwks<S>(
    cache: Arc<JwksCache>,
    source: Arc<S>,
    period: Duration,
) -> tokio::task::JoinHandle<()>
where
    S: JwksSource + Send + Sync + 'static,
{
    spawn_every("jwks", period, move || {
        let cache = Arc::clone(&cache);
        let source = Arc::clone(&source);
        async move {
            let _ = refresh(&cache, &*source).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtValidator;
    use jsonwebtoken::{Algorithm, DecodingKey};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key() -> VerifyKey {
        JwtValidator::new("test-issuer", "test-audience")
            .bind(Algorithm::HS256, DecodingKey::from_secret(b"test-secret"))
    }

    fn keys(kid: &str) -> HashMap<String, VerifyKey> {
        HashMap::from([(kid.to_string(), key())])
    }

    fn error(message: &str) -> JwksError {
        JwksError::Http(message.to_string())
    }

    struct FakeSource {
        queue: Mutex<VecDeque<Result<HashMap<String, VerifyKey>, JwksError>>>,
        calls: AtomicUsize,
    }

    impl FakeSource {
        fn new(items: Vec<Result<HashMap<String, VerifyKey>, JwksError>>) -> Self {
            Self {
                queue: Mutex::new(VecDeque::from(items)),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl JwksSource for FakeSource {
        async fn fetch(&self) -> Result<HashMap<String, VerifyKey>, JwksError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.queue
                .lock()
                .unwrap()
                .pop_front()
                .expect("FakeSource: очередь результатов пуста")
        }
    }

    // ---------- JwksCache ----------

    #[test]
    fn new_cache_is_empty() {
        let cache = JwksCache::default();

        assert!(!cache.is_loaded());
        assert!(cache.find("key-1").is_none());
    }

    #[test]
    fn default_cache_is_empty() {
        let cache = JwksCache::default();

        assert!(!cache.is_loaded());
        assert!(cache.find("key-1").is_none());
    }

    #[test]
    fn set_makes_cache_loaded() {
        let cache = JwksCache::default();
        cache.set(keys("key-1"));

        assert!(cache.is_loaded());
        assert!(cache.find("key-1").is_some());
        assert!(cache.find("unknown").is_none());
    }

    #[test]
    fn find_returns_same_key_allocation() {
        let cache = JwksCache::default();
        cache.set(keys("key-1"));

        let first = cache.find("key-1").unwrap();
        let second = cache.find("key-1").unwrap();

        assert!(
            Arc::ptr_eq(&first, &second),
            "find() не должен копировать VerifyKey"
        );
    }

    #[test]
    fn set_replaces_snapshot_and_old_holders_keep_old_key() {
        let cache = JwksCache::default();
        cache.set(keys("key-old"));

        let old = cache.find("key-old").unwrap();

        cache.set(keys("key-new"));

        let new = cache.find("key-new").unwrap();

        assert!(cache.find("key-old").is_none());
        assert!(!Arc::ptr_eq(&old, &new));
        // Старый ключ остаётся доступен через ранее полученный Arc.
        assert!(Arc::strong_count(&old) >= 1);
    }

    #[test]
    fn concurrent_readers_see_consistent_snapshots() {
        let cache = Arc::new(JwksCache::default());
        cache.set(keys("key-a"));

        let writer_cache = Arc::clone(&cache);
        let writer = std::thread::spawn(move || {
            for i in 0..10_000 {
                writer_cache.set(keys(if i % 2 == 0 { "key-a" } else { "key-b" }));
            }
        });

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        let snapshot = cache.snapshot().unwrap();
                        assert_eq!(snapshot.len(), 1);
                        assert!(
                            snapshot.contains_key("key-a") ^ snapshot.contains_key("key-b"),
                            "snapshot должен содержать ровно один ожидаемый ключ"
                        );
                    }
                })
            })
            .collect();

        writer.join().unwrap();
        for reader in readers {
            reader.join().unwrap();
        }
    }

    // ---------- refresh_jwks ----------

    #[tokio::test]
    async fn refresh_publishes_keys_on_success() {
        let cache = JwksCache::default();
        let source = FakeSource::new(vec![Ok(keys("key-1"))]);

        assert!(refresh(&cache, &source).await.is_ok());

        assert!(cache.is_loaded());
        assert!(cache.find("key-1").is_some());
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_error_on_empty_cache_keeps_it_empty() {
        let cache = JwksCache::default();
        let source = FakeSource::new(vec![Err(error("boom"))]);

        let err = refresh(&cache, &source).await.unwrap_err();
        assert_eq!(err.to_string(), "boom");

        assert!(!cache.is_loaded());
        assert!(cache.find("key-1").is_none());
    }

    #[tokio::test]
    async fn refresh_error_keeps_previous_snapshot() {
        let cache = JwksCache::default();
        cache.set(keys("key-1"));

        let before = cache.find("key-1").unwrap();
        let source = FakeSource::new(vec![Err(error("boom"))]);

        let err = refresh(&cache, &source).await.unwrap_err();
        assert_eq!(err.to_string(), "boom");

        let after = cache.find("key-1").unwrap();
        assert!(Arc::ptr_eq(&before, &after));
    }

    #[tokio::test]
    async fn refresh_replaces_previous_snapshot() {
        let cache = JwksCache::default();
        let source = FakeSource::new(vec![Ok(keys("key-v1")), Ok(keys("key-v2"))]);

        refresh(&cache, &source).await.unwrap();
        refresh(&cache, &source).await.unwrap();

        assert!(cache.find("key-v1").is_none());
        assert!(cache.find("key-v2").is_some());
    }

    #[tokio::test]
    async fn refresh_recovers_after_error() {
        let cache = JwksCache::default();
        let source = FakeSource::new(vec![Err(error("temporary")), Ok(keys("key-1"))]);

        assert!(refresh(&cache, &source).await.is_err());
        assert!(!cache.is_loaded());

        assert!(refresh(&cache, &source).await.is_ok());
        assert!(cache.is_loaded());
        assert!(cache.find("key-1").is_some());
    }

    #[tokio::test]
    async fn load_returns_ready_cache() {
        let source = FakeSource::new(vec![Ok(keys("key-1"))]);

        let cache = JwksCache::load(&source).await.unwrap();

        assert!(cache.is_loaded());
        assert!(cache.find("key-1").is_some());
    }

    #[tokio::test]
    async fn load_returns_error_instead_of_empty_cache() {
        let source = FakeSource::new(vec![Err(error("boom"))]);

        let err = JwksCache::load(&source)
            .await
            .err()
            .expect("load should return an error");
        assert_eq!(err.to_string(), "boom");
    }
}
