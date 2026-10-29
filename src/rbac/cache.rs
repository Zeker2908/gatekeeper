use super::{
    model::RuleSet,
    source::{RulesSource, RulesSourceError},
};
use crate::refresh::spawn_every;
use arc_swap::ArcSwapOption;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Default)]
pub struct RulesCache {
    inner: ArcSwapOption<RuleSet>,
}

impl RulesCache {
    /// Загружает снапшот правил до старта сервера: возвращает кэш только
    /// в полностью инициализированном состоянии, либо ошибку загрузки.
    pub async fn load<S: RulesSource>(source: &S) -> Result<Self, RulesSourceError> {
        let cache = Self::default();
        refresh(&cache, source).await?;
        Ok(cache)
    }

    pub fn get(&self) -> Option<Arc<RuleSet>> {
        self.inner.load_full()
    }
    pub fn is_loaded(&self) -> bool {
        self.inner.load().is_some()
    }
    pub fn set(&self, rules: RuleSet) {
        self.inner.store(Some(Arc::new(rules)))
    }
}

pub async fn refresh<S: RulesSource>(
    cache: &RulesCache,
    source: &S,
) -> Result<(), RulesSourceError> {
    let started = std::time::Instant::now();

    let rules = source
        .load()
        .await
        .inspect_err(|e| {
            warn!(error = %e, had_snapshot = cache.is_loaded(), "rules refresh failed, keeping previous snapshot");
        })?;

    let roles = rules.roles.len();
    let endpoints: usize = rules.roles.values().map(Vec::len).sum();
    let public_endpoints = rules.public.len();

    cache.set(rules);
    info!(
        roles,
        endpoints,
        public_endpoints,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "rules refreshed"
    );

    Ok(())
}

pub fn spawn_refresh_loop<S>(
    cache: Arc<RulesCache>,
    source: Arc<S>,
    period: Duration,
) -> tokio::task::JoinHandle<()>
where
    S: RulesSource + Send + Sync + 'static,
{
    spawn_every("rules", period, move || {
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
    use crate::rbac::model::Endpoint; // ПОДСТРОЙ путь
    use axum::http::Method;
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;

    // ---------- хелперы ----------

    /// RuleSet с одной ролью и одним правилом
    fn rules(role: &str, method: &str, path: &str) -> RuleSet {
        let ep = Endpoint::new(method, path).unwrap();
        let mut roles = HashMap::new();
        roles.insert(role.to_string(), vec![ep]);
        RuleSet {
            roles,
            public: vec![],
        }
    }

    fn allowed(rs: &RuleSet, role: &str, method: &Method, path: &str) -> bool {
        rs.is_allowed(&[role.to_string()], method, path)
    }

    fn error(message: &str) -> RulesSourceError {
        RulesSourceError::Http(message.to_string())
    }

    struct FakeSource {
        queue: Arc<Mutex<VecDeque<Result<RuleSet, RulesSourceError>>>>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        notify: Arc<tokio::sync::Notify>,
    }

    impl FakeSource {
        fn new(items: Vec<Result<RuleSet, RulesSourceError>>) -> Self {
            Self {
                queue: Arc::new(Mutex::new(VecDeque::from(items))),
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                notify: Arc::new(tokio::sync::Notify::new()),
            }
        }

        async fn wait_for_calls(&self, expected: usize) {
            loop {
                let notified = self.notify.notified();

                if self.calls.load(std::sync::atomic::Ordering::SeqCst) >= expected {
                    return;
                }

                notified.await;
            }
        }
    }

    impl Clone for FakeSource {
        fn clone(&self) -> Self {
            Self {
                queue: self.queue.clone(),
                calls: self.calls.clone(),
                notify: self.notify.clone(),
            }
        }
    }

    impl RulesSource for FakeSource {
        async fn load(&self) -> Result<RuleSet, RulesSourceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.notify.notify_one();

            self.queue
                .lock()
                .unwrap()
                .pop_front()
                .expect("FakeSource: очередь результатов пуста")
        }
    }

    // ---------- RulesCache ----------

    #[test]
    fn new_cache_is_empty() {
        let c = RulesCache::default();
        assert!(!c.is_loaded());
        assert!(c.get().is_none());
    }

    #[test]
    fn default_cache_is_empty() {
        let c = RulesCache::default();
        assert!(!c.is_loaded());
        assert!(c.get().is_none());
    }

    #[test]
    fn set_makes_cache_loaded() {
        let c = RulesCache::default();
        c.set(rules("user", "GET", "/a"));
        assert!(c.is_loaded());

        let snap = c.get().expect("после set должен быть снимок");
        assert!(allowed(&snap, "user", &Method::GET, "/a"));
        assert!(!allowed(&snap, "user", &Method::GET, "/b"));
    }

    #[test]
    fn get_returns_same_allocation() {
        let c = RulesCache::default();
        c.set(rules("user", "GET", "/a"));

        let a = c.get().unwrap();
        let b = c.get().unwrap();
        assert!(Arc::ptr_eq(&a, &b), "get() не должен копировать RuleSet");
    }

    #[test]
    fn set_replaces_snapshot_and_old_holders_keep_old() {
        let c = RulesCache::default();
        c.set(rules("user", "GET", "/old"));
        let old = c.get().unwrap();

        c.set(rules("user", "GET", "/new"));
        let new = c.get().unwrap();

        assert!(!Arc::ptr_eq(&old, &new));
        // тот, кто взял снимок раньше, видит старые правила
        assert!(allowed(&old, "user", &Method::GET, "/old"));
        assert!(!allowed(&old, "user", &Method::GET, "/new"));
        // новые читатели видят новые
        assert!(allowed(&new, "user", &Method::GET, "/new"));
        assert!(!allowed(&new, "user", &Method::GET, "/old"));
    }

    #[test]
    fn concurrent_readers_see_consistent_snapshots() {
        let cache = Arc::new(RulesCache::default());
        cache.set(rules("user", "GET", "/a"));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let c = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        let snap = c.get().expect("снимок загружен");
                        // снимок целиком старый (/a) или целиком новый (/b), смеси не бывает
                        let a = allowed(&snap, "user", &Method::GET, "/a");
                        let b = allowed(&snap, "user", &Method::GET, "/b");
                        assert_ne!(a, b);
                    }
                })
            })
            .collect();

        for i in 0..200 {
            let p = if i % 2 == 0 { "/b" } else { "/a" };
            cache.set(rules("user", "GET", p));
        }
        for r in readers {
            r.join().unwrap();
        }
    }

    // ---------- refresh ----------

    #[tokio::test]
    async fn refresh_publishes_rules_on_success() {
        let cache = RulesCache::default();
        let src = FakeSource::new(vec![Ok(rules("user", "GET", "/a"))]);

        assert!(refresh(&cache, &src).await.is_ok());

        assert!(cache.is_loaded());
        let snap = cache.get().unwrap();
        assert!(allowed(&snap, "user", &Method::GET, "/a"));
    }

    #[tokio::test]
    async fn refresh_error_on_empty_cache_keeps_it_empty() {
        let cache = RulesCache::default();
        let src = FakeSource::new(vec![Err(error("boom"))]);

        let err = refresh(&cache, &src).await.unwrap_err();
        assert_eq!(err.to_string(), "boom");

        assert!(!cache.is_loaded());
        assert!(cache.get().is_none());
    }

    #[tokio::test]
    async fn refresh_error_keeps_previous_snapshot() {
        let cache = RulesCache::default();
        cache.set(rules("user", "GET", "/old"));
        let before = cache.get().unwrap();

        let src = FakeSource::new(vec![Err(error("boom"))]);
        let err = refresh(&cache, &src).await.unwrap_err();
        assert_eq!(err.to_string(), "boom");

        let after = cache.get().unwrap();
        assert!(
            Arc::ptr_eq(&before, &after),
            "снимок не должен меняться при ошибке"
        );
        assert!(allowed(&after, "user", &Method::GET, "/old"));
    }

    #[tokio::test]
    async fn refresh_replaces_previous_snapshot() {
        let cache = RulesCache::default();
        let src = FakeSource::new(vec![
            Ok(rules("user", "GET", "/v1")),
            Ok(rules("user", "GET", "/v2")),
        ]);

        refresh(&cache, &src).await.unwrap();
        refresh(&cache, &src).await.unwrap();

        let snap = cache.get().unwrap();
        assert!(allowed(&snap, "user", &Method::GET, "/v2"));
        assert!(!allowed(&snap, "user", &Method::GET, "/v1"));
    }

    #[tokio::test]
    async fn refresh_recovers_after_error() {
        let cache = RulesCache::default();
        let src = FakeSource::new(vec![
            Err(error("temporary")),
            Ok(rules("user", "GET", "/a")),
        ]);

        assert!(refresh(&cache, &src).await.is_err());
        assert!(!cache.is_loaded());

        assert!(refresh(&cache, &src).await.is_ok());
        assert!(cache.is_loaded());
    }

    #[tokio::test]
    async fn load_returns_ready_cache() {
        let src = FakeSource::new(vec![Ok(rules("user", "GET", "/a"))]);

        let cache = RulesCache::load(&src).await.unwrap();

        assert!(cache.is_loaded());
        assert!(allowed(&cache.get().unwrap(), "user", &Method::GET, "/a"));
    }

    #[tokio::test]
    async fn load_returns_error_instead_of_empty_cache() {
        let src = FakeSource::new(vec![Err(error("boom"))]);

        let err = RulesCache::load(&src)
            .await
            .err()
            .expect("load should return an error");
        assert_eq!(err.to_string(), "boom");
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_loop_updates_rules_and_keeps_snapshot_on_error() {
        use tokio::time::advance;

        let cache = Arc::new(RulesCache::default());
        let period = Duration::from_secs(10);
        let source = FakeSource::new(vec![
            Ok(rules("user", "GET", "/v1")),
            Ok(rules("user", "GET", "/v2")),
            Err(error("source unavailable")),
        ]);

        // Начальная загрузка: v1.
        refresh(&cache, &source).await.unwrap();

        let snap = cache.get().unwrap();
        assert!(allowed(&snap, "user", &Method::GET, "/v1"));

        let task = spawn_refresh_loop(cache.clone(), Arc::new(source.clone()), period);

        // Даём фоновой задаче обработать первый тик интервала.
        tokio::task::yield_now().await;

        // Первое обновление: v2.
        advance(period).await;
        source.wait_for_calls(2).await;

        let snap = cache.get().unwrap();
        assert!(allowed(&snap, "user", &Method::GET, "/v2"));
        assert!(!allowed(&snap, "user", &Method::GET, "/v1"));

        // Второе обновление завершится ошибкой.
        advance(period).await;
        source.wait_for_calls(3).await;

        let snap = cache.get().unwrap();
        assert!(allowed(&snap, "user", &Method::GET, "/v2"));
        assert!(!allowed(&snap, "user", &Method::GET, "/v1"));

        task.abort();
    }
}
