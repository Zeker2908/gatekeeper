use std::future::Future;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tracing::debug;

/// Запускает периодическое выполнение `task` раз в `period`.
///
/// Первое срабатывание происходит через `period`, а не сразу: начальная
/// загрузка выполняется отдельно и синхронно, до старта сервера.
/// `MissedTickBehavior::Delay` не даёт накапливать пропущенные тики.
pub fn spawn_every<F, Fut>(name: &'static str, period: Duration, mut task: F) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        debug!(
            task = name,
            period_secs = period.as_secs(),
            "periodic task started"
        );

        // `interval` выдаёт первый тик немедленно — пропускаем его.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            task().await;
        }
    })
}
