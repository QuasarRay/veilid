use super::*;
use crate::network_manager::network::native::webtransport_state::spawn_tracked_flush;
use std::sync::atomic::{AtomicBool, Ordering};

pub async fn test_tracked_flush_is_cancelled_and_joined_at_shutdown() {
    let startup_lock = StartupLock::new();
    startup_lock.startup().expect("startup").success();

    struct SetOnDrop(Arc<AtomicBool>);
    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let marker = SetOnDrop(cancelled.clone());
    // Signals on first poll, so the test can wait for the flush to actually be running rather than guessing with a sleep.
    let polling_started = Eventual::new();
    let polled = polling_started.instance_empty();
    let flush = async move {
        let _marker = marker;
        polling_started.resolve().await;
        std::future::pending::<()>().await;
    };

    spawn_tracked_flush(&startup_lock, "test flush", flush);
    timeout(3_000, polled)
        .await
        .expect("the flush future was never polled (executor starved?)");

    let shutdown = timeout(3_000, startup_lock.shutdown())
        .await
        .expect("shutdown blocked past the grace (stop-token cancellation failed)");
    shutdown.expect("shutdown state").success();

    assert!(
        cancelled.load(Ordering::SeqCst),
        "the tracked flush was not cancelled/joined at shutdown"
    );
}

pub fn test_tracked_flush_dropped_when_not_started() {
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let startup_lock = StartupLock::new();
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let marker = SetOnDrop(cancelled.clone());
        let flush = async move {
            let _marker = marker;
        };
        spawn_tracked_flush(&startup_lock, "test flush", flush);
    }
    assert!(
        cancelled.load(Ordering::SeqCst),
        "flush should be dropped when the lock is not started"
    );
}
