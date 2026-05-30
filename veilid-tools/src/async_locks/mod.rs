//! Debuggable Async Locks
use super::*;

mod async_keyed_cache;
mod async_mutex;
mod async_rw_lock;
mod async_semaphore;
mod async_tag_lock;
#[cfg(feature = "debug-locks")]
mod debug_locks;

pub use async_keyed_cache::*;
pub use async_mutex::*;
pub use async_rw_lock::*;
pub use async_semaphore::*;
pub use async_tag_lock::*;

#[cfg(feature = "debug-locks")]
use debug_locks::*;

pub const DEBUG_LOCKS_DURATION_MS: u32 = 30000;

/// Acquisition backtrace for deadlock reports. Opt in with VEILID_DEBUG_LOCK_BACKTRACES=1; off by
/// default because capturing one per lock acquire is expensive and detection (acquire timeouts)
/// fires regardless. Unresolved so symbolication is deferred to the report site.
#[cfg(feature = "debug-locks")]
pub(crate) fn debug_lock_backtrace() -> backtrace::Backtrace {
    use std::sync::LazyLock;
    static ENABLED: LazyLock<bool> =
        LazyLock::new(|| std::env::var("VEILID_DEBUG_LOCK_BACKTRACES").is_ok_and(|v| v != "0"));
    if *ENABLED {
        backtrace::Backtrace::new_unresolved()
    } else {
        backtrace::Backtrace::from(Vec::new())
    }
}
