use super::*;

/// How often End re-checks for in-flight Sets to settle
pub(super) const END_QUIESCENCE_POLL_MS: u32 = 50;
/// Least time between commit round starts, so a round that fails fast does not spin
pub(super) const COMMIT_ROUND_MIN_INTERVAL_MS: u32 = 1_000;

/// Frequency to flush record stores to disk
pub const FLUSH_RECORD_STORES_INTERVAL_SECS: u32 = 1;
/// Frequency to check whether a metadata save is due
pub const SAVE_METADATA_CHECK_INTERVAL_SECS: u32 = 1;
/// Frequency to check for offline subkeys writes to send to the network
pub const OFFLINE_SUBKEY_WRITES_INTERVAL_SECS: u32 = 1;
/// Total number of offline subkey write requests to process in parallel
pub const OFFLINE_SUBKEY_WRITES_BATCH_SIZE: usize = 16;
/// Number of subkeys per offline subkey write keys to process in a chunk
pub const OFFLINE_SUBKEY_WRITES_SUBKEY_CHUNK_SIZE: u64 = 4;
/// Frequency to send ValueChanged notifications to the network
pub const SEND_VALUE_CHANGES_INTERVAL_SECS: u32 = 1;
/// Frequency to check for dead nodes and routes for client-side outbound watches
pub const CHECK_OUTBOUND_WATCHES_INTERVAL_SECS: u32 = 1;
/// Frequency to reconcile watches that are at consensus
pub const RECONCILE_OUTBOUND_WATCHES_INTERVAL: TimestampDuration = TimestampDuration::new_secs(60);
/// Frequency to retry reconciliation of watches that are not at consensus
pub const RECONCILE_OUTBOUND_WATCHES_RETRY_INTERVAL: TimestampDuration =
    TimestampDuration::new_secs(5);
/// How long before expiration to try to renew per-node watches
pub const RENEW_OUTBOUND_WATCHES_DURATION: TimestampDuration = TimestampDuration::new_secs(30);
/// Frequency to check for expired server-side watched records
pub const CHECK_INBOUND_WATCHES_INTERVAL_SECS: u32 = 1;
/// Frequency to check for expired client-side transactions
pub const CHECK_OUTBOUND_TRANSACTIONS_INTERVAL_SECS: u32 = 1;
/// Multiplier applied to rpc_timeout_ms to derive the server-side transaction TTL
pub const TRANSACTION_TIMEOUT_RPC_MULTIPLIER: u64 = 2;
/// Multiplier applied to a node's RTT to derive a post-consensus deadline (capped at `rpc.timeout_ms`)
pub const POST_CONSENSUS_RTT_FACTOR: u64 = 3;
/// Hard cap on the post-consensus collection window, which is for the answer wave trailing
/// consensus; under congested RTTs the RTT factor alone degenerates toward the rpc timeout
/// and waits on dead stragglers
pub const POST_CONSENSUS_GRACE_MS: u64 = 500;
/// How long a Background transaction begin queues on the record lock before
/// yielding TryAgain to the caller's retry loop
pub const BACKGROUND_BEGIN_LOCK_TIMEOUT_MS: u64 = 2000;
/// Headroom beyond `consensus_count` (= `set_value_count`) that Begin aims for, as a percentage rounded up
pub const CONSENSUS_TRIM_PERCENT: usize = 50;
/// Frequency to check for expired server-side transactions
pub const CHECK_INBOUND_TRANSACTIONS_INTERVAL_SECS: u32 = 1;
/// Frequency to process record rehydration requests
pub const REHYDRATE_RECORDS_INTERVAL_SECS: u32 = 1;
/// Number of rehydration requests to process in parallel
pub const REHYDRATE_BATCH_SIZE: usize = 16;
/// Maximum rehydration requests to start per tick
pub const REHYDRATE_REQUESTS_PER_TICK: usize = 4;
/// Number of subkey sets to push in parallel during transactional rehydration
pub const REHYDRATE_SET_CONCURRENCY: usize = 8;
/// How often to change inspect a watch that is wanted but has never established. Reconcile
/// is already retrying establishment, and until it lands this interval is delivery latency,
/// so it matches an established watch's longest fallback wait
pub const UNESTABLISHED_WATCH_INSPECT_INTERVAL: TimestampDuration =
    TimestampDuration::new_secs(120);
/// Delay before retrying a failed change inspection
pub const CHANGE_INSPECT_RETRY_INTERVAL: TimestampDuration = TimestampDuration::new_secs(5);
/// How long after foreground transaction activity background transactions stay deferred
pub const BACKGROUND_TRANSACTION_QUIET_INTERVAL: TimestampDuration = TimestampDuration::new_secs(5);
/// Length of descriptor cache (512 records and 5 nodes per record, roughly 184320 bytes)
pub const DESCRIPTOR_CACHE_SIZE: usize = 2560;
/// How long a completed rehydration check answers for a record, so a reopen
/// within the interval does not enqueue another one
pub const REHYDRATE_RECHECK_INTERVAL: TimestampDuration = TimestampDuration::new_secs(300);
/// Records worth of remembered rehydration checks
pub const REHYDRATION_CHECKED_CACHE_SIZE: usize = 1024;
/// Consecutive hard rehydration failures on one record before it earns a warning
pub const REHYDRATION_FAILURE_WARN_THRESHOLD: u32 = 3;
/// Table store table for storage manager metadata
pub const STORAGE_MANAGER_METADATA: &str = "storage_manager_metadata";
/// Storage manager metadata key name for offline subkey write persistence
pub const OFFLINE_SUBKEY_WRITES: &[u8] = b"offline_subkey_writes";
/// Outbound watch manager metadata key name for watch persistence
pub const OUTBOUND_WATCH_MANAGER: &[u8] = b"outbound_watch_manager";
/// Rehydration requests metadata key name for rehydration persistence
pub const REHYDRATION_REQUESTS: &[u8] = b"rehydration_requests";
/// Descriptor cache metadata key name for persistence
pub const DESCRIPTOR_CACHE: &[u8] = b"descriptor_cache";
/// Remote store connection pool divisor
pub const REMOTE_POOL_CONCURRENCY_DIVISOR: usize = 4;

// --- Outbound Transaction Manager Constants ---

/// Floor of the keepalive interval as a fraction (1/N) of the server-side TTL.
pub const KEEPALIVE_INTERVAL_FLOOR_TTL_FRACTION: u64 = 10;
/// Ceiling of the keepalive interval as a fraction (1/N) of the server-side TTL.
pub const KEEPALIVE_INTERVAL_CEILING_TTL_FRACTION: u64 = 3;
/// Number of RTTs of safety the next reply should land before server expiration.
pub const KEEPALIVE_SAFETY_RTT_FACTOR: u64 = 3;
