mod close_record;
mod constants;
mod create_record;
#[cfg_attr(not(feature = "debug-api"), expect(dead_code))]
mod debug;
mod delete_record;
mod flush_record;
mod gated_operation;
#[cfg(feature = "stats")]
mod gated_operation_accounting;
mod get_value;
mod inspect_record;
mod local_record_detail;
mod local_record_store_interface;
mod offline_subkey_writes;
mod open_record;
mod outbound_transaction_manager;
mod outbound_watch_manager;
mod record_encryption;
mod record_key;
mod record_lock_table;
mod record_store;
mod rehydrate;
mod remote_record_detail;
mod schema;
mod set_value;
#[cfg(feature = "stats")]
mod stats;
mod storage_manager_locks;
mod tasks;
mod transaction;
mod transaction_begin;
mod transaction_command;
mod types;
mod watch_value;

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "test support: printing and raw clocks are the thing under test"
)]
pub mod tests_storage_manager;

use super::*;

use hashlink::{LinkedHashMap, LruCache};
use std::sync::atomic::{AtomicU64, AtomicUsize};

use crate::network_manager::OnlineState;
use constants::*;
use gated_operation::*;
#[cfg(feature = "stats")]
use gated_operation_accounting::*;
use inspect_record::{InspectFanoutStop, OutboundInspectValueResult};
use local_record_detail::*;
use offline_subkey_writes::*;
use outbound_transaction_manager::*;
use outbound_watch_manager::*;
use record_lock_table::*;
use record_store::*;
use rehydrate::*;
use remote_record_detail::*;
use routing_table::*;
use rpc_processor::*;
use stop_token::future::FutureExt as _;
use storage_manager_locks::*;

pub(crate) use constants::STORAGE_MANAGER_METADATA;
pub(crate) use get_value::InboundGetValueResult;
pub(crate) use inspect_record::InboundInspectValueResult;
pub(crate) use outbound_transaction_manager::OutboundTransactionHandle;
pub(crate) use set_value::InboundSetValueResult;
use set_value::{SeqAssignment, SeqReuse};
pub(crate) use transaction_begin::{InboundTransactBeginResult, TransactBeginSuccess};
pub(crate) use transaction_command::{InboundTransactCommandResult, TransactCommandSuccess};
pub(crate) use watch_value::{InboundWatchParameters, InboundWatchValueResult};

pub use types::*;

impl_veilid_log_facility!("stor");

#[derive(Debug, Clone)]
/// A single 'value changed' message to send
struct ValueChangedInfo {
    target: Target,
    record_key: OpaqueRecordKey,
    subkeys: ValueSubkeyRangeSet,
    count: u32,
    watch_id: InboundWatchId,
    value: Option<Arc<SignedValueData>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
/// Which nodes have had which record descriptors sent to them
struct DescriptorCacheKey {
    opaque_record_key: OpaqueRecordKey,
    node_id: NodeId,
}

/// Locked structure for storage manager
struct StorageManagerInner {
    /// Records that have been 'opened' and are not yet closed
    pub opened_records: HashMap<OpaqueRecordKey, OpenedRecord>,
    /// Records that have ever been 'created' or 'opened' by this node, things we care about that we must republish to keep alive
    pub local_record_store: Option<RecordStore<LocalRecordDetail>>,
    /// Records that have been pushed to this node for distribution by other nodes, that we make an effort to republish
    pub remote_record_store: Option<RecordStore<RemoteRecordDetail>>,
    /// Record subkeys to commit to the network in the background,
    /// either because they were written to offline, or due to a rehydration action
    pub offline_subkey_writes: LinkedHashMap<OpaqueRecordKey, OfflineSubkeyWrite>,
    /// Records that have pending rehydration requests
    pub rehydration_requests: HashMap<OpaqueRecordKey, RehydrationRequest>,
    /// Records created by this node this session. Everything in them was just
    /// written with consensus, so opening them skips the rehydration check.
    pub locally_created_records: HashSet<OpaqueRecordKey>,
    /// StopSources for callers waiting on flush_record; dropped when offline writes for a key drain
    pub flush_record_waiters: HashMap<OpaqueRecordKey, Vec<StopSource>>,
    /// State management for outbound transactions
    pub outbound_transaction_manager: OutboundTransactionManager,
    /// Storage manager metadata that is persistent, including copy of offline subkey writes
    pub metadata_db: Option<TableDB>,
    /// Routing domain ready subscription (drives the DHT-online gate)
    pub routing_domain_ready_subscription: Option<EventBusSubscription>,
    pub online_state_change_subscription: Option<EventBusSubscription>,
    /// Tick subscription
    pub tick_subscription: Option<EventBusSubscription>,
    /// Network stats change subscription
    pub network_stats_change_subscription: Option<EventBusSubscription>,
}

impl fmt::Debug for StorageManagerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageManagerInner")
            // .field("unlocked_inner", &self.unlocked_inner)
            .field("opened_records", &self.opened_records)
            .field("local_record_store", &self.local_record_store)
            .field("remote_record_store", &self.remote_record_store)
            .field("offline_subkey_writes", &self.offline_subkey_writes)
            .field("rehydration_requests", &self.rehydration_requests)
            .field(
                "outbound_transaction_manager",
                &self.outbound_transaction_manager,
            )
            .field(
                "routing_domain_ready_subscription",
                &self.routing_domain_ready_subscription,
            )
            .field(
                "online_state_change_subscription",
                &self.online_state_change_subscription,
            )
            //.field("metadata_db", &self.metadata_db)
            //.field("tick_subscription", &self.tick_subscription)
            .finish()
    }
}

pub(crate) struct StorageManager {
    registry: VeilidComponentRegistry,
    inner: StatsMutex<StorageManagerInner>,
    /// Outbound watch state, on its own lock so the watch sweeps and every inbound
    /// ValueChanged stop queueing behind record operations. Lock order: record lock,
    /// then `inner`, then this; never take `inner` while holding it.
    outbound_watch_manager: StatsMutex<OutboundWatchManager>,
    startup_lock: Arc<StartupLock>,

    // Background processes
    save_metadata_task: TickTask<EyreReport>,
    flush_record_stores_task: TickTask<EyreReport>,
    offline_subkey_writes_task: TickTask<EyreReport>,
    send_value_changes_task: TickTask<EyreReport>,
    check_outbound_watches_task: TickTask<EyreReport>,
    check_inbound_watches_task: TickTask<EyreReport>,
    check_outbound_transactions_task: TickTask<EyreReport>,
    check_inbound_transactions_task: TickTask<EyreReport>,
    rehydrate_records_task: TickTask<EyreReport>,

    // Anonymous watch keys that will be used when watching or transacting on records or we opened without a writer
    anonymous_signing_keys: KeyPairGroup,

    // Record operation lock for local/outbound record operations
    // Keeps changes to records to one-at-a-time per record
    record_lock_table: StorageManagerRecordLockTable,

    // Background operation processor
    // for offline subkey writes, watch changes, and any other
    // background operations the storage manager wants to perform
    background_operation_processor: DeferredStreamProcessor,

    // Cache of which nodes have seen descriptors for which records to optimize outbound set_value and transact_begin operations
    descriptor_cache: Arc<Mutex<LruCache<DescriptorCacheKey, ()>>>,

    // When each record's last rehydration check completed, so an open/close/reopen
    // pattern does not fan out the same check every time (open enqueues one)
    rehydration_checked: Mutex<LruCache<OpaqueRecordKey, Timestamp>>,
    /// Consecutive hard rehydration failures per record subkey, cleared by a
    /// success. Per subkey rather than per record: an unreachable record is
    /// asked for in chunks, and counting the record would read one outage as
    /// a run. `None` is a request for the whole record.
    rehydration_failures: Mutex<LruCache<OpaqueRecordKey, HashMap<Option<ValueSubkey>, u32>>>,

    // Online check
    is_online: AtomicBool,

    // Last foreground transaction activity, including failed begin attempts (usec)
    last_foreground_transaction_ts: AtomicU64,

    // Per-direction byte budgets (adaptive with aimd-dht, never binding
    // without) + a count cap, shared by all DHT network ops. Local-only ops
    // acquire none.
    upload_budget: GatedOperationBandwidthBudget,
    download_budget: GatedOperationBandwidthBudget,
    gated_operation_concurrency: Arc<AsyncSemaphore>,
    // Ops currently admitted through the gate, for telemetry
    gate_active: Arc<AtomicUsize>,
    // Per-kind gate wait/hold telemetry
    #[cfg(feature = "stats")]
    gate_accounting: Arc<Mutex<GatedOperationAccounting>>,
}

impl fmt::Debug for StorageManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageManager")
            .field("registry", &self.registry)
            .field("inner", &self.inner)
            .field("record_lock_table", &self.record_lock_table)
            .field(
                "background_operation_processor",
                &self.background_operation_processor,
            )
            .field("anonymous_signing_keys", &self.anonymous_signing_keys)
            .field("is_online", &self.is_online)
            .field("descriptor_cache", &self.descriptor_cache)
            .finish()
    }
}

impl_veilid_component!(StorageManager, stats);

impl StorageManager {
    pub fn new(registry: VeilidComponentRegistry) -> StorageManager {
        let crypto = registry.crypto();

        // Generate keys to use for signing anonymous watch and transaction operations
        let mut anonymous_signing_keys = KeyPairGroup::new();
        for ck in VALID_CRYPTO_KINDS {
            let vcrypto = crypto.get(ck).unwrap_or_log();
            let kp = vcrypto.generate_keypair();
            anonymous_signing_keys.add(kp);
        }

        let upload_budget = GatedOperationBandwidthBudget::new("up", &registry.config());
        let download_budget = GatedOperationBandwidthBudget::new("down", &registry.config());
        let gated_operation_concurrency = Arc::new(AsyncSemaphore::new(
            (registry.config().network.dht.max_concurrent_operations as usize).max(1),
        ));

        let this = StorageManager {
            inner: StatsMutex::new(
                StorageManagerInner {
                    opened_records: Default::default(),
                    locally_created_records: Default::default(),
                    local_record_store: Default::default(),
                    remote_record_store: Default::default(),
                    offline_subkey_writes: Default::default(),
                    rehydration_requests: Default::default(),
                    flush_record_waiters: Default::default(),
                    outbound_transaction_manager: OutboundTransactionManager::new(registry.clone()),
                    metadata_db: Default::default(),
                    routing_domain_ready_subscription: None,
                    online_state_change_subscription: None,
                    tick_subscription: None,
                    network_stats_change_subscription: None,
                },
                "storage_manager_inner",
            ),
            outbound_watch_manager: StatsMutex::new(Default::default(), "outbound_watch_manager"),
            registry: registry.clone(),
            startup_lock: Arc::new(StartupLock::new()),

            save_metadata_task: TickTask::new("save_metadata_task", SAVE_METADATA_INTERVAL_SECS),
            flush_record_stores_task: TickTask::new(
                "flush_record_stores_task",
                FLUSH_RECORD_STORES_INTERVAL_SECS,
            ),
            offline_subkey_writes_task: TickTask::new(
                "offline_subkey_writes_task",
                OFFLINE_SUBKEY_WRITES_INTERVAL_SECS,
            ),
            send_value_changes_task: TickTask::new(
                "send_value_changes_task",
                SEND_VALUE_CHANGES_INTERVAL_SECS,
            ),
            check_outbound_watches_task: TickTask::new(
                "check_outbound_watches_task",
                CHECK_OUTBOUND_WATCHES_INTERVAL_SECS,
            ),
            check_inbound_watches_task: TickTask::new(
                "check_inbound_watches_task",
                CHECK_INBOUND_WATCHES_INTERVAL_SECS,
            ),
            check_outbound_transactions_task: TickTask::new(
                "check_outbound_transactions_task",
                CHECK_OUTBOUND_TRANSACTIONS_INTERVAL_SECS,
            ),
            check_inbound_transactions_task: TickTask::new(
                "check_inbound_transactions_task",
                CHECK_INBOUND_TRANSACTIONS_INTERVAL_SECS,
            ),
            rehydrate_records_task: TickTask::new(
                "rehydrate_records_task",
                REHYDRATE_RECORDS_INTERVAL_SECS,
            ),
            record_lock_table: StorageManagerRecordLockTable::new(registry.clone()),
            anonymous_signing_keys,
            background_operation_processor: DeferredStreamProcessor::new(),
            is_online: AtomicBool::new(false),
            last_foreground_transaction_ts: AtomicU64::new(0),
            descriptor_cache: Arc::new(Mutex::new(LruCache::new(DESCRIPTOR_CACHE_SIZE))),
            rehydration_checked: Mutex::new(LruCache::new(REHYDRATION_CHECKED_CACHE_SIZE)),
            rehydration_failures: Mutex::new(LruCache::new(REHYDRATION_CHECKED_CACHE_SIZE)),
            upload_budget,
            download_budget,
            gated_operation_concurrency,
            gate_active: Arc::new(AtomicUsize::new(0)),
            #[cfg(feature = "stats")]
            gate_accounting: Arc::new(Mutex::new(GatedOperationAccounting::default())),
        };

        this.setup_tasks();

        this
    }

    pub(crate) fn local_limits_from_config(c: Arc<VeilidConfig>) -> RecordStoreLimits {
        RecordStoreLimits {
            subkey_cache_size: c.network.dht.local_subkey_cache_size as usize,
            max_subkey_size: MAX_SUBKEY_SIZE,
            max_record_data_size: MAX_RECORD_DATA_SIZE,
            max_records: None,
            max_subkey_cache_memory_mb: Some(
                c.network.dht.local_max_subkey_cache_memory_mb as usize,
            ),
            max_storage_space_mb: None,
            public_watch_limit: c.internal().network.dht.public_watch_limit as usize,
            member_watch_limit: c.internal().network.dht.member_watch_limit as usize,
            max_watch_expiration: TimestampDuration::new_ms(
                c.internal().network.dht.max_watch_expiration_ms.into(),
            ),
            min_watch_expiration: TimestampDuration::new_ms(
                c.internal().network.rpc.timeout_ms.into(),
            ),
            public_transaction_limit: c.internal().network.dht.public_transaction_limit as usize,
            member_transaction_limit: c.internal().network.dht.member_transaction_limit as usize,
            transaction_timeout: TimestampDuration::new_ms(
                c.internal().network.rpc.timeout_ms as u64,
            )
            .saturating_mul(TRANSACTION_TIMEOUT_RPC_MULTIPLIER),
            pool_concurrency: 1,
        }
    }

    pub(crate) fn remote_limits_from_config(c: Arc<VeilidConfig>) -> RecordStoreLimits {
        RecordStoreLimits {
            subkey_cache_size: c.network.dht.remote_subkey_cache_size as usize,
            max_subkey_size: MAX_SUBKEY_SIZE,
            max_record_data_size: MAX_RECORD_DATA_SIZE,
            max_records: Some(c.network.dht.remote_max_records as usize),
            max_subkey_cache_memory_mb: Some(
                c.network.dht.remote_max_subkey_cache_memory_mb as usize,
            ),
            max_storage_space_mb: Some(c.network.dht.remote_max_storage_space_mb as usize),
            public_watch_limit: c.internal().network.dht.public_watch_limit as usize,
            member_watch_limit: c.internal().network.dht.member_watch_limit as usize,
            max_watch_expiration: TimestampDuration::new_ms(
                c.internal().network.dht.max_watch_expiration_ms.into(),
            ),
            min_watch_expiration: TimestampDuration::new_ms(
                c.internal().network.rpc.timeout_ms.into(),
            ),
            public_transaction_limit: c.internal().network.dht.public_transaction_limit as usize,
            member_transaction_limit: c.internal().network.dht.member_transaction_limit as usize,
            transaction_timeout: TimestampDuration::new_ms(
                c.internal().network.rpc.timeout_ms as u64,
            )
            .saturating_mul(TRANSACTION_TIMEOUT_RPC_MULTIPLIER),
            pool_concurrency: (get_concurrency() as usize)
                .div_ceil(REMOTE_POOL_CONCURRENCY_DIVISOR),
        }
    }

    fn log_facilities_impl(&self) -> VeilidComponentLogFacilities {
        VeilidComponentLogFacilities::new()
            .with_facility(
                VeilidComponentLogFacility::try_new_with_tags("stor", ["#common"]).unwrap(),
            )
            .with_facility(VeilidComponentLogFacility::try_new("stor::record_index").unwrap())
            .with_facility(VeilidComponentLogFacility::try_new_with_tags("dht", ["#dht"]).unwrap())
            .with_facility(
                VeilidComponentLogFacility::try_new_with_tags("watch", ["#dht"]).unwrap(),
            )
            .with_facility(
                VeilidComponentLogFacility::try_new_with_tags("network_result", ["#verbose"])
                    .unwrap(),
            )
    }

    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip_all, err))]
    async fn init_async(&self) -> EyreResult<()> {
        let guard = self.startup_lock.startup()?;

        veilid_log!(self debug "startup storage manager");
        let table_store = self.table_store();
        let config = self.config();

        let metadata_db = table_store.open(STORAGE_MANAGER_METADATA, 1).await?;

        let local_limits = Self::local_limits_from_config(config.clone());
        let remote_limits = Self::remote_limits_from_config(config.clone());

        let local_record_store = RecordStore::try_new(&table_store, "local", local_limits).await?;
        let remote_record_store =
            RecordStore::try_new(&table_store, "remote", remote_limits).await?;

        {
            let mut inner = self.inner.lock();
            inner.metadata_db = Some(metadata_db);
            inner.local_record_store = Some(local_record_store);
            inner.remote_record_store = Some(remote_record_store);

            // Start up outbound transaction manager
            inner.outbound_transaction_manager.init();

            // Terminal delivery only queues: drop_transaction spawns it while holding
            // the inner lock
            let registry = self.registry();
            inner
                .outbound_transaction_manager
                .set_terminal_delivery_spawner(Box::new(move |delivery| {
                    let registry2 = registry.clone();
                    registry
                        .storage_manager()
                        .background_operation_processor
                        .add_future(delivery.run(registry2));
                }));
        }

        self.load_metadata().await?;

        // Start deferred results processors
        self.background_operation_processor.init();

        guard.success();

        Ok(())
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "tstore", skip_all)
    )]
    #[allow(clippy::unused_async)]
    async fn post_init_async(&self) -> EyreResult<()> {
        // Register event handlers
        let routing_domain_ready_subscription =
            impl_subscribe_event_bus!(self, Self, routing_domain_ready_event_handler);
        let online_state_change_subscription =
            impl_subscribe_event_bus!(self, Self, online_state_change_event_handler);
        let tick_subscription = impl_subscribe_event_bus_async!(self, Self, tick_event_handler);
        let network_stats_change_subscription =
            impl_subscribe_event_bus!(self, Self, network_stats_change_event_handler);

        // Resolve outbound watch manager noderefs
        self.outbound_watch_manager
            .lock()
            .prepare(&self.routing_table());

        let mut inner = self.inner.lock();

        // Schedule tick
        inner.routing_domain_ready_subscription = Some(routing_domain_ready_subscription);
        inner.online_state_change_subscription = Some(online_state_change_subscription);
        inner.tick_subscription = Some(tick_subscription);
        inner.network_stats_change_subscription = Some(network_stats_change_subscription);

        Ok(())
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "tstore", skip_all)
    )]
    #[allow(clippy::unused_async)]
    async fn pre_terminate_async(&self) {
        // Unsubscribe from tickers and shut down outbound transaction manager
        {
            let mut inner = self.inner.lock();
            if let Some(sub) = inner.routing_domain_ready_subscription.take() {
                self.event_bus().unsubscribe(sub);
            }
            if let Some(sub) = inner.online_state_change_subscription.take() {
                self.event_bus().unsubscribe(sub);
            }
            if let Some(sub) = inner.tick_subscription.take() {
                self.event_bus().unsubscribe(sub);
            }
            if let Some(sub) = inner.network_stats_change_subscription.take() {
                self.event_bus().unsubscribe(sub);
            }
        }
    }

    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip_all))]
    async fn terminate_async(&self) {
        veilid_log!(self debug "starting storage manager shutdown");

        // Proceed with shutdown
        let guard = self
            .startup_lock
            .shutdown()
            .await
            .expect_or_log("should be started up");

        // Cancel all tasks associated with the tick future
        self.cancel_tasks().await;

        // Shutdown keepalive processor
        let cleanup = { self.inner.lock().outbound_transaction_manager.terminate() };
        cleanup.await;

        // Stop deferred result processor
        self.background_operation_processor.terminate().await;

        // Terminate and release the storage manager
        let (opt_local_record_store, opt_remote_record_store) = {
            let mut inner = self.inner.lock();
            let opt_local_record_store = inner.local_record_store.take();
            let opt_remote_record_store = inner.remote_record_store.take();
            (opt_local_record_store, opt_remote_record_store)
        };

        // Final flush on record stores
        if let Some(local_record_store) = opt_local_record_store {
            if let Err(e) = local_record_store.flush().await {
                veilid_log!(self error "Error flushing local record store during storage manager shutdown: {}", e);
            }
        }
        if let Some(remote_record_store) = opt_remote_record_store {
            if let Err(e) = remote_record_store.flush().await {
                veilid_log!(self error "Error flushing remote record store during storage manager shutdown: {}", e);
            }
        }

        // Save metadata
        if let Err(e) = self.save_metadata().await {
            veilid_log!(self error "termination metadata save failed: {}", e);
        }

        // Reset inner state
        *self.outbound_watch_manager.lock() = Default::default();
        {
            let mut inner = self.inner.lock();
            *inner = StorageManagerInner {
                outbound_transaction_manager: OutboundTransactionManager::new(self.registry()),
                opened_records: Default::default(),
                locally_created_records: Default::default(),
                local_record_store: Default::default(),
                remote_record_store: Default::default(),
                offline_subkey_writes: Default::default(),
                rehydration_requests: Default::default(),
                flush_record_waiters: Default::default(),
                metadata_db: Default::default(),
                routing_domain_ready_subscription: None,
                online_state_change_subscription: None,
                tick_subscription: None,
                network_stats_change_subscription: None,
            };
        }

        guard.success();

        veilid_log!(self debug "finished storage manager shutdown");
    }

    async fn save_metadata(&self) -> EyreResult<()> {
        let (
            metadata_db,
            offline_subkey_writes_json,
            outbound_watch_manager_json,
            rehydration_requests_json,
            descriptor_cache_json,
        ) = {
            let descriptor_cache = self
                .descriptor_cache
                .lock()
                .iter()
                .map(|x| x.0.clone())
                .collect::<Vec<DescriptorCacheKey>>();

            let inner = self.inner.lock();
            let Some(metadata_db) = inner.metadata_db.clone() else {
                return Ok(());
            };

            let offline_subkey_writes_json = serde_json::to_vec(&inner.offline_subkey_writes)
                .map_err(VeilidAPIError::internal)?;
            let outbound_watch_manager_json =
                serde_json::to_vec(&*self.outbound_watch_manager.lock())
                    .map_err(VeilidAPIError::internal)?;
            let rehydration_requests_json = serde_json::to_vec(&inner.rehydration_requests)
                .map_err(VeilidAPIError::internal)?;
            let descriptor_cache_json =
                serde_json::to_vec(&descriptor_cache).map_err(VeilidAPIError::internal)?;

            (
                metadata_db,
                offline_subkey_writes_json,
                outbound_watch_manager_json,
                rehydration_requests_json,
                descriptor_cache_json,
            )
        };

        let tx = metadata_db.transact();

        tx.store(0, OFFLINE_SUBKEY_WRITES, &offline_subkey_writes_json)
            .await?;
        tx.store(0, OUTBOUND_WATCH_MANAGER, &outbound_watch_manager_json)
            .await?;
        tx.store(0, REHYDRATION_REQUESTS, &rehydration_requests_json)
            .await?;
        tx.store(0, DESCRIPTOR_CACHE, &descriptor_cache_json)
            .await?;

        tx.commit().await.wrap_err("failed to commit")?;

        Ok(())
    }

    async fn load_metadata(&self) -> EyreResult<()> {
        let Some(metadata_db) = self.inner.lock().metadata_db.clone() else {
            bail!("metadata db should exist");
        };

        let offline_subkey_writes = match metadata_db.load_json(0, OFFLINE_SUBKEY_WRITES).await {
            Ok(v) => v.unwrap_or_default(),
            Err(_) => {
                if let Err(e) = metadata_db.delete(0, OFFLINE_SUBKEY_WRITES).await {
                    veilid_log!(self debug "offline_subkey_writes format changed, clearing: {}", e);
                }
                Default::default()
            }
        };
        let outbound_watch_manager = match metadata_db.load_json(0, OUTBOUND_WATCH_MANAGER).await {
            Ok(v) => v.unwrap_or_default(),
            Err(_) => {
                if let Err(e) = metadata_db.delete(0, OUTBOUND_WATCH_MANAGER).await {
                    veilid_log!(self debug "outbound_watch_manager format changed, clearing: {}", e);
                }
                Default::default()
            }
        };

        let rehydration_requests = match metadata_db.load_json(0, REHYDRATION_REQUESTS).await {
            Ok(v) => v.unwrap_or_default(),
            Err(_) => {
                if let Err(e) = metadata_db.delete(0, REHYDRATION_REQUESTS).await {
                    veilid_log!(self debug "rehydration_requests format changed, clearing: {}", e);
                }
                Default::default()
            }
        };
        let descriptor_cache_keys = match metadata_db
            .load_json::<Vec<DescriptorCacheKey>>(0, DESCRIPTOR_CACHE)
            .await
        {
            Ok(v) => v.unwrap_or_default(),
            Err(_) => {
                if let Err(e) = metadata_db.delete(0, DESCRIPTOR_CACHE).await {
                    veilid_log!(self debug "descriptor_cache format changed, clearing: {}", e);
                }
                Default::default()
            }
        };

        {
            let mut inner = self.inner.lock();
            inner.offline_subkey_writes = offline_subkey_writes;
            inner.rehydration_requests = rehydration_requests;
        }
        {
            *self.outbound_watch_manager.lock() = outbound_watch_manager;
        }

        {
            let mut descriptor_cache = self.descriptor_cache.lock();
            descriptor_cache.clear();
            for k in descriptor_cache_keys {
                descriptor_cache.insert(k, ());
            }
        }
        Ok(())
    }

    fn has_offline_subkey_writes(&self) -> bool {
        !self.inner.lock().offline_subkey_writes.is_empty()
    }

    fn has_rehydration_requests(&self) -> bool {
        !self.inner.lock().rehydration_requests.is_empty()
    }

    fn dht_is_online(&self) -> bool {
        self.is_online.load(Ordering::Acquire)
    }

    /// Mark foreground transaction activity, deferring background transactions
    /// for the quiet interval
    fn touch_foreground_transaction_activity(&self) {
        self.last_foreground_transaction_ts
            .store(Timestamp::now_non_decreasing().as_u64(), Ordering::Release);
    }

    /// Background transactions run only when no foreground transaction is active or recent
    fn background_transactions_allowed(&self) -> bool {
        let last_fg_ts =
            Timestamp::new(self.last_foreground_transaction_ts.load(Ordering::Acquire));
        if Timestamp::now_non_decreasing() < last_fg_ts.later(BACKGROUND_TRANSACTION_QUIET_INTERVAL)
        {
            return false;
        }
        !self
            .inner
            .lock()
            .outbound_transaction_manager
            .has_foreground_transaction()
    }

    fn get_local_record_store(&self) -> VeilidAPIResult<RecordStore<LocalRecordDetail>> {
        self.inner
            .lock()
            .local_record_store
            .as_ref()
            .cloned()
            .ok_or_else(VeilidAPIError::not_initialized)
    }

    fn get_remote_record_store(&self) -> VeilidAPIResult<RecordStore<RemoteRecordDetail>> {
        self.inner
            .lock()
            .remote_record_store
            .as_ref()
            .cloned()
            .ok_or_else(VeilidAPIError::not_initialized)
    }

    // Send a value change up through the callback
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "stor", skip(self, value))
    )]
    fn update_callback_value_change(
        &self,
        record_lock: StorageManagerRecordLockGuard,
        record_key: RecordKey,
        subkeys: ValueSubkeyRangeSet,
        count: u32,
        value: Option<ValueData>,
    ) {
        if record_lock.record() != record_key.opaque() {
            veilid_log!(self error "record lock record key mismatch: {} != {}", record_lock.record(), record_key.opaque());
            return;
        }

        // Explicit lock drop to ensure lifetime of lock stops before callback is called
        drop(record_lock);

        let update_callback = self.update_callback();
        update_callback(VeilidUpdate::ValueChange(Box::new(VeilidValueChange {
            key: record_key,
            subkeys,
            count,
            value,
        })));
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "stor", skip_all)
    )]
    fn check_fanout_finished_without_consensus(
        &self,
        opaque_record_key: &OpaqueRecordKey,
        subkey: ValueSubkey,
        fanout_result: &FanoutResult,
    ) -> bool {
        match fanout_result.kind {
            FanoutResultKind::Incomplete => false,
            FanoutResultKind::Timeout => {
                let get_consensus = self.config().internal().network.dht.get_value_count as usize;
                let value_node_count = fanout_result.consensus_nodes.len();
                if value_node_count < get_consensus {
                    veilid_log!(self debug "timeout with insufficient consensus ({}<{}), adding offline subkey: {}:{}",
                        value_node_count, get_consensus,
                        opaque_record_key, subkey);
                    true
                } else {
                    veilid_log!(self debug "timeout with sufficient consensus ({}>={}): set_value {}:{}",
                        value_node_count, get_consensus,
                        opaque_record_key, subkey);
                    false
                }
            }
            FanoutResultKind::Exhausted => {
                let get_consensus = self.config().internal().network.dht.get_value_count as usize;
                let value_node_count = fanout_result.consensus_nodes.len();
                if value_node_count < get_consensus {
                    veilid_log!(self debug "exhausted with insufficient consensus ({}<{}), adding offline subkey: {}:{}",
                        value_node_count, get_consensus,
                        opaque_record_key, subkey);
                    true
                } else {
                    veilid_log!(self debug "exhausted with sufficient consensus ({}>={}): set_value {}:{}",
                        value_node_count, get_consensus,
                        opaque_record_key, subkey);
                    false
                }
            }
            FanoutResultKind::Consensus => false,
        }
    }

    ////////////////////////////////////////////////////////////////////////

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "stor", skip_all)
    )]
    fn process_fanout_results<I: IntoIterator<Item = (ValueSubkeyRangeSet, FanoutResult)>>(
        &self,
        opaque_record_key: OpaqueRecordKey,
        subkey_results_iter: I,
        is_set: bool,
        consensus_width: usize,
    ) -> VeilidAPIResult<bool> {
        let cur_ts = Timestamp::now();
        let local_record_store = self.get_local_record_store()?;
        let existed = local_record_store
            .with_record_detail_mut(&opaque_record_key, |_descriptor, detail| {
                for (subkeys, fanout_result) in subkey_results_iter {
                    for node_id in fanout_result
                        .value_nodes
                        .iter()
                        .filter_map(|x| x.node_ids().get(opaque_record_key.kind()))
                    {
                        let pnd = detail.nodes.entry(node_id).or_default();
                        if is_set || pnd.last_set == Timestamp::default() {
                            pnd.last_set = cur_ts;
                        }
                        pnd.last_seen = cur_ts;
                        pnd.subkeys = pnd.subkeys.union(&subkeys);
                    }
                }

                // Purge nodes down to the N most recently seen, where N is the consensus width
                let mut nodes_ts = detail
                    .nodes
                    .iter()
                    .map(|kv| (kv.0.clone(), kv.1.last_seen))
                    .collect::<Vec<_>>();
                nodes_ts.sort_unstable_by(|a, b| {
                    // Timestamp is first metric
                    let res = b.1.cmp(&a.1);
                    if res != cmp::Ordering::Equal {
                        return res;
                    }
                    // Distance is the next metric, closer nodes first
                    let da =
                        a.0.to_hash_coordinate()
                            .distance(&opaque_record_key.to_hash_coordinate());

                    let db =
                        b.0.to_hash_coordinate()
                            .distance(&opaque_record_key.to_hash_coordinate());
                    da.cmp(&db)
                });

                for dead_node_key in nodes_ts.iter().skip(consensus_width) {
                    detail.nodes.remove(&dead_node_key.0);
                }
            })?
            .is_some();

        Ok(existed)
    }

    fn routing_domain_ready_event_handler(&self, evt: Arc<RoutingDomainReadyEvent>) {
        // Gate DHT ops on the same level-based signal as public_internet_ready, so
        // it survives a network switch (the old peer-info-edge gate stuck on a
        // some->some republish).
        if evt.routing_domain != RoutingDomain::PublicInternet {
            return;
        }
        let now_online = evt.is_ready_inbound && evt.is_ready_outbound;
        let was_online = self.is_online.swap(now_online, Ordering::AcqRel);
        if now_online && !was_online {
            // A new network invalidates learned budgets
            self.reset_gated_operation_budgets();
            veilid_log!(self debug "network came back online, change inspecting all watches");
            self.change_inspect_all_watches();
        }
    }

    fn online_state_change_event_handler(&self, evt: Arc<OnlineStateChangeEvent>) {
        if Self::online_state_change_reinspects_watches(&evt) {
            veilid_log!(self debug "recovered from degraded, change inspecting all watches");
            self.change_inspect_all_watches();
        }
    }

    /// Whether an online-state change is the moment to ask every watch for missed
    /// changes. Degraded suppresses blame because the failures were about this
    /// node; a watch established or renewed then may never have been accepted, and
    /// a change it should have delivered is not coming. Same answer as coming back
    /// online: now, rather than at each watch's backed-off interval.
    pub(super) fn online_state_change_reinspects_watches(evt: &OnlineStateChangeEvent) -> bool {
        evt.routing_domain == RoutingDomain::PublicInternet
            && evt.old_state == OnlineState::Degraded
            && evt.new_state == OnlineState::Online
    }

    async fn tick_event_handler(&self, _evt: Arc<TickEvent>) {
        if let Err(e) = self.tick().await {
            error!("Error in storage manager tick: {}", e);
        }
    }

    fn network_stats_change_event_handler(
        &self,
        evt: Arc<crate::network_manager::NetworkManagerAccountingChangeEvent>,
    ) {
        let (up_bps, down_bps) = {
            let stats = evt.accounting.read();
            (
                stats.self_stats.transfer_stats.up.maximum.as_u64(),
                stats.self_stats.transfer_stats.down.maximum.as_u64(),
            )
        };
        self.step_gated_operation_budgets(up_bps, down_bps);
    }
}
