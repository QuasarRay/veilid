mod bucket;
mod bucket_entry;
mod bucket_entry_snapshot;
mod debug;
mod entry_snapshot;
mod find_nodes;
#[cfg(feature = "geolocation")]
mod geolocation;
mod get_nodes;
mod health;
mod node_ref;
mod privacy;
mod route_spec_store;
mod routing_domains;
mod routing_table_inner;
mod stats_accounting;
mod tasks;
mod types;

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod tests_routing_table;

pub(crate) use bucket_entry::*;
pub(crate) use bucket_entry_snapshot::*;
pub(crate) use entry_snapshot::*;
pub(crate) use node_ref::*;
pub(crate) use privacy::*;
pub(crate) use route_spec_store::*;
pub(crate) use routing_domains::*;
pub(crate) use routing_table_inner::*;
pub(crate) use stats_accounting::*;
pub use types::*;

use super::*;

use crate::crypto::*;
use crate::network_manager::*;
use crate::rpc_processor::*;

use bucket::*;
use hashlink::LruCache;
use tasks::ping_validator::PingValidationEntry;

impl_veilid_log_facility!("rtab");

//////////////////////////////////////////////////////////////////////////

/// Routing table bucket count (one per bit per 32 byte node id)
const BUCKET_COUNT: usize = HASH_COORDINATE_LENGTH * 8;

/// How frequently we flush the routing table and route spec store to storage
const ROUTING_TABLE_FLUSH_INTERVAL_SECS: u32 = 30;

// Table store keys
const ALL_ENTRY_BYTES: &[u8] = b"all_entry_bytes";
const ROUTING_TABLE: &str = "routing_table";
const SERIALIZED_BUCKET_MAP: &[u8] = b"serialized_bucket_map";
const CACHE_VALIDITY_KEY: &[u8] = b"cache_validity_key";

pub type RoutingTableEntryFilter<'t> =
    Box<dyn FnMut(&Option<BucketEntrySnapshot>, Timestamp) -> bool + Send + 't>;
pub type RoutingTableEntryPreSortFilter<'t> =
    Box<dyn FnMut(&mut Vec<Option<BucketEntrySnapshot>>, Timestamp) + Send + 't>;
pub type RoutingTableEntrySort<'t> = Box<
    dyn FnMut(
            &Option<BucketEntrySnapshot>,
            &Option<BucketEntrySnapshot>,
            Timestamp,
        ) -> core::cmp::Ordering
        + Send
        + 't,
>;

type SerializedBuckets = Vec<Vec<u8>>;
type SerializedBucketMap = BTreeMap<CryptoKind, SerializedBuckets>;

pub type BucketIndex = (CryptoKind, usize);

#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct RecentPeersEntry {
    pub last_connection: Flow,
}

#[derive(Debug, Clone)]
pub struct RoutingTableStartupContext {
    pub startup_lock: Arc<StartupLock>,
}
impl RoutingTableStartupContext {
    pub fn new() -> Self {
        Self {
            startup_lock: Arc::new(StartupLock::new()),
        }
    }
}
impl Default for RoutingTableStartupContext {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub(crate) struct RoutingTable {
    registry: VeilidComponentRegistry,

    // Startup context
    startup_context: RoutingTableStartupContext,

    /// Routing table inner state
    inner: RwLock<RoutingTableInner>,
    /// Routing domains
    routing_domains: Mutex<HashMap<RoutingDomain, Arc<dyn RoutingDomainController>>>,

    // Ping validation channel sender (recreated on each startup/shutdown cycle)
    ping_validation_sender: Mutex<flume::Sender<Vec<PingValidationEntry>>>,
    // Ping validation channel receiver (taken during startup, recreated during shutdown)
    ping_validation_receiver: Mutex<Option<flume::Receiver<Vec<PingValidationEntry>>>>,
    // Ping validation processor join handle
    ping_validation_processor_jh: Mutex<Option<MustJoinHandle<()>>>,
    // Ping validation processor stop source
    ping_validation_stop_source: Mutex<Option<StopSource>>,

    /// Node Ids
    node_ids: RwLock<NodeIdGroup>,
    /// Public Keysyea
    public_keys: RwLock<PublicKeyGroup>,
    /// Secret Keys
    secret_keys: RwLock<SecretKeyGroup>,
    /// Route spec store
    route_spec_store: RouteSpecStore,
    /// Buckets to kick on our next kick task
    kick_queue: Mutex<BTreeSet<BucketIndex>>,
    /// Interim accounting mechanism for this node's RPC latency to any other node
    self_latency_stats_accounting: Mutex<(LatencyStatsAccounting, LatencyStats)>,
    /// Interim accounting mechanism for the total bandwidth to/from this node
    self_transfer_stats_accounting: Mutex<(TransferStatsAccounting, TransferStatsDownUp)>,
    /// Peers we have recently communicated with
    recent_peers: Mutex<LruCache<NodeId, RecentPeersEntry>>,
    /// Async tagged critical sections table
    /// Tag: "tick" -> in ticker
    critical_sections: AsyncTagLockTable<&'static str>,
    /// Last routing table health summary
    routing_table_health: Mutex<Arc<RoutingTableHealth>>,

    /// Background process for flushing the table to disk
    flush_task: TickTask<EyreReport>,
    /// Background process for computing statistics
    rolling_transfers_task: TickTask<EyreReport>,
    /// Background process for computing statistics
    update_state_stats_task: TickTask<EyreReport>,
    /// Background process for computing statistics
    rolling_answers_task: TickTask<EyreReport>,
    /// Background process to purge dead routing table entries when necessary
    kick_buckets_task: TickTask<EyreReport>,

    /// Tick subscription
    tick_subscription: Mutex<Option<EventBusSubscription>>,
}

impl fmt::Debug for RoutingTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingTable")
            // .field("inner", &self.inner)
            // .field("unlocked_inner", &self.unlocked_inner)
            .finish()
    }
}

impl_veilid_component!(RoutingTable);

impl RoutingTable {
    pub fn new(
        registry: VeilidComponentRegistry,
        startup_context: RoutingTableStartupContext,
    ) -> Self {
        let inner = RwLock::new(RoutingTableInner::new(registry.clone()));
        let route_spec_store = RouteSpecStore::new(registry.clone());

        // Create ping validation channel
        let (ping_validation_sender, ping_validation_receiver) = flume::unbounded();

        let this = Self {
            registry,
            inner,
            startup_context,
            route_spec_store,

            routing_domains: Default::default(),
            node_ids: Default::default(),
            public_keys: Default::default(),
            secret_keys: Default::default(),
            kick_queue: Default::default(),
            ping_validation_sender: Mutex::new(ping_validation_sender),
            ping_validation_receiver: Mutex::new(Some(ping_validation_receiver)),
            ping_validation_processor_jh: Mutex::new(None),
            ping_validation_stop_source: Mutex::new(None),
            self_latency_stats_accounting: Default::default(),
            self_transfer_stats_accounting: Default::default(),
            recent_peers: Mutex::new(LruCache::new(RECENT_PEERS_TABLE_SIZE)),
            critical_sections: AsyncTagLockTable::new(),
            routing_table_health: Mutex::new(Arc::new(RoutingTableHealth::default())),

            flush_task: TickTask::new("flush_task", ROUTING_TABLE_FLUSH_INTERVAL_SECS),
            rolling_transfers_task: TickTask::new(
                "rolling_transfers_task",
                ROLLING_TRANSFERS_INTERVAL_SECS,
            ),
            update_state_stats_task: TickTask::new(
                "update_state_stats_task",
                UPDATE_STATE_STATS_INTERVAL_SECS,
            ),
            rolling_answers_task: TickTask::new(
                "rolling_answers_task",
                ROLLING_ANSWER_INTERVAL_SECS,
            ),
            kick_buckets_task: TickTask::new("kick_buckets_task", 1),

            tick_subscription: Default::default(),
        };

        this.setup_tasks();

        this
    }

    /////////////////////////////////////
    // Initialization

    fn log_facilities_impl(&self) -> VeilidComponentLogFacilities {
        let mut facilities = VeilidComponentLogFacilities::new();

        facilities = facilities.with_facility(
            VeilidComponentLogFacility::try_new_with_tags("rtab", ["#common"]).unwrap(),
        );

        facilities = facilities.with_facility(
            VeilidComponentLogFacility::try_new_with_tags("rtab::route", ["#common"]).unwrap(),
        );

        facilities = facilities.with_facility(
            VeilidComponentLogFacility::try_new_with_tags("network_result", ["#verbose"]).unwrap(),
        );

        #[cfg(feature = "geolocation")]
        {
            facilities = facilities.with_facility(
                VeilidComponentLogFacility::try_new_with_tags("geolocation", ["#verbose"]).unwrap(),
            );
        }

        facilities
    }

    /// Called to initialize the routing table after it is created
    async fn init_async(&self) -> EyreResult<()> {
        veilid_log!(self debug "starting routing table init");

        // Set up routing domains (eventually make this pluggable or use features)
        {
            let mut routing_domains = self.routing_domains.lock();
            routing_domains.insert(
                RoutingDomain::PublicInternet,
                Arc::new(PublicInternetRoutingDomainController::new(self.registry())),
            );
            routing_domains.insert(
                RoutingDomain::LocalNetwork,
                Arc::new(LocalNetworkRoutingDomainController::new(self.registry())),
            );
        }

        // Set up initial keys and node ids
        self.setup_public_keys().await?;

        // Set up routing buckets
        {
            let mut inner = self.inner.write();
            inner.init_buckets();
        }

        // Clear out routing table health
        *self.routing_table_health.lock() = Arc::new(RoutingTableHealth::default());

        // Load bucket entries from table db if possible
        veilid_log!(self debug "loading routing table entries");
        if let Err(e) = self.load_buckets().await {
            veilid_log!(self debug "Error loading buckets from storage: {:#?}. Resetting.", e);
            let mut inner = self.inner.write();
            inner.init_buckets();
        }

        // Set up routespecstore
        veilid_log!(self debug "starting route spec store init");
        if let Err(e) = self.route_spec_store().load().await {
            veilid_log!(self debug "Error loading route spec store: {:#?}. Resetting.", e);
            self.route_spec_store().reset();
        };
        veilid_log!(self debug "finished route spec store init");

        veilid_log!(self debug "finished routing table init");
        Ok(())
    }

    #[expect(clippy::unused_async)]
    async fn post_init_async(&self) -> EyreResult<()> {
        Ok(())
    }

    pub(crate) async fn startup(&self) -> EyreResult<()> {
        let guard = self.startup_context.startup_lock.startup()?;

        // Start all routing domain controllers
        veilid_log!(self debug "starting routing domain controllers");
        let mut started_rdcs: Vec<Arc<dyn RoutingDomainController>> = Vec::new();
        for rdc in self.get_routing_domain_controllers(RoutingDomainSet::all()) {
            veilid_log!(self debug "  starting routing domain controller: {}", rdc.routing_domain());
            if let Err(e) = rdc.startup().await {
                veilid_log!(self debug "error starting routing domain controller: {}", e);
                for started_rdc in started_rdcs {
                    veilid_log!(self debug "  shutting down routing domain controller: {}", started_rdc.routing_domain());
                    started_rdc.shutdown().await;
                }

                return Err(e);
            }
            started_rdcs.push(rdc);
        }
        veilid_log!(self debug "finished starting routing domain controllers");

        // Start ping validation processor
        veilid_log!(self debug "starting ping validation processor");
        let rx = self
            .ping_validation_receiver
            .lock()
            .take()
            .expect("ping validation receiver already taken");
        let stop_source = StopSource::new();
        let stop_token = stop_source.token();
        let jh = spawn(
            "ping validation processor",
            Self::ping_validation_processor(self.registry(), stop_token, rx),
        );
        *self.ping_validation_processor_jh.lock() = Some(jh);
        *self.ping_validation_stop_source.lock() = Some(stop_source);

        // Register event handlers
        let tick_subscription = impl_subscribe_event_bus_async!(self, Self, tick_event_handler);
        *self.tick_subscription.lock() = Some(tick_subscription);

        guard.success();
        Ok(())
    }

    pub(crate) async fn shutdown(&self) {
        // Stop tasks
        veilid_log!(self debug "stopping routing table tasks");

        let guard = self
            .startup_context
            .startup_lock
            .shutdown()
            .await
            .expect_or_log("should be started up");

        if let Some(sub) = self.tick_subscription.lock().take() {
            self.event_bus().unsubscribe(sub);
        }

        veilid_log!(self debug "cancelling routing table tasks");
        self.cancel_tasks().await;

        // Stop ping validation processor
        veilid_log!(self debug "stopping ping validation processor");
        drop(self.ping_validation_stop_source.lock().take());
        let opt_jh = self.ping_validation_processor_jh.lock().take();
        if let Some(jh) = opt_jh {
            jh.await;
        }

        // Recreate ping validation channel for potential re-attach
        let (tx, rx) = flume::unbounded();
        *self.ping_validation_sender.lock() = tx;
        *self.ping_validation_receiver.lock() = Some(rx);

        // Shutdown all routing domain controllers
        veilid_log!(self debug "shutting down routing domain controllers");
        for rdc in self.get_routing_domain_controllers(RoutingDomainSet::all()) {
            veilid_log!(self debug "  shutting down routing domain controller: {}", rdc.routing_domain());
            rdc.shutdown().await;
        }
        veilid_log!(self debug "finished shutting down routing domain controllers");

        guard.success();
    }

    #[expect(clippy::unused_async)]
    async fn pre_terminate_async(&self) {
        // Ensure things have shut down
        assert!(
            self.startup_context.startup_lock.is_shut_down(),
            "should have shut down by now"
        );
    }

    /// Called to shut down the routing table
    async fn terminate_async(&self) {
        veilid_log!(self debug "starting routing table terminate");

        veilid_log!(self debug "routing table termination flush");
        self.flush().await;

        veilid_log!(self debug "shutting down routing table");

        {
            let mut inner = self.inner.write();
            *inner = RoutingTableInner::new(self.registry());
        }
        *self.routing_table_health.lock() = Arc::new(RoutingTableHealth::default());

        self.node_ids.write().clear();

        self.routing_domains.lock().clear();

        veilid_log!(self debug "finished routing table terminate");
    }

    pub async fn flush(&self) {
        if let Err(e) = self.save_buckets().await {
            error!("failed to save routing table entries: {}", e);
        }

        if let Err(e) = self.route_spec_store().save().await {
            error!("couldn't save route spec store: {}", e);
        }
    }

    ///////////////////////////////////////////////////////////////////

    /// Create a point-in-time snapshot of all routing table entries matching the minimum state
    pub fn snapshot_entries(
        &self,
        cur_ts: Timestamp,
        min_state: BucketEntryState,
    ) -> EntrySnapshot {
        self.inner
            .read()
            .snapshot_entries(self.registry(), cur_ts, min_state)
    }

    pub fn node_id(&self, kind: CryptoKind) -> NodeId {
        self.node_ids.read().get(kind).unwrap_or_log()
    }

    pub fn public_key(&self, kind: CryptoKind) -> PublicKey {
        self.public_keys.read().get(kind).unwrap_or_log()
    }

    pub fn secret_key(&self, kind: CryptoKind) -> SecretKey {
        self.secret_keys.read().get(kind).unwrap_or_log()
    }

    pub fn node_ids(&self) -> NodeIdGroup {
        self.node_ids.read().clone()
    }

    pub fn public_keys(&self) -> PublicKeyGroup {
        self.public_keys.read().clone()
    }

    pub fn signing_key_pairs(&self) -> KeyPairGroup {
        let mut tkps = KeyPairGroup::new();
        for ck in VALID_CRYPTO_KINDS {
            tkps.add(KeyPair::new(
                ck,
                BareKeyPair::new(self.public_key(ck).value(), self.secret_key(ck).value()),
            ));
        }
        tkps
    }

    pub fn matches_own_node_id(&self, node_ids: &[NodeId]) -> bool {
        for ni in node_ids {
            if let Some(v) = self.node_ids().get(ni.kind()) {
                if v.ref_value() == ni.ref_value() {
                    return true;
                }
            }
        }
        false
    }

    pub fn matches_own_public_key(&self, public_keys: &[PublicKey]) -> bool {
        for pk in public_keys {
            if let Some(v) = self.public_keys().get(pk.kind()) {
                if v.ref_value() == pk.ref_value() {
                    return true;
                }
            }
        }
        false
    }

    fn reset_low_water_mark(&self, routing_domain: RoutingDomain) {
        let rdc = self.get_routing_domain_controller(routing_domain);
        let rdd = rdc.read();
        rdd.reset_low_water_mark();
    }

    #[cfg(not(test))]
    async fn setup_public_key(
        &self,
        vcrypto: AsyncCryptoSystemGuard<'_>,
    ) -> VeilidAPIResult<(PublicKey, SecretKey)> {
        let config = self.config();
        let table_store = self.table_store();
        let ck = vcrypto.kind();
        let mut public_key = config.network.routing_table.public_keys.get(ck);
        let mut secret_key = config.network.routing_table.secret_keys.get(ck);

        let config_table = table_store.open("__veilid_config", 1).await?;

        // Old pre-0.5.0 locations
        let table_key_node_id = format!("node_id_{}", ck);
        let table_key_node_id_secret = format!("node_id_secret_{}", ck);
        // Post-0.5.0 locations
        let table_key_public_key = format!("public_key_{}", ck);
        let table_key_secret_key = format!("secret_key_{}", ck);

        // See if public key was previously stored in the table store
        if public_key.is_none() {
            veilid_log!(self debug "pulling {} from storage", table_key_public_key);
            if let Ok(Some(stored_public_key)) = config_table
                .load_json::<PublicKey>(0, table_key_public_key.as_bytes())
                .await
            {
                veilid_log!(self debug "{} found in storage", table_key_public_key);
                public_key = Some(stored_public_key);
            } else {
                veilid_log!(self debug "{} not found in storage", table_key_public_key);
            }
        }
        if public_key.is_none() {
            veilid_log!(self debug "pulling {} from deprecated storage", table_key_node_id);
            if let Ok(Some(stored_public_key)) = config_table
                .load_json::<PublicKey>(0, table_key_node_id.as_bytes())
                .await
            {
                veilid_log!(self debug "{} found in deprecated storage", table_key_node_id);
                public_key = Some(stored_public_key);
            } else {
                veilid_log!(self debug "{} not found in deprecated storage", table_key_node_id);
            }
        }

        // See if secret key was previously stored in the table store
        if secret_key.is_none() {
            veilid_log!(self debug "pulling {} from storage", table_key_secret_key);
            if let Ok(Some(stored_secret_key)) = config_table
                .load_json::<SecretKey>(0, table_key_secret_key.as_bytes())
                .await
            {
                veilid_log!(self debug "{} found in storage", table_key_secret_key);
                secret_key = Some(stored_secret_key);
            } else {
                veilid_log!(self debug "{} not found in storage", table_key_secret_key);
            }
        }
        if secret_key.is_none() {
            veilid_log!(self debug "pulling {} from deprecated storage", table_key_node_id_secret);
            if let Ok(Some(stored_secret_key)) = config_table
                .load_json::<SecretKey>(0, table_key_node_id_secret.as_bytes())
                .await
            {
                veilid_log!(self debug "{} found in deprecated storage", table_key_node_id_secret);
                secret_key = Some(stored_secret_key);
            } else {
                veilid_log!(self debug "{} not found in deprecated storage", table_key_node_id_secret);
            }
        }

        // If we have a public key from storage, check it
        let (public_key, secret_key) =
            if let (Some(public_key), Some(secret_key)) = (public_key, secret_key) {
                // Validate node id
                if !vcrypto.validate_keypair(&public_key, &secret_key).await? {
                    apibail_generic!(
                        "secret_key and public_key don't match:\npublic_key: {}\nsecret_key: {}",
                        public_key,
                        secret_key
                    );
                }
                (public_key, secret_key)
            } else {
                // If we still don't have a valid keypair, generate one
                veilid_log!(self debug "generating new node {} keypair", ck);
                vcrypto.generate_keypair().await.into_split()
            };

        // Save the public key + secret in storage
        config_table
            .store_json(0, table_key_public_key.as_bytes(), &public_key)
            .await?;
        config_table
            .store_json(0, table_key_secret_key.as_bytes(), &secret_key)
            .await?;

        Ok((public_key, secret_key))
    }

    /// Get the public keys from config if one is specified
    #[cfg_attr(test, allow(unused_variables))]
    async fn setup_public_keys(&self) -> VeilidAPIResult<()> {
        let crypto = self.crypto();

        let mut out_public_keys = PublicKeyGroup::new();
        let mut out_secret_keys = SecretKeyGroup::new();

        for ck in VALID_CRYPTO_KINDS {
            let vcrypto = crypto
                .get_async(ck)
                .expect_or_log("Valid crypto kind is not actually valid.");

            #[cfg(test)]
            let (public_key, secret_key) = vcrypto.generate_keypair().await.into_split();
            #[cfg(not(test))]
            let (public_key, secret_key) = self.setup_public_key(vcrypto).await?;

            // Save for config
            out_public_keys.add(public_key);
            out_secret_keys.add(secret_key);
        }

        veilid_log!(self info  "Public Keys: {}", out_public_keys);

        *self.public_keys.write() = out_public_keys;
        *self.secret_keys.write() = out_secret_keys;

        // Set up node ids
        let mut node_ids = NodeIdGroup::new();
        for pk in self.public_keys().iter() {
            let node_id = self.generate_node_id(pk)?;
            node_ids.add(node_id);
        }

        veilid_log!(self info "Node Ids: {}", node_ids);

        *self.node_ids.write() = node_ids;

        Ok(())
    }

    // Convenience validators
    pub fn check_route_id(&self, route_id: &RouteId) -> VeilidAPIResult<()> {
        let crypto = self.crypto();
        let Some(vcrypto) = crypto.get(route_id.kind()) else {
            apibail_generic!("unsupported crypto kind");
        };
        if route_id.ref_value().len() != vcrypto.hash_digest_length() {
            apibail_generic!("invalid route id length");
        }
        Ok(())
    }
    pub fn check_node_id(&self, node_id: &NodeId) -> VeilidAPIResult<()> {
        let crypto = self.crypto();
        let Some(_) = crypto.get(node_id.kind()) else {
            apibail_generic!("unsupported crypto kind");
        };
        if node_id.ref_value().len() != HASH_COORDINATE_LENGTH {
            apibail_generic!("invalid node id length");
        }
        Ok(())
    }

    /// Produce node id from public key
    pub fn generate_node_id(&self, public_key: &PublicKey) -> VeilidAPIResult<NodeId> {
        if public_key.ref_value().len() == HASH_COORDINATE_LENGTH {
            return Ok(NodeId::new(
                public_key.kind(),
                BareNodeId::new(public_key.ref_value()),
            ));
        }
        let crypto = self.crypto();
        let Some(vcrypto) = crypto.get(public_key.kind()) else {
            apibail_generic!("unsupported cryptosystem");
        };

        let idhash = vcrypto.generate_hash(public_key.ref_value());
        assert!(
            idhash.ref_value().len() >= HASH_COORDINATE_LENGTH,
            "generate_hash needs to produce at least {} bytes",
            HASH_COORDINATE_LENGTH
        );
        Ok(NodeId::new(
            public_key.kind(),
            BareNodeId::new(&idhash.ref_value()[0..HASH_COORDINATE_LENGTH]),
        ))
    }

    pub fn calculate_bucket_index(&self, node_id: &NodeId) -> EyreResult<BucketIndex> {
        if node_id.ref_value().len() * 8 != BUCKET_COUNT {
            bail!("NodeId should be hashed down to BUCKET_COUNT bits");
        }
        let self_hash_coordinate = self.node_id(node_id.kind()).to_hash_coordinate();
        Ok((
            node_id.kind(),
            node_id
                .to_hash_coordinate()
                .distance(&self_hash_coordinate)
                .first_nonzero_bit()
                .unwrap_or_log(),
        ))
    }

    /// Serialize the routing table.
    fn serialized_buckets(&self) -> (SerializedBucketMap, SerializedBuckets) {
        // Since entries are shared by multiple buckets per cryptokind
        // we need to get the list of all unique entries when serializing
        let mut all_entries: Vec<Arc<BucketEntry>> = Vec::new();

        // Serialize all buckets and get map of entries
        let mut serialized_bucket_map: SerializedBucketMap = BTreeMap::new();
        {
            let mut entry_map: HashMap<*const BucketEntry, u32> = HashMap::new();
            let inner = &*self.inner.read();
            for ck in VALID_CRYPTO_KINDS {
                let buckets = inner.buckets.get(&ck).unwrap_or_log();
                let mut serialized_buckets = Vec::new();
                for bucket in buckets.iter() {
                    serialized_buckets.push(bucket.save_bucket(&mut all_entries, &mut entry_map))
                }
                serialized_bucket_map.insert(ck, serialized_buckets);
            }
        }

        // Serialize all the entries
        let mut all_entry_bytes = Vec::with_capacity(all_entries.len());
        for entry in all_entries {
            // Serialize entry
            let entry_bytes = entry.with(|e| serialize_json_bytes(e));
            all_entry_bytes.push(entry_bytes);
        }

        (serialized_bucket_map, all_entry_bytes)
    }

    /// Write the serialized routing table to the table store.
    async fn save_buckets(&self) -> EyreResult<()> {
        let (serialized_bucket_map, all_entry_bytes) = self.serialized_buckets();

        let table_store = self.table_store();
        let tdb = table_store.open(ROUTING_TABLE, 1).await?;
        let dbx = tdb.transact();
        if let Err(e) = dbx
            .store_json(0, SERIALIZED_BUCKET_MAP, &serialized_bucket_map)
            .await
        {
            dbx.rollback();
            return Err(e.into());
        }
        if let Err(e) = dbx.store_json(0, ALL_ENTRY_BYTES, &all_entry_bytes).await {
            dbx.rollback();
            return Err(e.into());
        }
        dbx.commit().await?;
        Ok(())
    }

    /// Deserialize routing table from table store
    async fn load_buckets(&self) -> EyreResult<()> {
        // Make a cache validity key of all our node ids and our bootstrap choice
        let mut cache_validity_key: Vec<u8> = Vec::new();
        {
            let config = self.config();
            for ck in VALID_CRYPTO_KINDS {
                if let Some(nid) = config.network.routing_table.public_keys.get(ck) {
                    cache_validity_key.extend_from_slice(nid.ref_value());
                }
            }
            for b in &config.network.routing_table.bootstrap {
                cache_validity_key.extend_from_slice(b.as_bytes());
            }
            cache_validity_key.extend_from_slice(
                config
                    .network
                    .network_key_password
                    .clone()
                    .unwrap_or_default()
                    .as_bytes(),
            );
        };

        // Deserialize bucket map and all entries from the table store
        let table_store = self.table_store();
        let db = table_store.open(ROUTING_TABLE, 1).await?;

        let caches_valid = match db.load(0, CACHE_VALIDITY_KEY).await? {
            Some(v) => v == cache_validity_key,
            None => false,
        };
        if !caches_valid {
            // Caches not valid, start over
            veilid_log!(self debug "cache validity key changed, emptying routing table");
            drop(db);
            table_store.delete(ROUTING_TABLE).await?;
            let db = table_store.open(ROUTING_TABLE, 1).await?;
            db.store(0, CACHE_VALIDITY_KEY, &cache_validity_key).await?;
            return Ok(());
        }

        // Caches valid, load saved routing table
        let Some(serialized_bucket_map): Option<SerializedBucketMap> =
            db.load_json(0, SERIALIZED_BUCKET_MAP).await?
        else {
            veilid_log!(self debug "no bucket map in saved routing table");
            return Ok(());
        };
        let Some(all_entry_bytes): Option<SerializedBuckets> =
            db.load_json(0, ALL_ENTRY_BYTES).await?
        else {
            veilid_log!(self debug "no all_entry_bytes in saved routing table");
            return Ok(());
        };

        // Reconstruct all entries
        let inner = &mut *self.inner.write();
        Self::populate_routing_table_inner(inner, serialized_bucket_map, all_entry_bytes)?;

        // // Make all entries live so they can be tested again
        // let cur_ts = Timestamp::now();
        // inner.with_entries(cur_ts, BucketEntryState::Dead, |v| {
        //     v.with_mut(|e| {
        //         e.make_not_dead(cur_ts);
        //     });
        //     Option::<()>::None
        // });

        Ok(())
    }

    /// Write the deserialized table store data to the routing table.
    pub fn populate_routing_table_inner(
        inner: &mut RoutingTableInner,
        serialized_bucket_map: SerializedBucketMap,
        all_entry_bytes: SerializedBuckets,
    ) -> EyreResult<()> {
        let mut all_entries: Vec<Arc<BucketEntry>> = Vec::with_capacity(all_entry_bytes.len());
        for entry_bytes in all_entry_bytes {
            #[allow(unused_mut)]
            let mut entryinner: BucketEntryInner = deserialize_json_bytes(&entry_bytes)
                .wrap_err("failed to deserialize bucket entry")?;

            #[cfg(feature = "geolocation")]
            {
                entryinner.update_geolocation_info();
            }

            let entry = Arc::new(BucketEntry::new_with_inner(entryinner));

            // Keep strong reference in table
            all_entries.push(entry.clone());

            // Keep all entries in weak table too
            inner.all_entries.insert(entry);
        }

        // Validate serialized bucket map
        for (k, v) in &serialized_bucket_map {
            if !VALID_CRYPTO_KINDS.contains(k) {
                veilid_log!(inner warn "crypto kind is not valid, not loading routing table");
                return Ok(());
            }
            if v.len() != BUCKET_COUNT {
                veilid_log!(inner warn "bucket count is different, not loading routing table");
                return Ok(());
            }
        }

        // Recreate buckets
        for (k, v) in serialized_bucket_map {
            let buckets = inner.buckets.get_mut(&k).unwrap_or_log();

            for n in 0..v.len() {
                buckets[n].load_bucket(v[n].clone(), &all_entries)?;
            }
        }

        Ok(())
    }

    pub fn route_spec_store(&self) -> &RouteSpecStore {
        &self.route_spec_store
    }

    /// Record bytes sent/received from this node
    pub fn record_sent_bytes(&self, bytes: ByteCount) {
        self.self_transfer_stats_accounting.lock().0.add_up(bytes);
    }

    pub fn record_received_bytes(&self, bytes: ByteCount) {
        self.self_transfer_stats_accounting.lock().0.add_down(bytes);
    }

    pub fn record_latency(&self, latency: TimestampDuration) {
        let mut lsa = self.self_latency_stats_accounting.lock();
        lsa.1 = lsa.0.record_latency(latency);
    }

    /////////////////////////////////////
    // Locked operations

    /// Attempt to empty the routing table
    /// May not empty buckets completely if there are existing node_refs
    pub fn purge_buckets(&self) {
        self.inner.write().purge_buckets();
    }

    /// Attempt to remove last_connections from entries
    pub fn purge_last_connections(&self) {
        self.inner.write().purge_last_connections();
    }

    fn queue_bucket_kicks(&self, node_ids: NodeIdGroup) {
        for node_id in node_ids.iter() {
            // Skip node ids we didn't add to buckets
            if !VALID_CRYPTO_KINDS.contains(&node_id.kind()) {
                continue;
            }

            // Put it in the kick queue
            let x = self
                .calculate_bucket_index(node_id)
                .expect_or_log("node ids should already be the right length");
            self.kick_queue.lock().insert(x);
        }
    }

    // Update buckets with new node ids we may have learned belong to this entry
    fn update_bucket_entry_node_ids_inner(
        &self,
        inner: &mut RoutingTableInner,
        entry: Arc<BucketEntry>,
        node_ids: &[NodeId],
    ) -> EyreResult<()> {
        entry.with_mut(|e| {
            let mut existing_node_ids = e.node_ids();

            // Peer infos for all routing domains we have
            let mut old_peer_infos = vec![];

            for node_id in node_ids {
                let ck = node_id.kind();
                let is_existing_node_id = existing_node_ids.contains(node_id);

                existing_node_ids.remove(ck);

                // Skip node ids that exist already
                if is_existing_node_id {
                    continue;
                }

                // New node id, get the old peer info if we don't have it yet
                if old_peer_infos.is_empty() {
                    for rd in RoutingDomainSet::all() {
                        if let Some(old_peer_info) = e.get_peer_info(rd) {
                            old_peer_infos.push(old_peer_info);
                        }
                    }
                }

                // Add new node id to entry
                if let Some(old_node_id) = e.add_node_id(node_id.clone())? {
                    // Remove any old node id for this crypto kind
                    if VALID_CRYPTO_KINDS.contains(&ck) {
                        let bucket_index = self.calculate_bucket_index(&old_node_id)?;
                        let bucket = inner.get_bucket_mut(bucket_index);
                        bucket.remove_entry(old_node_id.ref_value());
                        self.kick_queue.lock().insert(bucket_index);
                    }
                }

                // Bucket the entry appropriately
                if VALID_CRYPTO_KINDS.contains(&ck) {
                    let bucket_index = self.calculate_bucket_index(node_id)?;
                    let bucket = inner.get_bucket_mut(bucket_index);
                    bucket.add_existing_entry(node_id.value(), entry.clone());

                    // Kick bucket
                    self.kick_queue.lock().insert(bucket_index);
                }
            }

            // Remove from buckets if node id wasn't seen in new peer info list
            for node_id in existing_node_ids.iter() {
                let ck = node_id.kind();
                if VALID_CRYPTO_KINDS.contains(&ck) {
                    let bucket_index = self.calculate_bucket_index(node_id)?;
                    let bucket = inner.get_bucket_mut(bucket_index);
                    bucket.remove_entry(node_id.ref_value());
                    entry.with_mut(|e| e.remove_node_id(ck));
                }
            }

            // New node id, get the old peer info if we don't have it yet
            if !old_peer_infos.is_empty() {
                let mut new_peer_infos = vec![];
                for rd in RoutingDomainSet::all() {
                    if let Some(new_peer_info) = e.get_peer_info(rd) {
                        new_peer_infos.push(new_peer_info);
                    }
                }

                // adding a node id should never change what routing domains peers are in
                // so we should have a 1:1 ordered mapping here to update with the new nodeids
                assert_eq!(old_peer_infos.len(), new_peer_infos.len());
                for (old_pi, new_pi) in old_peer_infos.into_iter().zip(new_peer_infos.into_iter()) {
                    assert_eq!(old_pi.routing_domain(), new_pi.routing_domain());
                    self.on_entry_peer_info_updated(Some(old_pi), Some(new_pi));
                }
            }
            Ok(())
        })
    }

    /// Create a node reference, possibly creating a bucket entry
    /// the 'update_func' closure is called on the node, and, if created,
    /// in a locked fashion as to ensure the bucket entry state is always valid
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    fn create_node_ref<F>(&self, node_ids: &NodeIdGroup, update_func: F) -> EyreResult<NodeRef>
    where
        F: FnOnce(&mut BucketEntryInner),
    {
        if node_ids.is_empty() {
            bail!("Can't create node with no node id");
        }

        // Ensure someone isn't trying register this node itself
        if self.matches_own_node_id(node_ids) {
            bail!("can't register own node");
        }

        // Look up all bucket entries and make sure we only have zero or one
        // If we have more than one, pick the one with the best cryptokind to add node ids to

        let entry = {
            let mut inner = self.inner.write();

            let mut best_entry: Option<Arc<BucketEntry>> = None;
            let mut supported_node_ids = NodeIdGroup::new();
            for node_id in node_ids.iter() {
                // Ignore node ids we don't support
                if !VALID_CRYPTO_KINDS.contains(&node_id.kind()) {
                    continue;
                }
                supported_node_ids.add(node_id.clone());

                // Find the first in crypto sort order
                let bucket_index = self.calculate_bucket_index(node_id)?;
                let bucket = inner.get_bucket(bucket_index);
                if let Some(entry) = bucket.entry(node_id.ref_value()) {
                    // Best entry is the first one in sorted order that exists from the node id list
                    // Everything else that matches will be overwritten in the bucket and the
                    // existing noderefs will eventually unref and drop the old unindexed bucketentry
                    // We do this instead of merging for now. We could 'kill' entries and have node_refs
                    // rewrite themselves to point to the merged entry upon dereference. The use case for this
                    // may not be worth the effort.
                    best_entry = Some(entry);
                    break;
                };
            }

            // If the entry does exist already, update it
            let entry = if let Some(best_entry) = best_entry {
                // Update the entry with all of the node ids
                if let Err(e) = self.update_bucket_entry_node_ids_inner(
                    &mut inner,
                    best_entry.clone(),
                    node_ids,
                ) {
                    bail!("Not registering new ids for existing node: {}", e);
                }

                best_entry
            } else {
                // Fail out if we can't handle this node
                if supported_node_ids.is_empty() {
                    bail!("Not registering node with no supported node ids");
                }

                // If no entry exists yet, add the first entry to a bucket, possibly evicting a bucket member
                let first_node_id = supported_node_ids[0].clone();
                let bucket_entry = self.calculate_bucket_index(&first_node_id)?;
                let bucket = inner.get_bucket_mut(bucket_entry);
                let new_entry = bucket.add_new_entry(first_node_id.value());
                inner.all_entries.insert(new_entry.clone());
                self.kick_queue.lock().insert(bucket_entry);

                // Update the other bucket entries with the remaining node ids
                if let Err(e) =
                    self.update_bucket_entry_node_ids_inner(&mut inner, new_entry.clone(), node_ids)
                {
                    bail!("Not registering new node: {}", e);
                }

                new_entry
            };

            entry
        };

        // Make node ref to return
        let nr = NodeRef::new(self.registry(), entry.clone());

        // Update the entry with the update func
        entry.with_mut(|e| update_func(e));

        Ok(nr)
    }

    /// Resolve an existing routing table entry using any crypto kind and return a reference to it
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn lookup_bare_node_id(&self, node_id_key: BareNodeId) -> EyreResult<Option<NodeRef>> {
        for ck in VALID_CRYPTO_KINDS {
            if let Some(nr) = self.lookup_node_id(NodeId::new(ck, node_id_key.clone()))? {
                return Ok(Some(nr));
            }
        }
        Ok(None)
    }

    /// Resolve an existing routing table entry and return a reference to it
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn lookup_node_id(&self, node_id: NodeId) -> EyreResult<Option<NodeRef>> {
        if self.matches_own_node_id(std::slice::from_ref(&node_id)) {
            bail!("can't look up own node id in routing table");
        }
        if !VALID_CRYPTO_KINDS.contains(&node_id.kind()) {
            bail!("can't look up node id with invalid crypto kind");
        }

        let bucket_index = self.calculate_bucket_index(&node_id)?;
        let opt_entry = {
            let inner = self.inner.read();
            let bucket = inner.get_bucket(bucket_index);
            bucket.entry(node_id.ref_value())
        };
        Ok(opt_entry.map(|e| NodeRef::new(self.registry(), e)))
    }

    /// Resolve an existing routing table entry and return a filtered reference to it
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn lookup_node_id_with_filter(
        &self,
        node_id: NodeId,
        routing_domain_set: RoutingDomainSet,
        dial_info_filter: DialInfoFilter,
    ) -> EyreResult<Option<FilteredNodeRef>> {
        let nr = self.lookup_node_id(node_id)?;
        Ok(nr.map(|nr| {
            nr.custom_filtered(
                NodeRefFilter::new()
                    .with_dial_info_filter(dial_info_filter)
                    .with_routing_domain_set(routing_domain_set),
            )
        }))
    }

    /// Shortcut function to add a node to our routing table if it doesn't exist
    /// and add the dial info we have for it. Returns a noderef filtered to
    /// the routing domain in which this node was registered for convenience.
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn register_node_with_peer_info(
        &self,
        peer_info: Arc<PeerInfo>,
        allow_invalid: bool,
    ) -> EyreResult<FilteredNodeRef> {
        let routing_domain = peer_info.routing_domain();

        // if our own node is in the list, then ignore it as we don't add ourselves to our own routing table
        if self
            .routing_table()
            .matches_own_node_id(peer_info.node_ids())
        {
            bail!("can't register own node id in routing table");
        }

        // node can not be its own relay
        let node_info = peer_info.node_info();
        let relay_ids = node_info.relay_ids();
        let node_ids = peer_info.node_ids().clone();
        if node_ids.contains_any_from_iter(relay_ids.iter()) {
            bail!("node can not be its own relay");
        }

        if !allow_invalid {
            // verify signature
            if peer_info.signatures().is_empty() {
                bail!(
                    "peerinfo for {:?} has no valid signature",
                    peer_info.node_ids()
                );
            }
        }
        // verify node info is valid in this routing domain
        let valid_routing_domains = self.get_node_info_routing_domains(node_info);
        if !valid_routing_domains.contains(routing_domain) {
            bail!(
                "peerinfo for {:?} not valid in the {:?} routing domain",
                peer_info.node_ids(),
                routing_domain
            );
        }

        let mut updated = false;
        let mut old_peer_info = None;
        let nr = self.create_node_ref(&node_ids, |e| {
            old_peer_info = e.get_peer_info(routing_domain);
            updated = e.update_peer_info(routing_domain, peer_info.clone());
        })?;

        // Process any new or updated PeerInfo
        if old_peer_info.is_none() || updated {
            self.on_entry_peer_info_updated(old_peer_info, Some(peer_info));
        }

        Ok(nr.custom_filtered(NodeRefFilter::new().with_routing_domain(routing_domain)))
    }

    /// Shortcut function to add a node to our routing table if it doesn't exist
    /// Returns a noderef filtered to
    /// the routing domain in which this node was registered for convenience.
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn register_node_with_id(
        &self,
        routing_domain: RoutingDomain,
        node_id: NodeId,
        timestamp: Timestamp,
    ) -> EyreResult<FilteredNodeRef> {
        let nr = self.create_node_ref(&NodeIdGroup::from(node_id), |e| {
            e.touch_last_seen(timestamp);
        })?;

        // Enforce routing domain
        let nr = nr.custom_filtered(NodeRefFilter::new().with_routing_domain(routing_domain));
        Ok(nr)
    }

    /// Called whenever a routing table entry is:
    /// 1. created or updated with new peer information
    /// 2. has a node id added or removed (per CryptoKind)
    ///   * by a new peer info showing up with a different overlapping node id list
    ///   * by a bucket kick removing an entry from a bucket for some cryptokind
    /// 3. (todo) is removed from some routing domain (peer info gone)
    ///
    /// It is not called when:
    /// 1. nodes are registered by id for an existing connection but have no peer info yet
    /// 2. nodes are removed that don't have any peer info
    fn on_entry_peer_info_updated(
        &self,
        old_peer_info: Option<Arc<PeerInfo>>,
        new_peer_info: Option<Arc<PeerInfo>>,
    ) {
        let (routing_domain, node_ids) = match (old_peer_info.as_ref(), new_peer_info.as_ref()) {
            (None, None) => {
                return;
            }
            (None, Some(new_pi)) => (new_pi.routing_domain(), new_pi.node_ids().clone()),
            (Some(old_pi), None) => (old_pi.routing_domain(), old_pi.node_ids().clone()),
            (Some(old_pi), Some(new_pi)) => {
                assert_eq!(
                    old_pi.routing_domain(),
                    new_pi.routing_domain(),
                    "routing domains should be the same here",
                );
                let mut node_ids = old_pi.node_ids().clone();
                node_ids.add_all_from_iter(new_pi.node_ids().iter());
                (new_pi.routing_domain(), node_ids)
            }
        };

        // If this is our relay, then redo our own peerinfo because
        // if we have relayed peerinfo, then changing the relay's peerinfo
        // changes our own peer info
        let rdc = self.get_routing_domain_controller(routing_domain);
        let rdd = rdc.read();
        let our_relay_node_ids = rdd
            .relays()
            .iter()
            .flat_map(|rdr| rdr.relay_node.node_ids().to_vec())
            .collect::<Vec<_>>();
        if node_ids.contains_any_from_iter(our_relay_node_ids.iter()) {
            rdd.refresh();
            rdc.publish_peer_info();
        }

        // Update tables that use peer info
        // if let Some(_old_pi) = old_peer_info {
        //     // Remove old info
        // }
        // if let Some(_new_pi) = new_peer_info {
        //     // Add new info
        // }
    }

    pub fn clear_punishments(&self) {
        let cur_ts = Timestamp::now();
        self.inner
            .read()
            .with_entries(cur_ts, BucketEntryState::Punished, |e| {
                e.with_mut(|ei| ei.set_punished(None));
                Option::<()>::None
            });
    }

    pub fn get_outbound_relay_peer(
        &self,
        _routing_domain: routing_table::RoutingDomain,
    ) -> Option<Arc<routing_table::PeerInfo>> {
        // unimplemented!
        None
    }

    /// Find the first dial info that matches a routing domain set and filter
    pub fn first_filtered_dial_info_detail(
        &self,
        routing_domain_set: RoutingDomainSet,
        filter: &DialInfoFilter,
    ) -> Option<DialInfoDetail> {
        if filter.is_dead() || routing_domain_set.is_empty() {
            return None;
        }
        for rdd in self.get_routing_domain_controllers(routing_domain_set) {
            let rdd = rdd.read();
            if let Some(did) = rdd
                .dial_info_details()
                .iter()
                .find(|did| did.matches_filter(filter))
                .cloned()
            {
                return Some(did);
            }
        }
        None
    }

    /// Makes a filter that finds nodes with a matching inbound dialinfo
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    pub fn make_inbound_dial_info_entry_filter<'a>(
        &self,
        routing_domain: RoutingDomain,
        dial_info_filter: DialInfoFilter,
    ) -> RoutingTableEntryFilter<'a> {
        let self_has_matching_dial_info = self
            .first_filtered_dial_info_detail(routing_domain.into(), &dial_info_filter)
            .is_some();

        // does it have matching public dial info?
        Box::new(
            move |opt_snap: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
                if let Some(snap) = opt_snap {
                    if let Some(pi) = snap.get_peer_info(routing_domain) {
                        if pi
                            .node_info()
                            .first_filtered_dial_info_detail(DialInfoDetail::NO_SORT, &|did| {
                                did.matches_filter(&dial_info_filter)
                            })
                            .is_some()
                        {
                            return true;
                        }
                    }
                    false
                } else {
                    self_has_matching_dial_info
                }
            },
        )
    }

    /// Makes a filter that finds nodes capable of dialing a particular outbound dialinfo
    pub fn make_outbound_dial_info_entry_filter<'a>(
        &self,
        routing_domain: RoutingDomain,
        dial_info: DialInfo,
    ) -> RoutingTableEntryFilter<'a> {
        let outbound_dial_info_filter = self
            .get_routing_domain_controller(routing_domain)
            .read()
            .outbound_dial_info_filter();
        let self_has_matching_dial_info = dial_info.matches_filter(&outbound_dial_info_filter);

        // does the node's outbound capabilities match the dialinfo?
        Box::new(
            move |opt_snap: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
                if let Some(snap) = opt_snap {
                    if let Some(pi) = snap.get_peer_info(routing_domain) {
                        let ni = pi.node_info();
                        let dif = DialInfoFilter::all()
                            .with_protocol_type_set(ni.outbound_protocols())
                            .with_address_type_set(ni.address_types());
                        if dial_info.matches_filter(&dif) {
                            return true;
                        }
                    }
                    false
                } else {
                    self_has_matching_dial_info
                }
            },
        )
    }

    /// Registers a set of PeerInfo with the routing table
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", skip(self, peer_info_list), fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn register_nodes_with_peer_info_list(
        &self,
        peer_info_list: Vec<Arc<PeerInfo>>,
    ) -> Vec<NodeRef> {
        // Register nodes we'd found
        let mut out = Vec::<NodeRef>::with_capacity(peer_info_list.len());
        for p in peer_info_list {
            // Don't register our own node
            if self.matches_own_node_id(p.node_ids()) {
                continue;
            }

            // Register the node if it's new
            match self.register_node_with_peer_info(p, false) {
                Ok(nr) => out.push(nr.unfiltered()),
                Err(e) => {
                    veilid_log!(self debug "failed to register node with peer info from find node answer: {}", e);
                }
            }
        }
        out
    }

    /// Find the best routing domain for a node info
    /// Returns Some(rd) if there is a 'best' routing domain for this node info given its stated origin
    /// Returns None if no node info from this origin is acceptable
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab", skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn find_best_node_info_routing_domain(
        &self,
        origin_routing_domain: RoutingDomain,
        node_info: &NodeInfo,
    ) -> Option<RoutingDomain> {
        // See what routing domains it could be placed in
        let valid_routing_domains = self.get_node_info_routing_domains(node_info);

        // For each valid routing domain in preference order,
        // see if the valid domains can accept peer info from this origin
        for rd in valid_routing_domains {
            let origin_routing_domains = self.origin_routing_domains(rd);
            if origin_routing_domains.contains(origin_routing_domain) {
                return Some(rd);
            }
        }

        None
    }
}
