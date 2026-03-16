use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteSpecDetail {
    /// Secret key
    pub secret_key: SecretKey,
    /// Route hop node ids
    pub hops: Vec<NodeId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteSetSpecDetail {
    /// Routes in the set
    route_set: BTreeMap<PublicKey, RouteSpecDetail>,
    /// Directions this route is guaranteed to work in
    directions: DirectionSet,
    /// Stability preference (prefer reliable nodes over faster)
    stability: Stability,
    /// Sequencing capability (connection oriented protocols vs datagram)
    orderings: SequenceOrderingSet,
    /// Automatically allocated route vs manually allocated route
    automatic: bool,
    /// Route noderefs
    #[serde(skip)]
    hop_node_refs: Vec<NodeRef>,
    /// Published private route, do not reuse for ephemeral routes
    /// Not serialized because all routes should be re-published when restarting
    #[serde(skip)]
    published: AtomicBool,
    /// Lock count: when > 0, route is locked from invalidation and testing
    #[serde(skip)]
    lock_count: AtomicUsize,
    /// Stats
    stats: RwLock<RouteStats>,
}

impl Clone for RouteSetSpecDetail {
    fn clone(&self) -> Self {
        Self {
            route_set: self.route_set.clone(),
            directions: self.directions,
            stability: self.stability,
            orderings: self.orderings,
            automatic: self.automatic,
            hop_node_refs: self.hop_node_refs.clone(),
            published: AtomicBool::new(self.published.load(Ordering::Relaxed)),
            lock_count: AtomicUsize::new(self.lock_count.load(Ordering::Relaxed)),
            stats: RwLock::new(self.stats.read().clone()),
        }
    }
}

impl fmt::Display for RouteSetSpecDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (latency_stats, transfer_stats, last_known_valid_ts) = self.with_stats(|s| {
            (
                s.latency_stats().to_string(),
                s.transfer_stats().to_string(),
                s.last_known_valid_ts
                    .map(|ts| ts.to_string())
                    .unwrap_or_else(|| "None".to_string()),
            )
        });
        write!(
            f,
            "count={}, stability={:?} dirs={:?} auto={:?} pub={:?} latency={} transfer={} last_valid={} hops=[{}]",
            self.hop_count(),
            self.get_stability(),
            self.get_directions(),
            self.is_automatic(),
            self.is_published(),
            latency_stats,
            transfer_stats,
            last_known_valid_ts,
            self.hop_node_refs().iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
        )
    }
}

impl RouteSetSpecDetail {
    pub fn new(
        cur_ts: Timestamp,
        route_set: BTreeMap<PublicKey, RouteSpecDetail>,
        hop_node_refs: Vec<NodeRef>,
        directions: DirectionSet,
        stability: Stability,
        orderings: SequenceOrderingSet,
        automatic: bool,
    ) -> VeilidAPIResult<Self> {
        if route_set.is_empty() {
            apibail_missing_argument!("route set is empty", "route_set");
        }
        if hop_node_refs.is_empty() {
            apibail_missing_argument!("hop node refs is empty", "hop_node_refs");
        }
        if directions.is_empty() {
            apibail_missing_argument!("directions is empty", "directions");
        }
        if orderings.is_empty() {
            apibail_missing_argument!("orderings is empty", "orderings");
        }
        Ok(Self {
            route_set,
            hop_node_refs,
            published: AtomicBool::new(false),
            lock_count: AtomicUsize::new(0),
            directions,
            stability,
            orderings,
            stats: RwLock::new(RouteStats::new(cur_ts)),
            automatic,
        })
    }

    pub fn prepare(&mut self, routing_table: &RoutingTable) -> bool {
        let rsd = self.route_set.values().next().unwrap_or_log();
        let mut hop_node_refs = Vec::with_capacity(rsd.hops.len());
        for h in &rsd.hops {
            let Ok(Some(nr)) = routing_table.lookup_node_id(h.clone()) else {
                return false;
            };
            hop_node_refs.push(nr);
        }

        // Apply noderefs
        self.hop_node_refs = hop_node_refs;

        true
    }

    pub fn get_route_by_key(&self, key: &PublicKey) -> Option<&RouteSpecDetail> {
        self.route_set.get(key)
    }
    pub fn get_route_set_keys(&self) -> PublicKeyGroup {
        let mut tks = PublicKeyGroup::new();
        for k in self.route_set.keys() {
            tks.add(k.clone());
        }
        tks
    }
    pub fn get_best_route_set_key(&self) -> Option<PublicKey> {
        self.get_route_set_keys().first().cloned()
    }
    pub fn iter_route_set(
        &self,
    ) -> alloc::collections::btree_map::Iter<'_, PublicKey, RouteSpecDetail> {
        self.route_set.iter()
    }
    pub fn with_stats<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&RouteStats) -> R,
    {
        let stats = self.stats.read();
        f(&stats)
    }
    pub fn with_stats_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut RouteStats) -> R,
    {
        let mut stats = self.stats.write();
        f(&mut stats)
    }
    #[must_use]
    pub fn is_published(&self) -> bool {
        self.published.load(Ordering::Relaxed)
    }
    pub fn set_published(&self, published: bool) {
        self.published.store(published, Ordering::Relaxed);
    }
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.lock_count.load(Ordering::Relaxed) > 0
    }
    pub fn lock(&self) {
        self.lock_count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn unlock(&self) {
        let prev = self.lock_count.fetch_sub(1, Ordering::Relaxed);
        assert!(prev > 0, "unlock called on unlocked route");
    }
    #[must_use]
    pub fn needs_testing(&self, cur_ts: Timestamp) -> bool {
        if self.is_locked() {
            return false;
        }
        self.with_stats(|stats| stats.needs_testing(cur_ts))
    }
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hop_node_refs.len()
    }
    pub fn hop_node_refs(&self) -> Vec<NodeRef> {
        self.hop_node_refs.clone()
    }
    pub fn hop_node_ref(&self, idx: usize) -> Option<NodeRef> {
        self.hop_node_refs.get(idx).cloned()
    }
    pub fn get_stability(&self) -> Stability {
        self.stability
    }
    pub fn get_directions(&self) -> DirectionSet {
        self.directions
    }
    pub fn is_sequencing_match(&self, sequencing: Sequencing) -> bool {
        for ordering in self.orderings.iter() {
            if sequencing.matches_ordering(ordering) {
                return true;
            }
        }
        false
    }
    #[must_use]
    pub fn contains_nodes(&self, nodes: &[NodeId]) -> bool {
        for tk in nodes {
            for rsd in self.route_set.values() {
                if rsd.hops.contains(tk) {
                    return true;
                }
            }
        }
        false
    }
    #[must_use]
    pub fn is_automatic(&self) -> bool {
        self.automatic
    }

    /// Generate a key for the cache that can be used to uniquely identify this route's contents
    #[must_use]
    pub fn make_cache_key(&self) -> Vec<u8> {
        let best_route_set_key = self.get_best_route_set_key().unwrap_or_log();
        let best_hops_node_ids = &self
            .get_route_by_key(&best_route_set_key)
            .unwrap_or_log()
            .hops;

        let mut cache: Vec<u8> = Vec::with_capacity(best_hops_node_ids.len() * 32); // xxx hack: this code is going away soon anyway
        for best_hop_node_id in best_hops_node_ids {
            cache.extend_from_slice(best_hop_node_id.ref_value());
        }
        cache
    }
}
