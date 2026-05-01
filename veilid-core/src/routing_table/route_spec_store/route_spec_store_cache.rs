use super::*;
impl_veilid_log_facility!("rtab::route");

/// The size of the compiled route cache
const COMPILED_ROUTE_CACHE_SIZE: usize = 1024;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[must_use]
struct UsedNodesKey {
    node_id: NodeId,
    hop_count: usize,
}

/// A key for the cache that can be used to uniquely identify this route's contents
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[must_use]
pub struct RouteHopCacheKey {
    data: Bytes,
}

impl RouteHopCacheKey {
    pub fn from_hop_node_refs(crypto_kind: CryptoKind, hop_node_refs: &[NodeRef]) -> Self {
        let mut data: BytesMut =
            BytesMut::with_capacity(hop_node_refs.len() * HASH_COORDINATE_LENGTH);
        for hop_node_ref in hop_node_refs {
            let best_hop_node_hc = hop_node_ref
                .node_ids()
                .get(crypto_kind)
                .unwrap_or_log()
                .to_hash_coordinate();
            data.extend_from_slice(best_hop_node_hc.ref_value());
        }

        Self {
            data: data.freeze(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RouteCompileCacheDisposition {
    Compile,
    Optimize,
    Cached(Arc<CompiledRoute>),
}

/// Ephemeral data used to help the RouteSpecStore operate efficiently
#[derive(Debug)]
pub(super) struct RouteSpecStoreCache {
    /// Registry accessor
    registry: VeilidComponentRegistry,
    /// How many times nodes have been used
    used_nodes: HashMap<UsedNodesKey, usize>,
    /// How many times nodes have been used at the terminal point of a route
    used_end_nodes: HashMap<UsedNodesKey, usize>,
    /// Route spec hop cache, used to quickly disqualify routes
    hop_cache: HashSet<RouteHopCacheKey>,

    /// Allocated route info by route id
    allocated_route_set_cache: HashMap<RouteId, AllocatedRouteCacheEntry>,
    /// Allocated route ids indexed by route's public key
    allocated_routes_by_key: HashMap<PublicKey, RouteId>,

    /// Remote private routes we've imported and statistics
    remote_route_set_cache: LruCache<RouteId, RemoteRouteCacheEntry>,
    /// Remote private route ids indexed by route's public key
    remote_routes_by_key: HashMap<PublicKey, RouteId>,

    /// List of dead allocated routes
    dead_allocated_routes: Vec<RouteId>,
    /// List of dead remote routes
    dead_remote_routes: Vec<RouteId>,

    /// Compiled route cache
    compiled_route_cache: Mutex<LruCache<CompiledRouteCacheKey, Arc<CompiledRoute>>>,
}

impl_veilid_component_accessors!(RouteSpecStoreCache);

impl RouteSpecStoreCache {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        Self {
            registry,
            used_nodes: Default::default(),
            used_end_nodes: Default::default(),
            hop_cache: Default::default(),
            allocated_route_set_cache: Default::default(),
            allocated_routes_by_key: Default::default(),
            remote_route_set_cache: LruCache::new(REMOTE_ROUTE_CACHE_SIZE),
            remote_routes_by_key: HashMap::new(),
            dead_allocated_routes: Default::default(),
            dead_remote_routes: Default::default(),
            compiled_route_cache: Mutex::new(LruCache::new(COMPILED_ROUTE_CACHE_SIZE)),
        }
    }

    /// Add an allocated route set to our cache via its cache key
    pub fn add_allocated_route(
        &mut self,
        id: RouteId,
        rssd: &RouteSetSpecDetail,
        hop_node_refs: Vec<NodeRef>,
    ) -> VeilidAPIResult<()> {
        let route_set_keys = rssd.get_route_set_keys();
        let route_set_secrets = rssd.get_route_set_secrets();

        if route_set_keys.is_empty() {
            apibail_internal!("route set keys should not be empty: id={}", id);
        }

        if route_set_secrets.kinds() != route_set_keys.kinds() {
            apibail_internal!(
                "route set secrets should have the same kinds as route set keys: id={}",
                id
            );
        }

        if hop_node_refs.is_empty() {
            apibail_internal!("hop node refs should not be empty: id={}", id);
        }

        let hop_count = hop_node_refs.len();

        let best_crypto_kind = route_set_keys.first().unwrap_or_log().kind();
        let hop_cache_key = RouteHopCacheKey::from_hop_node_refs(best_crypto_kind, &hop_node_refs);
        if !self.hop_cache.insert(hop_cache_key.clone()) {
            apibail_internal!("route should never be inserted twice: id={}", id);
        }

        let arce = AllocatedRouteCacheEntry::new(
            route_set_keys,
            route_set_secrets,
            hop_node_refs.clone(),
            hop_cache_key,
            rssd.is_automatic(),
            rssd.get_directions(),
            rssd.get_stability(),
            rssd.get_orderings(),
            rssd.get_stats(),
        );

        // store in id by key table
        for key in arce.route_set_keys().iter() {
            self.allocated_routes_by_key.insert(key.clone(), id.clone());
        }

        // store entry by id table
        self.allocated_route_set_cache.insert(id, arce);

        // store used nodes caches
        for (idx, hop_node_ref) in hop_node_refs.iter().enumerate() {
            for node_id in hop_node_ref.node_ids().iter() {
                let key = UsedNodesKey {
                    node_id: node_id.clone(),
                    hop_count: hop_node_refs.len(),
                };
                if idx == hop_count - 1 {
                    self.used_end_nodes
                        .entry(key.clone())
                        .and_modify(|e| *e += 1)
                        .or_insert(1);
                }
                self.used_nodes
                    .entry(key)
                    .and_modify(|e| *e += 1)
                    .or_insert(1);
            }
        }

        Ok(())
    }

    /// Checks if an allocated route is in our cache
    pub fn contains_allocated_route_with_hops(&self, cache_key: &RouteHopCacheKey) -> bool {
        self.hop_cache.contains(cache_key)
    }

    /// Removes an allocated route set from our cache
    pub fn remove_allocated_route(&mut self, id: RouteId, is_automatic: bool) -> bool {
        let Some(arce) = self.allocated_route_set_cache.remove(&id) else {
            return false;
        };

        // remove from id by key table
        for key in arce.route_set_keys().iter() {
            if self.allocated_routes_by_key.remove(key).is_none() {
                veilid_log!(self error "allocated_routes_by_key should have contained key: key={}, id={}", key, id);
            }
        }

        // Remove from hop cache table
        let cache_key = arce.hop_cache_key();
        if !self.hop_cache.remove(&cache_key) {
            veilid_log!(self error "hop cache should have contained cache key: id={}", id);
        }

        // Remove from used nodes caches
        let hop_node_refs = arce.hop_node_refs();
        let hop_count = hop_node_refs.len();
        for (idx, hop_node_ref) in hop_node_refs.iter().enumerate() {
            for node_id in hop_node_ref.node_ids().iter() {
                let key = UsedNodesKey {
                    node_id: node_id.clone(),
                    hop_count: hop_node_refs.len(),
                };
                if idx == hop_count - 1 {
                    match self.used_end_nodes.entry(key.clone()) {
                        std::collections::hash_map::Entry::Occupied(mut o) => {
                            *o.get_mut() -= 1;
                            if *o.get() == 0 {
                                o.remove();
                            }
                        }
                        std::collections::hash_map::Entry::Vacant(_) => {
                            veilid_log!(self error "used_end_nodes cache should have contained hop");
                        }
                    }
                }
                match self.used_nodes.entry(key) {
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        *o.get_mut() -= 1;
                        if *o.get() == 0 {
                            o.remove();
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(_) => {
                        veilid_log!(self error "used_nodes cache should have contained hop");
                    }
                }
            }
        }

        // Invalidate compiled route cache for all route keys
        self.invalidate_compiled_route_cache_iter(arce.route_set_keys().iter());

        // Mark it as dead for the update if it wasn't automatically created
        if !is_automatic {
            self.dead_allocated_routes.push(id);
        }

        true
    }

    /// Get an allocated route by id
    pub fn get_allocated_route_by_id(&self, id: &RouteId) -> Option<&AllocatedRouteCacheEntry> {
        self.allocated_route_set_cache.get(id)
    }

    /// Look up a remote private route id by one of the route public keys
    pub fn get_allocated_route_id_by_key(&self, key: &PublicKey) -> Option<RouteId> {
        self.allocated_routes_by_key.get(key).cloned()
    }

    /// Get the number of allocated routes in the cache
    pub fn get_allocated_route_count(&self) -> usize {
        self.allocated_route_set_cache.len()
    }

    /// Iterate all of the allocated routes we have in the cache
    pub fn iter_allocated_routes(
        &self,
    ) -> impl Iterator<Item = (&RouteId, &AllocatedRouteCacheEntry)> {
        self.allocated_route_set_cache.iter()
    }

    /// Calculate how many times a node with a particular node id set has been used anywhere in the path of our allocated routes
    pub fn get_used_node_count(&self, node_ids: &NodeIdGroup, hop_count: usize) -> usize {
        node_ids.iter().fold(0usize, |acc, k| {
            let key = UsedNodesKey {
                node_id: k.clone(),
                hop_count,
            };
            acc + self.used_nodes.get(&key).cloned().unwrap_or_default()
        })
    }

    /// Calculate how many times a node with a particular node id set has been used at the end of the path of our allocated routes
    #[expect(dead_code)]
    pub fn get_used_end_node_count(&self, node_ids: &NodeIdGroup, hop_count: usize) -> usize {
        node_ids.iter().fold(0usize, |acc, k| {
            let key = UsedNodesKey {
                node_id: k.clone(),
                hop_count,
            };
            acc + self.used_end_nodes.get(&key).cloned().unwrap_or_default()
        })
    }

    /// Add remote private route to caches
    fn insert_remote_route_cache_entry(&mut self, id: RouteId, rrce: RemoteRouteCacheEntry) {
        veilid_log!(self debug "Adding remote route to cache: {}, keys=[{}]", id, rrce.get_private_routes().iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","));

        // also store in id by key table
        for private_route in rrce.get_private_routes() {
            self.remote_routes_by_key
                .insert(private_route.public_key.clone(), id.clone());
        }

        let mut dead = None;
        self.remote_route_set_cache
            .insert_with_callback(id, rrce, |dead_id, dead_rrce| {
                dead = Some((dead_id, dead_rrce));
            });

        if let Some((dead_id, dead_rrce)) = dead {
            // If anything LRUs out, remove from the by-key table
            // Follow the same logic as 'remove_remote_private_route' here
            let mut dead_keys = Vec::new();
            for dead_private_route in dead_rrce.get_private_routes() {
                let _ = self
                    .remote_routes_by_key
                    .remove(&dead_private_route.public_key)
                    .unwrap_or_log();
                dead_keys.push(&dead_private_route.public_key);
            }
            self.invalidate_compiled_route_cache_iter(dead_keys);
            self.dead_remote_routes.push(dead_id);
        }
    }

    /// Iterate all of the remote private routes we have in the cache
    pub fn get_remote_route_ids(&self, cur_ts: Timestamp) -> Vec<RouteId> {
        self.remote_route_set_cache
            .iter()
            .filter_map(|(id, rrce)| {
                if !rrce.did_expire(cur_ts) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remote private route cache accessor
    ///
    /// Will LRU entries and may expire entries and not return them if they are stale
    pub fn get_remote_route(
        &mut self,
        cur_ts: Timestamp,
        id: &RouteId,
    ) -> Option<&RemoteRouteCacheEntry> {
        if let Some(rrce) = self.remote_route_set_cache.get(id) {
            if !rrce.did_expire(cur_ts) {
                rrce.touch(cur_ts);
                return Some(rrce);
            }
        }
        None
    }

    /// Remote private route cache accessor without LRU action
    ///
    /// Will not LRU entries but may expire entries and not return them if they are stale
    pub fn peek_remote_route(
        &self,
        cur_ts: Timestamp,
        id: &RouteId,
    ) -> Option<&RemoteRouteCacheEntry> {
        if let Some(rrce) = self.remote_route_set_cache.peek(id) {
            if !rrce.did_expire(cur_ts) {
                rrce.touch(cur_ts);
                return Some(rrce);
            }
        }
        None
    }

    /// Look up a remote private route id by one of the route public keys
    pub fn get_remote_route_id_by_key(&self, key: &PublicKey) -> Option<RouteId> {
        self.remote_routes_by_key.get(key).cloned()
    }

    /// Get or create a remote private route cache entry
    /// may LRU and/or expire other cache entries to make room for the new one
    /// or update an existing entry with the same private route set
    /// returns the route set id
    pub fn add_remote_route(
        &mut self,
        cur_ts: Timestamp,
        id: RouteId,
        private_routes: Vec<Arc<PrivateRoute>>,
    ) {
        // get id for this route set
        if let Some(rrce) = self.get_remote_route(cur_ts, &id) {
            if rrce.did_expire(cur_ts) {
                // Start fresh if this had expired
                rrce.unexpire(cur_ts);
            } else {
                // If not expired, just mark as being used
                rrce.touch(cur_ts);
            }
        } else {
            // New remote private route cache entry
            let rrce = RemoteRouteCacheEntry::new(private_routes, cur_ts);

            self.insert_remote_route_cache_entry(id.clone(), rrce);
            if self.peek_remote_route(cur_ts, &id).is_none() {
                veilid_log!(self error "remote private route should exist");
            };
        };
    }

    /// Remove a remote private route from the cache
    pub fn remove_remote_route(&mut self, id: RouteId) -> bool {
        let Some(rrce) = self.remote_route_set_cache.remove(&id) else {
            return false;
        };
        veilid_log!(self debug "removing remote route from cache {}: keys=[{}]", id, rrce.get_private_routes().iter().map(|x| x.public_key.to_string()).collect::<Vec<_>>().join(","));

        let mut dead_keys = Vec::new();
        for private_route in rrce.get_private_routes() {
            let _ = self
                .remote_routes_by_key
                .remove(&private_route.public_key)
                .unwrap_or_log();

            dead_keys.push(&private_route.public_key);
        }
        self.invalidate_compiled_route_cache_iter(dead_keys);
        self.dead_remote_routes.push(id);
        true
    }

    /// Take the dead local and remote routes so we can update clients
    pub fn take_dead_routes(&mut self) -> Option<(Vec<RouteId>, Vec<RouteId>)> {
        if self.dead_allocated_routes.is_empty() && self.dead_remote_routes.is_empty() {
            // Nothing to do
            return None;
        }
        let dead_allocated_routes = core::mem::take(&mut self.dead_allocated_routes);
        let dead_remote_routes = core::mem::take(&mut self.dead_remote_routes);
        Some((dead_allocated_routes, dead_remote_routes))
    }

    /// Clean up imported remote routes when our peer info changes
    /// Resets statistics assocaited with remote private routes
    pub fn report_peer_info_changed(&self) {
        // Invalidate all of the compiled routes for all routes we have allocated so we can ensure
        // they get re-optimized.
        // Unpublished routes are still valid but the compilation cache will need to be invalidated
        let mut dead_keys = Vec::new();
        for arce in self.allocated_route_set_cache.values() {
            for key in arce.route_set_keys().iter() {
                dead_keys.push(key);
            }
        }
        self.invalidate_compiled_route_cache_iter(dead_keys);

        // Restart start for allocated routes so we test the route again
        for (id, arce) in self.allocated_route_set_cache.iter() {
            // If the route is published it will need to be republished if our peer info changes
            if arce.is_published() {
                // Must republish route now
                arce.set_published(false);

                match arce.with_stats_mut(|s| {
                    s.reset();
                    Ok(())
                }) {
                    Ok(disp) => {
                        self.handle_allocated_route_stats_disposition(id.clone(), arce, None, disp);
                    }
                    Err(e) => {
                        veilid_log!(self error "Error resetting allocated route stats during peer info change: {}", e);
                    }
                }
            }
        }
        // Restart stats for routes so we test the route again
        for (id, rrce) in self.remote_route_set_cache.iter() {
            // Restart stats for routes so we test the route again
            match rrce.with_stats_mut(|s| {
                s.reset();
                Ok(())
            }) {
                Ok(disp) => {
                    self.handle_remote_route_stats_disposition(id.clone(), rrce, None, disp);
                }
                Err(e) => {
                    veilid_log!(self error "Error resetting remote route stats during peer info change: {}", e);
                }
            }
        }
    }

    /// Roll transfer statistics
    pub fn roll_transfers(&self, last_ts: Timestamp, cur_ts: Timestamp) {
        for (id, arce) in self.allocated_route_set_cache.iter() {
            match arce.with_stats_mut(|s| {
                s.roll_transfers(last_ts, cur_ts);
                Ok(())
            }) {
                Ok(disp) => {
                    self.handle_allocated_route_stats_disposition(id.clone(), arce, None, disp);
                }
                Err(e) => {
                    veilid_log!(self error "Error rolling allocated route stats: {}", e);
                }
            }
        }

        for (id, rrce) in self.remote_route_set_cache.iter() {
            match rrce.with_stats_mut(|s| {
                s.roll_transfers(last_ts, cur_ts);
                Ok(())
            }) {
                Ok(disp) => {
                    self.handle_remote_route_stats_disposition(id.clone(), rrce, None, disp);
                }
                Err(e) => {
                    veilid_log!(self error "Error rolling remote route stats: {}", e);
                }
            }
        }
    }

    /// Roll answer statistics
    pub fn roll_answers(&self, cur_ts: Timestamp) {
        for (id, arce) in self.allocated_route_set_cache.iter() {
            match arce.with_stats_mut(|s| {
                s.roll_answers(cur_ts);
                Ok(())
            }) {
                Ok(disp) => {
                    self.handle_allocated_route_stats_disposition(id.clone(), arce, None, disp);
                }
                Err(e) => {
                    veilid_log!(self error "Error rolling allocated route answers: {}", e);
                }
            }
        }
        for (id, rrce) in self.remote_route_set_cache.iter() {
            match rrce.with_stats_mut(|s| {
                s.roll_answers(cur_ts);
                Ok(())
            }) {
                Ok(disp) => {
                    self.handle_remote_route_stats_disposition(id.clone(), rrce, None, disp);
                }
                Err(e) => {
                    veilid_log!(self error "Error rolling remote route answers: {}", e);
                }
            }
        }
    }

    /// Stores a compiled 'safety + private' route so we don't have to compile it again later
    pub fn add_to_compiled_route_cache(
        &self,
        key: CompiledRouteCacheKey,
        compiled_route: Arc<CompiledRoute>,
    ) -> VeilidAPIResult<()> {
        if let Some(existing_compiled_route) = self
            .compiled_route_cache
            .lock()
            .insert(key, compiled_route.clone())
        {
            apibail_internal!("route cache should not contain duplicate entries: existing_compiled_route={:?}, compiled_route={:?}", existing_compiled_route, compiled_route);
        }
        Ok(())
    }

    /// Looks up an existing compiled route from the safety and private route components
    pub fn lookup_compiled_route_cache(
        &self,
        key: &CompiledRouteCacheKey,
    ) -> RouteCompileCacheDisposition {
        // Check the compiled route cache
        // If there's nothing there, then return None so we can compile the route
        let mut crc = self.compiled_route_cache.lock();
        let Some(compiled_route) = crc.get(key).cloned() else {
            return RouteCompileCacheDisposition::Compile;
        };

        // Ensure the safety route is still in the cache
        let safety_route_key = &compiled_route.safety_route.public_key;

        let Some(safety_route_id) = self.get_allocated_route_id_by_key(safety_route_key) else {
            // Safety route no longer exists
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug "Safety route no longer exists for key {}, removing compiled routes from cache", safety_route_key);
            self.invalidate_compiled_route_cache_inner(&mut crc, safety_route_key);
            return RouteCompileCacheDisposition::Compile;
        };

        let Some(arce) = self.get_allocated_route_by_id(&safety_route_id) else {
            veilid_log!(self error "Safety route no longer exists for id {} (key={}), removing compiled routes from cache", safety_route_id, safety_route_key);
            self.invalidate_compiled_route_cache_inner(&mut crc, safety_route_key);
            return RouteCompileCacheDisposition::Compile;
        };

        // Check a cached compiled route and determine if it can be used as-is or needs recompilation.
        // If the cached route is unoptimized but the safety route has since been validated,
        // removes the stale cache entry and signals recompilation.
        if compiled_route.optimized == arce.is_route_optimizable() {
            // If the route has the same optimizability as the cache, then return the cached route
            return RouteCompileCacheDisposition::Cached(compiled_route);
        }

        // Can be reoptimized, or needs to be recompiled unoptimized
        self.invalidate_compiled_route_cache_inner(&mut crc, safety_route_key);

        // If what was in the cache was optimized, then we need to recompile unoptimized
        // If what was in the cache was unoptimized, then we can optimize it now
        if compiled_route.optimized {
            RouteCompileCacheDisposition::Compile
        } else {
            RouteCompileCacheDisposition::Optimize
        }
    }

    /// When routes are dropped or have accumulated failures,
    /// they should be removed from the compiled route cache
    fn invalidate_compiled_route_cache(&self, dead_key: &PublicKey) {
        let mut crc = self.compiled_route_cache.lock();
        self.invalidate_compiled_route_cache_inner(&mut crc, dead_key);
    }

    /// Iterator form of invalidate_compiled_route_cache that avoids repeated locking
    fn invalidate_compiled_route_cache_iter<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a PublicKey> + 'a,
    ) {
        let mut crc = self.compiled_route_cache.lock();
        for key in keys.into_iter() {
            self.invalidate_compiled_route_cache_inner(&mut crc, key);
        }
    }

    fn invalidate_compiled_route_cache_inner(
        &self,
        crc: &mut LruCache<CompiledRouteCacheKey, Arc<CompiledRoute>>,
        dead_key: &PublicKey,
    ) {
        let mut dead_entries = Vec::new();
        for (k, v) in crc.iter() {
            if &v.safety_route.public_key == dead_key
                || &k.pr_pubkey == dead_key
                || k.opt_reply_pr_pubkey
                    .as_ref()
                    .map(|k| k == dead_key)
                    .unwrap_or(false)
            {
                dead_entries.push(k.clone());
            }
        }
        #[cfg(feature = "verbose-tracing")]
        veilid_log!(self debug "Invalidating {} entries from compiled route cache for key {}", dead_entries.len(), dead_key);

        for d in dead_entries {
            crc.remove(&d);
        }
    }

    pub fn update_allocated_route_stats<F>(
        &self,
        _cur_ts: Timestamp,
        key: &PublicKey,
        f: F,
    ) -> VeilidAPIResult<()>
    where
        F: FnOnce(&mut RouteStats) -> VeilidAPIResult<()>,
    {
        if let Some(rid) = self.get_allocated_route_id_by_key(key) {
            if let Some(arce) = self.get_allocated_route_by_id(&rid) {
                let disposition = arce.with_stats_mut(f)?;
                self.handle_allocated_route_stats_disposition(rid, arce, Some(key), disposition);
            }
        }

        Ok(())
    }

    pub fn update_remote_route_stats<F>(
        &self,
        cur_ts: Timestamp,
        key: &PublicKey,
        f: F,
    ) -> VeilidAPIResult<()>
    where
        F: FnOnce(&mut RouteStats) -> VeilidAPIResult<()>,
    {
        if let Some(rrid) = self.get_remote_route_id_by_key(key) {
            if let Some(rrce) = self.peek_remote_route(cur_ts, &rrid) {
                let disposition = rrce.with_stats_mut(f)?;
                self.handle_remote_route_stats_disposition(rrid, rrce, Some(key), disposition);
            }
        }

        Ok(())
    }

    fn handle_allocated_route_stats_disposition(
        &self,
        id: RouteId,
        arce: &AllocatedRouteCacheEntry,
        key: Option<&PublicKey>,
        disposition: RouteStatsDisposition,
    ) {
        let all_keys = arce.route_set_keys().to_vec();
        match disposition {
            RouteStatsDisposition::InvalidSendFailure => {
                veilid_log!(self debug "Allocated route {}{} exceeded send failure threshold, invalidating compiled route cache", id, key.map(|k| format!("(key={})",k)).unwrap_or_default());
                self.invalidate_compiled_route_cache_iter(all_keys.iter());
            }
            RouteStatsDisposition::InvalidLostAnswers => {
                veilid_log!(self debug "Allocated route {}{} exceeded lost destination threshold, invalidating compiled route cache",id, key.map(|k| format!("(key={})",k)).unwrap_or_default());
                self.invalidate_compiled_route_cache_iter(all_keys.iter());
            }
            RouteStatsDisposition::Locked | RouteStatsDisposition::Valid => {}
        }
    }

    fn handle_remote_route_stats_disposition(
        &self,
        id: RouteId,
        rrce: &RemoteRouteCacheEntry,
        key: Option<&PublicKey>,
        disposition: RouteStatsDisposition,
    ) {
        let all_keys = rrce
            .get_private_routes()
            .iter()
            .map(|pr| pr.public_key.clone())
            .collect::<Vec<_>>();

        match disposition {
            RouteStatsDisposition::InvalidSendFailure => {
                veilid_log!(self debug "Remote route {}{} exceeded send failure threshold, invalidating compiled route cache", id, key.map(|k| format!("(key={})",k)).unwrap_or_default());
                for key in all_keys.iter() {
                    self.invalidate_compiled_route_cache(key);
                }
            }
            RouteStatsDisposition::InvalidLostAnswers => {
                veilid_log!(self debug "Remote route {}{} exceeded lost destination threshold, invalidating compiled route cache",id, key.map(|k| format!("(key={})",k)).unwrap_or_default());
                for key in all_keys.iter() {
                    self.invalidate_compiled_route_cache(key);
                }
            }
            RouteStatsDisposition::Locked | RouteStatsDisposition::Valid => {}
        }
    }
}
