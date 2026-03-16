use super::*;
impl_veilid_log_facility!("rtab");

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct UsedNodesKey {
    pub node_id: NodeId,
    pub hop_count: usize,
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
    hop_cache: HashSet<Vec<u8>>,
    /// Remote private routes we've imported and statistics
    remote_private_route_set_cache: LruCache<RouteId, RemotePrivateRouteInfo>,
    /// Remote private route ids indexed by route's public key
    remote_private_routes_by_key: HashMap<PublicKey, RouteId>,
    /// List of dead allocated routes
    dead_routes: Vec<RouteId>,
    /// List of dead remote routes
    dead_remote_routes: Vec<RouteId>,
}

impl_veilid_component_accessors!(RouteSpecStoreCache);

impl RouteSpecStoreCache {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        Self {
            registry,
            used_nodes: Default::default(),
            used_end_nodes: Default::default(),
            hop_cache: Default::default(),
            remote_private_route_set_cache: LruCache::new(REMOTE_PRIVATE_ROUTE_CACHE_SIZE),
            remote_private_routes_by_key: HashMap::new(),
            dead_routes: Default::default(),
            dead_remote_routes: Default::default(),
        }
    }

    /// add an allocated route set to our cache via its cache key
    pub fn add_to_cache(&mut self, rssd: &RouteSetSpecDetail) {
        let cache_key = rssd.make_cache_key();
        if !self.hop_cache.insert(cache_key) {
            veilid_log!(self error "route should never be inserted twice");
            return;
        }
        for (_pk, rsd) in rssd.iter_route_set() {
            for h in &rsd.hops {
                let key = UsedNodesKey {
                    node_id: h.clone(),
                    hop_count: rsd.hops.len(),
                };

                self.used_nodes
                    .entry(key)
                    .and_modify(|e| *e += 1)
                    .or_insert(1);
            }
            let key = UsedNodesKey {
                node_id: rsd.hops.last().unwrap_or_log().clone(),
                hop_count: rsd.hops.len(),
            };
            self.used_end_nodes
                .entry(key)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }
    }

    /// checks if an allocated route is in our cache
    pub fn contains_route(&self, cache_key: &Vec<u8>) -> bool {
        self.hop_cache.contains(cache_key)
    }

    /// removes an allocated route set from our cache
    pub fn remove_from_cache<C>(
        &mut self,
        id: RouteId,
        rssd: &RouteSetSpecDetail,
        invalidation_callback: C,
    ) -> bool
    where
        C: Fn(&PublicKey),
    {
        let cache_key = rssd.make_cache_key();

        // Remove from hop cache
        if !self.hop_cache.remove(&cache_key) {
            return false;
        }
        for (pk, rsd) in rssd.iter_route_set() {
            for h in &rsd.hops {
                // Remove from used nodes cache
                let key = UsedNodesKey {
                    node_id: h.clone(),
                    hop_count: rsd.hops.len(),
                };
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
            // Remove from end nodes cache
            let key = UsedNodesKey {
                node_id: rsd.hops.last().unwrap_or_log().clone(),
                hop_count: rsd.hops.len(),
            };

            match self.used_end_nodes.entry(key) {
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

            // Invalidate compiled route cache
            invalidation_callback(pk);
        }

        // Mark it as dead for the update if it wasn't automatically created
        if !rssd.is_automatic() {
            self.dead_routes.push(id);
        }

        true
    }

    /// calculate how many times a node with a particular node id set has been used anywhere in the path of our allocated routes
    pub fn get_used_node_count(&self, node_ids: &NodeIdGroup, hop_count: usize) -> usize {
        node_ids.iter().fold(0usize, |acc, k| {
            let key = UsedNodesKey {
                node_id: k.clone(),
                hop_count,
            };
            acc + self.used_nodes.get(&key).cloned().unwrap_or_default()
        })
    }

    /// calculate how many times a node with a particular node id set has been used at the end of the path of our allocated routes
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

    /// add remote private route to caches
    fn add_remote_private_route<C>(
        &mut self,
        id: RouteId,
        rprinfo: RemotePrivateRouteInfo,
        invalidation_callback: C,
    ) where
        C: Fn(&PublicKey),
    {
        // also store in id by key table
        for private_route in rprinfo.get_private_routes() {
            self.remote_private_routes_by_key
                .insert(private_route.public_key.clone(), id.clone());
        }

        let mut dead = None;
        self.remote_private_route_set_cache.insert_with_callback(
            id,
            rprinfo,
            |dead_id, dead_rpri| {
                dead = Some((dead_id, dead_rpri));
            },
        );

        if let Some((dead_id, dead_rpri)) = dead {
            // If anything LRUs out, remove from the by-key table
            // Follow the same logic as 'remove_remote_private_route' here
            for dead_private_route in dead_rpri.get_private_routes() {
                let _ = self
                    .remote_private_routes_by_key
                    .remove(&dead_private_route.public_key)
                    .unwrap_or_log();
                invalidation_callback(&dead_private_route.public_key);
            }
            self.dead_remote_routes.push(dead_id);
        }
    }

    /// iterate all of the remote private routes we have in the cache
    pub fn get_remote_private_route_ids(&self, cur_ts: Timestamp) -> Vec<RouteId> {
        self.remote_private_route_set_cache
            .iter()
            .filter_map(|(id, rpri)| {
                if !rpri.did_expire(cur_ts) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// remote private route cache accessor
    /// will LRU entries and may expire entries and not return them if they are stale
    pub fn get_remote_private_route(
        &mut self,
        cur_ts: Timestamp,
        id: &RouteId,
    ) -> Option<&RemotePrivateRouteInfo> {
        if let Some(rpri) = self.remote_private_route_set_cache.get(id) {
            if !rpri.did_expire(cur_ts) {
                rpri.touch(cur_ts);
                return Some(rpri);
            }
        }
        None
    }

    /// remote private route cache accessor without lru action
    /// will not LRU entries but may expire entries and not return them if they are stale
    pub fn peek_remote_private_route(
        &self,
        cur_ts: Timestamp,
        id: &RouteId,
    ) -> Option<&RemotePrivateRouteInfo> {
        if let Some(rpri) = self.remote_private_route_set_cache.peek(id) {
            if !rpri.did_expire(cur_ts) {
                rpri.touch(cur_ts);
                return Some(rpri);
            }
        }
        None
    }

    /// look up a remote private route id by one of the route public keys
    pub fn get_remote_private_route_id_by_key(&self, key: &PublicKey) -> Option<RouteId> {
        self.remote_private_routes_by_key.get(key).cloned()
    }

    /// get or create a remote private route cache entry
    /// may LRU and/or expire other cache entries to make room for the new one
    /// or update an existing entry with the same private route set
    /// returns the route set id
    pub fn cache_remote_private_route<C>(
        &mut self,
        cur_ts: Timestamp,
        id: RouteId,
        private_routes: Vec<Arc<PrivateRoute>>,
        invalidation_callback: C,
    ) where
        C: Fn(&PublicKey),
    {
        // get id for this route set
        if let Some(rpri) = self.get_remote_private_route(cur_ts, &id) {
            if rpri.did_expire(cur_ts) {
                // Start fresh if this had expired
                rpri.unexpire(cur_ts);
            } else {
                // If not expired, just mark as being used
                rpri.touch(cur_ts);
            }
        } else {
            // New remote private route cache entry
            let rpri = RemotePrivateRouteInfo::new(private_routes, cur_ts);

            self.add_remote_private_route(id.clone(), rpri, invalidation_callback);
            if self.peek_remote_private_route(cur_ts, &id).is_none() {
                veilid_log!(self error "remote private route should exist");
            };
        };
    }

    /// remove a remote private route from the cache
    pub fn remove_remote_private_route<C>(&mut self, id: RouteId, invalidation_callback: C) -> bool
    where
        C: Fn(&PublicKey),
    {
        let Some(rprinfo) = self.remote_private_route_set_cache.remove(&id) else {
            return false;
        };
        for private_route in rprinfo.get_private_routes() {
            let _ = self
                .remote_private_routes_by_key
                .remove(&private_route.public_key)
                .unwrap_or_log();
            invalidation_callback(&private_route.public_key);
        }
        self.dead_remote_routes.push(id);
        true
    }

    /// Take the dead local and remote routes so we can update clients
    pub fn take_dead_routes(&mut self) -> Option<(Vec<RouteId>, Vec<RouteId>)> {
        if self.dead_routes.is_empty() && self.dead_remote_routes.is_empty() {
            // Nothing to do
            return None;
        }
        let dead_routes = core::mem::take(&mut self.dead_routes);
        let dead_remote_routes = core::mem::take(&mut self.dead_remote_routes);
        Some((dead_routes, dead_remote_routes))
    }

    /// Clean up imported remote routes
    /// Resets statistics for when our node info changes
    pub fn reset_remote_private_routes(&self) {
        // Restart stats for routes so we test the route again
        for (_k, v) in self.remote_private_route_set_cache.iter() {
            v.with_stats_mut(|s| s.reset());
        }
    }

    /// Roll transfer statistics
    pub fn roll_transfers(&self, last_ts: Timestamp, cur_ts: Timestamp) {
        for (_k, v) in self.remote_private_route_set_cache.iter() {
            v.with_stats_mut(|s| s.roll_transfers(last_ts, cur_ts));
        }
    }
    /// Roll answer statistics
    pub fn roll_answers(&self, cur_ts: Timestamp) {
        for (_k, v) in self.remote_private_route_set_cache.iter() {
            v.with_stats_mut(|s| s.roll_answers(cur_ts));
        }
    }
}
