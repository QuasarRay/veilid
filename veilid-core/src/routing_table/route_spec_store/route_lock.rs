use super::*;

/// Tracks locked safety routes with per-key lock counts for correct unlock semantics
#[derive(Debug)]
#[must_use]
pub struct LockedRoutes {
    registry: VeilidComponentRegistry,
    allocated_lock_counts: HashMap<PublicKey, usize>,
    remote_lock_counts: HashMap<PublicKey, usize>,
}

impl_veilid_component_accessors!(LockedRoutes);

impl LockedRoutes {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        Self {
            registry,
            allocated_lock_counts: HashMap::new(),
            remote_lock_counts: HashMap::new(),
        }
    }

    fn insert_allocated(&mut self, key: PublicKey) {
        *self.allocated_lock_counts.entry(key).or_insert(0) += 1;
    }

    fn insert_remote(&mut self, key: PublicKey) {
        *self.remote_lock_counts.entry(key).or_insert(0) += 1;
    }

    pub fn take_from(&mut self, other: &mut Self) {
        for (key, count) in core::mem::take(&mut other.allocated_lock_counts) {
            *self.allocated_lock_counts.entry(key).or_default() += count;
        }
        for (key, count) in core::mem::take(&mut other.remote_lock_counts) {
            *self.remote_lock_counts.entry(key).or_default() += count;
        }
    }

    pub fn take(&mut self) -> Self {
        Self {
            registry: self.registry.clone(),
            allocated_lock_counts: core::mem::take(&mut self.allocated_lock_counts),
            remote_lock_counts: core::mem::take(&mut self.remote_lock_counts),
        }
    }

    pub fn len(&self) -> usize {
        self.allocated_lock_counts.len() + self.remote_lock_counts.len()
    }

    #[expect(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.allocated_lock_counts.is_empty() && self.remote_lock_counts.is_empty()
    }
}

impl fmt::Display for LockedRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "allocated=[{}] remote=[{}]",
            self.allocated_lock_counts
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(","),
            self.remote_lock_counts
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

impl Drop for LockedRoutes {
    fn drop(&mut self) {
        if self.allocated_lock_counts.is_empty() && self.remote_lock_counts.is_empty() {
            return;
        }

        let routing_table = self.routing_table();
        let rss = routing_table.route_spec_store();
        for (key, count) in core::mem::take(&mut self.allocated_lock_counts) {
            rss.unlock_allocated_route_with_count(&key, count);
        }
        for (key, count) in core::mem::take(&mut self.remote_lock_counts) {
            rss.unlock_remote_route_with_count(&key, count);
        }
    }
}

impl RouteSpecStore {
    /// Lock an allocated route from invalidation by its public key
    pub fn lock_allocated_routes_by_keys(&self, keys: &[PublicKey]) -> LockedRoutes {
        let mut locked_routes = LockedRoutes::new(self.registry());
        for key in keys {
            self.update_allocated_route_stats(Timestamp::now(), key, |stats| {
                if stats.lock_count == usize::MAX {
                    apibail_internal!("allocated lock count overflow for key {}", key);
                }
                stats.lock_count += 1;
                Ok(())
            });
            locked_routes.insert_allocated(key.clone());
        }
        locked_routes
    }

    /// Lock a remote route from invalidation by its public key
    pub fn lock_remote_routes_by_keys(&self, keys: &[PublicKey]) -> LockedRoutes {
        let mut locked_routes = LockedRoutes::new(self.registry());
        for key in keys {
            self.update_remote_route_stats(Timestamp::now(), key, |stats| {
                if stats.lock_count == usize::MAX {
                    apibail_internal!("remote lock count overflow for key {}", key);
                }
                stats.lock_count += 1;
                Ok(())
            });
            locked_routes.insert_remote(key.clone());
        }
        locked_routes
    }

    /// Unlock an allocatedroute with some count which will also check if it should be invalidated now
    fn unlock_allocated_route_with_count(&self, key: &PublicKey, count: usize) {
        self.update_allocated_route_stats(Timestamp::now(), key, |stats| {
            if stats.lock_count < count {
                apibail_internal!(
                    "lock count exceeded on allocated unlock: {} < {}",
                    stats.lock_count,
                    count
                );
            }
            stats.lock_count -= count;
            Ok(())
        });
    }

    /// Unlock a remote route with some count which will also check if it should be invalidated now
    fn unlock_remote_route_with_count(&self, key: &PublicKey, count: usize) {
        self.update_remote_route_stats(Timestamp::now(), key, |stats| {
            if stats.lock_count < count {
                apibail_internal!(
                    "lock count exceeded on remote unlock: {} < {}",
                    stats.lock_count,
                    count
                );
            }
            stats.lock_count -= count;
            Ok(())
        });
    }
}
