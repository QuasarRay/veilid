use super::*;

/// What remote private routes have seen
#[derive(Debug, Default)]
pub struct RemoteRouteCacheEntry {
    /// The private routes themselves
    private_routes: Vec<Arc<PrivateRoute>>,
    /// Did this remote private route see our node info due to no safety route in use
    last_seen_our_node_info_ts: AtomicOptionTimestamp,
    /// Last time this remote private route was requested for any reason (cache expiration)
    last_touched_ts: AtomicTimestamp,
    /// Stats
    stats: RwLock<RouteStats>,
}

impl fmt::Display for RemoteRouteCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (latency_stats, transfer_stats) = self.with_stats(|s| {
            (
                s.latency_stats().to_string(),
                s.transfer_stats().to_string(),
            )
        });
        write!(
            f,
            "last_seen_our_ni={} last_touched={} latency={} transfer={}",
            self.last_seen_our_node_info_ts, self.last_touched_ts, latency_stats, transfer_stats
        )
    }
}
impl RemoteRouteCacheEntry {
    pub fn new(private_routes: Vec<Arc<PrivateRoute>>, cur_ts: Timestamp) -> Self {
        RemoteRouteCacheEntry {
            private_routes,
            last_seen_our_node_info_ts: AtomicOptionTimestamp::none(),
            last_touched_ts: AtomicTimestamp::new(cur_ts),
            stats: RwLock::new(RouteStats::new(cur_ts)),
        }
    }
    pub fn get_private_routes(&self) -> &[Arc<PrivateRoute>] {
        &self.private_routes
    }
    pub fn best_private_route(&self) -> Option<Arc<PrivateRoute>> {
        self.private_routes
            .iter()
            .reduce(|acc, x| {
                if x.public_key < acc.public_key {
                    x
                } else {
                    acc
                }
            })
            .filter(|x| VALID_CRYPTO_KINDS.contains(&x.public_key.kind()))
            .cloned()
    }

    pub fn with_stats<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&RouteStats) -> R,
    {
        let stats = self.stats.read();
        f(&stats)
    }

    pub(super) fn with_stats_mut<F>(&self, f: F) -> VeilidAPIResult<RouteStatsDisposition>
    where
        F: FnOnce(&mut RouteStats) -> VeilidAPIResult<()>,
    {
        let mut stats = self.stats.write();
        f(&mut stats)?;
        Ok(stats.disposition())
    }

    pub fn has_seen_our_node_info_ts(&self, our_node_info_ts: Timestamp) -> bool {
        self.last_seen_our_node_info_ts.get() == Some(our_node_info_ts)
    }
    pub fn set_last_seen_our_node_info_ts(&self, last_seen_our_node_info_ts: Timestamp) {
        self.last_seen_our_node_info_ts
            .set(Some(last_seen_our_node_info_ts));
    }

    // Check to see if this remote private route has expired
    pub fn did_expire(&self, cur_ts: Timestamp) -> bool {
        self.last_touched_ts
            .expiration_state(cur_ts, REMOTE_PRIVATE_ROUTE_CACHE_EXPIRY)
            == ExpirationState::Dead
    }

    /// Start fresh if this had expired
    pub fn unexpire(&self, cur_ts: Timestamp) {
        self.last_seen_our_node_info_ts.set(None);
        self.last_touched_ts.set(cur_ts);
        *self.stats.write() = RouteStats::new(cur_ts);
    }

    /// Note when this was last used
    pub fn touch(&self, cur_ts: Timestamp) {
        self.last_touched_ts.set(cur_ts)
    }
}
