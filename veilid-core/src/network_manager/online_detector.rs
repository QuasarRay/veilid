use super::*;

impl_veilid_log_facility!("net");

/// Distinct previously-seen targets that must time out (no intervening success) for the
/// local node to be considered offline.
pub const OFFLINE_DETECTION_FAILURE_THRESHOLD: usize = 4;

/// Bounds the seen-successfully LRU per routing domain.
const SEEN_SUCCESSFULLY_CACHE_SIZE: usize = 1024;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum OnlineState {
    #[default]
    Online,
    Offline,
}

#[derive(Debug)]
struct OnlineDetectionPerDomain {
    /// Node ids previously reached successfully since the last network address change,
    /// keyed by the timestamp of the last success.
    seen_successfully: hashlink::LruCache<NodeId, Timestamp>,
    /// Subset of seen_successfully with a recent failure and no intervening success.
    pending_failures: BTreeSet<NodeId>,
    last_success_ts: Option<Timestamp>,
    online_state: OnlineState,
}

impl Default for OnlineDetectionPerDomain {
    fn default() -> Self {
        Self {
            seen_successfully: hashlink::LruCache::new(SEEN_SUCCESSFULLY_CACHE_SIZE),
            pending_failures: BTreeSet::new(),
            last_success_ts: None,
            online_state: OnlineState::default(),
        }
    }
}

pub struct OnlineDetector {
    registry: VeilidComponentRegistry,
    inner: Mutex<BTreeMap<RoutingDomain, OnlineDetectionPerDomain>>,
}

impl_veilid_component_accessors!(OnlineDetector);

impl fmt::Debug for OnlineDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnlineDetector")
            .field("inner", &*self.inner.lock())
            .finish()
    }
}

impl OnlineDetector {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        Self {
            registry,
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Only PublicInternet uses ping-based detection; other domains will plug in their own
    /// domain-appropriate signals (LocalNetwork: interface link state; future hardware-mesh: carrier).
    fn uses_ping_detection(routing_domain: RoutingDomain) -> bool {
        matches!(routing_domain, RoutingDomain::PublicInternet)
    }

    /// Record an RPC failure. Failures only count toward the offline threshold if the target
    /// has been reached successfully since the last network address change, AND the RPC was
    /// sent after the most recent success — failures from RPCs that were already in flight
    /// when a success arrived are stale and don't indicate the network is offline.
    pub fn record_failure(
        &self,
        routing_domain: RoutingDomain,
        node_id: NodeId,
        send_ts: Timestamp,
    ) -> Option<OnlineState> {
        if !Self::uses_ping_detection(routing_domain) {
            return None;
        }

        let transition = {
            let mut inner = self.inner.lock();
            let pd = inner.entry(routing_domain).or_default();
            let last_seen_successfully = pd.seen_successfully.get(&node_id).copied()?;

            // Discard failures from RPCs sent before the most recent success;
            // they were already in flight when we got proof we're online.
            if let Some(last_success_ts) = pd.last_success_ts {
                if send_ts <= last_success_ts {
                    return None;
                }
            }

            pd.pending_failures.insert(node_id);
            if pd.online_state == OnlineState::Online
                && pd.pending_failures.len() >= OFFLINE_DETECTION_FAILURE_THRESHOLD
            {
                pd.online_state = OnlineState::Offline;
                Some((OnlineState::Offline, last_seen_successfully))
            } else {
                None
            }
        };

        if let Some((new_state, last_success)) = transition {
            let elapsed = Timestamp::now().duration_since(last_success);
            veilid_log!(self info
                "{:?} offline detected ({} distinct failures, last success {:#} ago)",
                routing_domain, OFFLINE_DETECTION_FAILURE_THRESHOLD, elapsed
            );
            Some(new_state)
        } else {
            None
        }
    }

    /// Record a successful RPC. Each provided node id is added/refreshed in the
    /// seen-successfully LRU so future failures from it can count toward the offline threshold.
    /// Pass an empty iterator when the sender/round-trip identity isn't known (e.g. raw envelope receive).
    pub fn record_success<I: IntoIterator<Item = NodeId>>(
        &self,
        routing_domain: RoutingDomain,
        node_ids: I,
    ) -> Option<OnlineState> {
        if !Self::uses_ping_detection(routing_domain) {
            return None;
        }

        let now = Timestamp::now();
        let transition = {
            let mut inner = self.inner.lock();
            let pd = inner.entry(routing_domain).or_default();
            for node_id in node_ids {
                pd.seen_successfully.insert(node_id, now);
            }
            pd.pending_failures.clear();
            pd.last_success_ts = Some(now);
            if pd.online_state == OnlineState::Offline {
                pd.online_state = OnlineState::Online;
                Some(OnlineState::Online)
            } else {
                None
            }
        };

        if transition.is_some() {
            veilid_log!(self info "{:?} online detected", routing_domain);
        }

        transition
    }

    /// Local network addresses changed: clear the seen and failure sets and presume offline
    /// until a new RPC succeeds.
    pub fn network_address_change(&self, routing_domain: RoutingDomain) {
        if !Self::uses_ping_detection(routing_domain) {
            return;
        }

        let transition = {
            let mut inner = self.inner.lock();
            let pd = inner.entry(routing_domain).or_default();
            pd.seen_successfully.clear();
            pd.pending_failures.clear();
            pd.last_success_ts = None;
            if pd.online_state == OnlineState::Online {
                pd.online_state = OnlineState::Offline;
                Some(OnlineState::Offline)
            } else {
                None
            }
        };

        if transition.is_some() {
            veilid_log!(self info
                "{:?} offline detected (network address change)",
                routing_domain
            );
        }
    }

    /// Returns Online for any domain not using ping-based detection.
    pub fn online_state(&self, routing_domain: RoutingDomain) -> OnlineState {
        if !Self::uses_ping_detection(routing_domain) {
            return OnlineState::Online;
        }
        self.inner
            .lock()
            .get(&routing_domain)
            .map(|pd| pd.online_state)
            .unwrap_or_default()
    }

    #[expect(dead_code)]
    pub fn last_success_ts(&self, routing_domain: RoutingDomain) -> Option<Timestamp> {
        self.inner
            .lock()
            .get(&routing_domain)
            .and_then(|pd| pd.last_success_ts)
    }
}
