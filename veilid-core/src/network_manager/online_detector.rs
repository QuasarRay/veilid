use super::*;

impl_veilid_log_facility!("net");

/// Distinct previously-live targets that must fail on the stream socket class, with no
/// intervening success, for the local node to be considered offline.
pub const OFFLINE_DETECTION_FAILURE_THRESHOLD_STREAM: usize = 4;
/// Same, but for the datagram socket class.
pub const OFFLINE_DETECTION_FAILURE_THRESHOLD_DATAGRAM: usize = 4;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum OnlineState {
    #[default]
    Online,
    Offline,
}

/// Failure count threshold for a socket class.
fn failure_threshold(socket_type: SocketType) -> usize {
    match socket_type {
        SocketType::Stream => OFFLINE_DETECTION_FAILURE_THRESHOLD_STREAM,
        SocketType::Datagram => OFFLINE_DETECTION_FAILURE_THRESHOLD_DATAGRAM,
    }
}

/// Events that drive the online/offline state machine.
enum OnlineEvent {
    /// Received something from outside.
    Success,
    /// Failures for previously-live nodes on one socket class.
    Failure {
        live_node_ids: Vec<NodeId>,
        sent_ts: Timestamp,
        socket_type: SocketType,
    },
    /// The local network address changed.
    NetworkChange,
}

/// Per-routing-domain online/offline tracking.
#[derive(Debug)]
struct OnlineDetectionPerDomain {
    /// Previously-live nodes that failed on each socket class since the last success.
    pending_failures: BTreeMap<SocketType, BTreeSet<NodeId>>,
    /// When we last switched online/offline.
    last_transition_ts: Timestamp,
    /// Current state.
    online_state: OnlineState,
    /// Flap detector over online_state.
    flap_detector: FlapDetector<OnlineState>,
}

impl Default for OnlineDetectionPerDomain {
    fn default() -> Self {
        Self {
            pending_failures: BTreeMap::new(),
            last_transition_ts: Timestamp::new(0),
            online_state: OnlineState::default(),
            // 4 online/offline flips within ~60s = flapping
            flap_detector: FlapDetector::new_secs(4.0, 60),
        }
    }
}

pub struct OnlineDetector {
    registry: VeilidComponentRegistry,
    inner: Mutex<BTreeMap<RoutingDomain, OnlineDetectionPerDomain>>,
    /// Socket classes the network uses; only these gate offline detection.
    enabled_socket_types: Mutex<SocketTypeSet>,
}

impl_veilid_component_accessors!(OnlineDetector);

impl fmt::Debug for OnlineDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnlineDetector")
            .field("inner", &*self.inner.lock())
            .field("enabled_socket_types", &*self.enabled_socket_types.lock())
            .finish()
    }
}

impl OnlineDetector {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        Self {
            registry,
            inner: Mutex::new(BTreeMap::new()),
            // Require both classes until the network reports its protocol config.
            enabled_socket_types: Mutex::new(SocketTypeSet::all()),
        }
    }

    /// Whether this routing domain uses ping-based online detection.
    fn uses_ping_detection(routing_domain: RoutingDomain) -> bool {
        // Other domains will plug in their own signals (LocalNetwork: interface link state).
        matches!(routing_domain, RoutingDomain::PublicInternet)
    }

    /// Set which socket classes offline detection requires, from the network protocol config.
    pub fn set_protocol_config(&self, outbound: ProtocolTypeSet, inbound: ProtocolTypeSet) {
        let mut socket_types = SocketTypeSet::new();
        for pt in outbound | inbound {
            socket_types.insert(pt.low_level_protocol_type().socket_type());
        }
        *self.enabled_socket_types.lock() = socket_types;
    }

    /// Record a successful round-trip.
    pub fn record_success(&self, routing_domain: RoutingDomain) {
        self.process_event(routing_domain, OnlineEvent::Success);
    }

    /// Record RPC failures against the attempted nodes (direct target, or routed hops).
    pub fn record_failure(
        &self,
        routing_domain: RoutingDomain,
        node_ids: impl IntoIterator<Item = NodeId>,
        sent_ts: Timestamp,
        transport: TransportType,
    ) {
        if !Self::uses_ping_detection(routing_domain) {
            return;
        }
        // Only previously-live nodes count: a dead node we probe timing out isn't evidence
        // that *we* are offline. Read liveness now, before the caller's lost-answer /
        // failed-to-send handler clears first_consecutive_seen_ts.
        let routing_table = self.routing_table();
        let live_node_ids: Vec<NodeId> = node_ids
            .into_iter()
            .filter(|node_id| {
                routing_table
                    .lookup_node_id(node_id.clone())
                    .ok()
                    .flatten()
                    .is_some_and(|nr| {
                        nr.peer_stats()
                            .rpc_stats
                            .first_consecutive_seen_ts
                            .is_some()
                    })
            })
            .collect();
        if live_node_ids.is_empty() {
            return;
        }
        self.process_event(
            routing_domain,
            OnlineEvent::Failure {
                live_node_ids,
                sent_ts,
                socket_type: transport.socket_type(),
            },
        );
    }

    /// Local network addresses changed: presume offline until a new RPC succeeds.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    pub fn network_address_change(&self, routing_domain: RoutingDomain) {
        self.process_event(routing_domain, OnlineEvent::NetworkChange);
    }

    /// Current online state for a routing domain.
    pub fn online_state(&self, routing_domain: RoutingDomain) -> OnlineState {
        // Domains without ping detection are always considered online.
        if !Self::uses_ping_detection(routing_domain) {
            return OnlineState::Online;
        }
        self.inner
            .lock()
            .get(&routing_domain)
            .map(|pd| pd.online_state)
            .unwrap_or_default()
    }

    /// Drive the state machine with an event, dispatching to the current state's handler.
    fn process_event(&self, routing_domain: RoutingDomain, event: OnlineEvent) {
        if !Self::uses_ping_detection(routing_domain) {
            return;
        }
        let enabled_socket_types = *self.enabled_socket_types.lock();
        let now = Timestamp::now();

        let (opt_new_state, opt_flap_penalty) = {
            let mut inner = self.inner.lock();
            let pd = inner.entry(routing_domain).or_default();
            let opt_new_state = match pd.online_state {
                OnlineState::Offline => Self::process_offline_event(&event),
                OnlineState::Online => Self::process_online_event(pd, &event, enabled_socket_types),
            };
            let mut opt_flap_penalty = None;
            if let Some(new_state) = opt_new_state {
                pd.online_state = new_state;
                pd.last_transition_ts = now;
                opt_flap_penalty = pd.flap_detector.record(now.as_u64(), new_state);
            }
            (opt_new_state, opt_flap_penalty)
        };

        // Log the transition (and any flapping) outside the lock.
        if let Some(new_state) = opt_new_state {
            veilid_log!(self info "{:?} {} detected", routing_domain,
                if new_state == OnlineState::Online { "online" } else { "offline" });
        }
        if let Some(penalty) = opt_flap_penalty {
            veilid_log!(self debugwarn "{:?} online state FLAPPING (penalty={:.1})", routing_domain, penalty);
        }
    }

    /// Handle an event while offline.
    fn process_offline_event(event: &OnlineEvent) -> Option<OnlineState> {
        match event {
            // Any success means we're back online.
            OnlineEvent::Success => Some(OnlineState::Online),
            OnlineEvent::Failure { .. } | OnlineEvent::NetworkChange => None,
        }
    }

    /// Handle an event while online.
    fn process_online_event(
        pd: &mut OnlineDetectionPerDomain,
        event: &OnlineEvent,
        enabled_socket_types: SocketTypeSet,
    ) -> Option<OnlineState> {
        match event {
            OnlineEvent::Success => {
                pd.pending_failures.clear();
                None
            }
            OnlineEvent::Failure {
                live_node_ids,
                sent_ts,
                socket_type,
            } => {
                // Ignore failures from RPCs sent before this online period began.
                if *sent_ts < pd.last_transition_ts {
                    return None;
                }
                let bucket = pd.pending_failures.entry(*socket_type).or_default();
                for node_id in live_node_ids {
                    bucket.insert(node_id.clone());
                }
                // Offline only when every enabled socket class has crossed its threshold, so
                // localized trouble on one class doesn't drive offline while another works.
                let all_failed = !enabled_socket_types.is_empty()
                    && enabled_socket_types.iter().all(|st| {
                        pd.pending_failures.get(&st).map_or(0, BTreeSet::len)
                            >= failure_threshold(st)
                    });
                if all_failed {
                    pd.pending_failures.clear();
                    return Some(OnlineState::Offline);
                }
                None
            }
            OnlineEvent::NetworkChange => {
                pd.pending_failures.clear();
                Some(OnlineState::Offline)
            }
        }
    }
}
