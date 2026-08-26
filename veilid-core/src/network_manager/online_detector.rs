use super::*;

impl_veilid_log_facility!("net");

/// Distinct previously-live targets that must fail on the stream framing type, with no
/// intervening success, for the local node to be considered offline.
pub const OFFLINE_DETECTION_FAILURE_THRESHOLD_CONNECTION: usize = 4;
/// Same, but for the datagram socket class.
pub const OFFLINE_DETECTION_FAILURE_THRESHOLD_MESSAGE: usize = 4;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum OnlineState {
    /// Round trips complete and failure evidence is trustworthy
    #[default]
    Online,
    /// Round trips complete but failure evidence is about us; blame writers hold fire
    Degraded,
    /// Nothing gets through; blame and recovery behaviors both gate
    Offline,
}

impl OnlineState {
    /// Whether blame writers should hold fire: in Degraded or Offline the failure
    /// evidence is about us, not the peer it names.
    pub fn suppresses_blame(&self) -> bool {
        !matches!(self, OnlineState::Online)
    }
}

/// How long ping-derived offline must persist before it counts as a real outage.
/// Sub-second blips (missed ping deadlines under load, idle-node sparse probes) carry
/// no transport information, and the carrier-NAT-flush wedge it must still catch lasts
/// minutes.
const OFFLINE_SUSTAINED_SECS: u32 = 5;

/// Sliding window that failure breadth accumulates over for degradation detection (~2x rpc timeout)
const DEGRADED_EVIDENCE_WINDOW_SECS: u32 = 10;

/// Base clean time after the last degradation evidence before Degraded can end
pub(crate) const DEGRADED_EXIT_CLEAN_SECS: u32 = 5;

/// Ceiling on the escalated clean window
pub(crate) const DEGRADED_EXIT_CLEAN_MAX_SECS: u32 = 20;

/// Recovering and degrading again within this is one marginal period, not two
const DEGRADED_REENTRY_SECS: u32 = 30;

/// Degraded decays after this long without a post-evidence success
pub(crate) const DEGRADED_MAX_HOLD_SECS: u32 = 60;

/// Local pipeline stalls at or above this consume enough of the rpc timeout to void peer evidence
const LOCAL_STALL_MIN_MS: u64 = 2500;

/// Degraded breadth scales with the table: at least this fraction (1/divisor) of live
/// entries must fail fresh in-window per framing type. A big table always carries a few
/// flapping peers (a flat count false-fires on healthy networks), while a lossy uplink
/// fails a large slice of previously-clean peers at once.
const DEGRADED_BREADTH_TABLE_DIVISOR: usize = 20;

/// Failure count threshold for a socket class.
fn failure_threshold(framing_type: FramingType) -> usize {
    match framing_type {
        FramingType::Connection => OFFLINE_DETECTION_FAILURE_THRESHOLD_CONNECTION,
        FramingType::Message => OFFLINE_DETECTION_FAILURE_THRESHOLD_MESSAGE,
    }
}

/// Clean window required to leave Degraded, doubled per consecutive rapid re-entry.
///
/// A marginal period is evidence with gaps in it, and at the base window those gaps open
/// brief Online windows for blame to land in. Escalating closes them on a network that
/// keeps re-degrading; a recovered one stays on the fast path.
pub(crate) fn degraded_exit_clean_secs(reentries: u32) -> u32 {
    DEGRADED_EXIT_CLEAN_SECS
        .saturating_mul(1u32 << reentries.min(16))
        .min(DEGRADED_EXIT_CLEAN_MAX_SECS)
}

/// The three-state answer, derived from the stored two-state machine plus
/// degradation evidence. Pure so the timing rules are testable without a network.
///
/// Entry is fast, exit is slow: fresh evidence holds Degraded, and leaving requires a
/// success AFTER the evidence (an interleaved success is what keeps the offline detector
/// blind), with the max hold bounding the idle case.
pub(crate) fn effective_online_state(
    stored: OnlineState,
    last_evidence_ts: Option<Timestamp>,
    last_success_ts: Option<Timestamp>,
    clean_secs: u32,
    now: Timestamp,
) -> OnlineState {
    if stored == OnlineState::Offline {
        return OnlineState::Offline;
    }
    let Some(ev) = last_evidence_ts else {
        return OnlineState::Online;
    };
    if now < ev.later(TimestampDuration::new_secs(clean_secs)) {
        return OnlineState::Degraded;
    }
    let recovered = last_success_ts.is_some_and(|s| s > ev);
    if recovered || now >= ev.later(TimestampDuration::new_secs(DEGRADED_MAX_HOLD_SECS)) {
        return OnlineState::Online;
    }
    OnlineState::Degraded
}

/// Events that drive the online/offline state machine.
enum OnlineEvent {
    /// Received something from outside.
    Success,
    /// Failures for previously-live nodes on one framing type. `fresh_node_ids` is the
    /// subset whose failure is news (see `record_failure`); only those arm the degraded
    /// window, while offline detection keeps the full live set.
    Failure {
        live_node_ids: Vec<NodeId>,
        fresh_node_ids: Vec<NodeId>,
        /// Live table size at record time, for the fractional degraded breadth
        responsive_count: usize,
        sent_ts: Timestamp,
        framing_type: FramingType,
    },
    /// The local network address changed.
    NetworkChange,
    /// The node detached from the network (a deliberate offline period).
    Detached,
}

/// Per-routing-domain online/offline tracking.
#[derive(Debug)]
struct OnlineDetectionPerDomain {
    /// Previously-live nodes that failed on each framing type since the last success.
    pending_failures: BTreeMap<FramingType, BTreeSet<NodeId>>,
    /// The same breadth over a time window, which an interleaved success cannot erase
    windowed_failures: BTreeMap<FramingType, BTreeMap<NodeId, Timestamp>>,
    /// Last time the windowed breadth crossed threshold on every enabled framing type
    last_degraded_evidence_ts: Option<Timestamp>,
    /// Last completed round trip; exiting Degraded requires one after the evidence
    last_success_ts: Option<Timestamp>,
    /// Last committed three-state answer, updated on events and lazily on reads
    effective_state: OnlineState,
    /// Consecutive Degraded re-entries within `DEGRADED_REENTRY_SECS`; escalates the exit window
    degraded_reentries: u32,
    /// When Degraded last ended, for the rapid-re-entry test
    degraded_recovered_ts: Option<Timestamp>,
    /// When we last switched online/offline.
    last_transition_ts: Timestamp,
    /// Current state.
    online_state: OnlineState,
    /// Flap detector over online_state.
    flap_detector: FlapDetector<OnlineState>,
    /// Start of the current offline period, if currently offline.
    offline_started_ts: Option<Timestamp>,
    /// Whether this offline period's connection purge has already run.
    offline_purged: bool,
    /// Recently-completed offline intervals (start, end), pruned to
    /// `RELIABLE_PING_INTERVAL_MAX` old. Credits node reliability for time we
    /// couldn't test.
    recent_offline_intervals: VecDeque<(Timestamp, Timestamp)>,
    /// Start of the current degraded period, if effectively degraded
    degraded_started_ts: Option<Timestamp>,
    /// The same for degraded periods, where we could test but must not believe the answer.
    recent_degraded_intervals: VecDeque<(Timestamp, Timestamp)>,
    /// Cumulative online<->offline transition count
    #[cfg(feature = "stats")]
    total_transitions: u64,
    /// Cumulative time spent offline
    #[cfg(feature = "stats")]
    total_time_offline: TimestampDuration,
    /// Cumulative time spent degraded
    #[cfg(feature = "stats")]
    total_time_degraded: TimestampDuration,
}

impl Default for OnlineDetectionPerDomain {
    fn default() -> Self {
        Self {
            pending_failures: BTreeMap::new(),
            windowed_failures: BTreeMap::new(),
            last_degraded_evidence_ts: None,
            last_success_ts: None,
            effective_state: OnlineState::default(),
            degraded_reentries: 0,
            degraded_recovered_ts: None,
            last_transition_ts: Timestamp::new(0),
            online_state: OnlineState::default(),
            // 4 online/offline flips within ~60s = flapping
            flap_detector: FlapDetector::new_secs(4.0, 60),
            offline_started_ts: None,
            offline_purged: false,
            recent_offline_intervals: VecDeque::new(),
            degraded_started_ts: None,
            recent_degraded_intervals: VecDeque::new(),
            #[cfg(feature = "stats")]
            total_transitions: 0,
            #[cfg(feature = "stats")]
            total_time_offline: TimestampDuration::new(0),
            #[cfg(feature = "stats")]
            total_time_degraded: TimestampDuration::new(0),
        }
    }
}

/// Detects if our node is online or offline.
///
/// To determine if network errors are 'our fault' or 'the other side's fault', we need to
/// generally know if we are online or offline, before assigning blame to another node and
/// changing its state.
pub struct OnlineDetector {
    registry: VeilidComponentRegistry,
    inner: Mutex<BTreeMap<RoutingDomain, OnlineDetectionPerDomain>>,
    /// Framing types the network uses; only these gate offline detection.
    enabled_framing_types: Mutex<FramingTypeSet>,
    /// Last local pipeline stall long enough to void timeout evidence; process-wide
    last_local_stall: Mutex<Option<Timestamp>>,
    /// Read-mostly snapshot of the interval data credit math reads.
    ///
    /// Every bucket entry state computation may consult the overlap of its span
    /// with offline/degraded time, from every sweep and peer-selection sort at
    /// once. Serving those reads from `inner` would make it the most contended
    /// lock in the process; readers share this instead, and the state machine
    /// republishes on every path that can change the interval data.
    overlap_data: RwLock<BTreeMap<RoutingDomain, Arc<OverlapData>>>,
}

/// The interval data [OnlineDetector::interval_overlap] reads.
#[derive(Debug, Default)]
struct OverlapData {
    offline_intervals: VecDeque<(Timestamp, Timestamp)>,
    degraded_intervals: VecDeque<(Timestamp, Timestamp)>,
    offline_started_ts: Option<Timestamp>,
    degraded_started_ts: Option<Timestamp>,
}

impl_veilid_component_accessors!(OnlineDetector);

impl fmt::Debug for OnlineDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnlineDetector")
            .field("inner", &*self.inner.lock())
            .field("enabled_framing_types", &*self.enabled_framing_types.lock())
            .finish()
    }
}

impl OnlineDetector {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        Self {
            registry,
            inner: Mutex::new(BTreeMap::new()),
            // Require both classes until the network reports its protocol config.
            enabled_framing_types: Mutex::new(FramingTypeSet::all()),
            last_local_stall: Mutex::new(None),
            overlap_data: RwLock::new(BTreeMap::new()),
        }
    }

    /// Whether this routing domain uses ping-based online detection.
    fn uses_ping_detection(routing_domain: RoutingDomain) -> bool {
        // Other domains will plug in their own signals (LocalNetwork: interface link state).
        matches!(routing_domain, RoutingDomain::PublicInternet)
    }

    /// Republish the overlap snapshot; call before releasing `inner` on any
    /// path that can change interval data (all three mutable-lock functions do)
    fn publish_overlap_data(&self, routing_domain: RoutingDomain, pd: &OnlineDetectionPerDomain) {
        let snap = Arc::new(OverlapData {
            offline_intervals: pd.recent_offline_intervals.clone(),
            degraded_intervals: pd.recent_degraded_intervals.clone(),
            offline_started_ts: pd.offline_started_ts,
            degraded_started_ts: pd.degraded_started_ts,
        });
        self.overlap_data.write().insert(routing_domain, snap);
    }

    /// Set which framing types offline detection requires, from the network protocol config.
    pub fn set_protocol_config(&self, outbound: ProtocolTypeSet, inbound: ProtocolTypeSet) {
        let mut framing_types = FramingTypeSet::new();
        for pt in outbound | inbound {
            framing_types.insert(pt.framing_type());
        }
        *self.enabled_framing_types.lock() = framing_types;
    }

    /// Record a successful round-trip.
    pub fn record_success(&self, routing_domain: RoutingDomain) {
        self.process_event(routing_domain, OnlineEvent::Success);
    }

    /// Record an RPC failure against the directly attempted node. Routed failures are
    /// never fed here: any hop or the route itself may be at fault, and spreading one
    /// failure across hop ids fabricates broad-failure breadth.
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
        // Only currently-responsive nodes count. A probe timing out to a node that is
        // Initial/Missing/Dead/Punished is evidence about that node, not about us: a stale
        // routing table loads entries as Initial while their persisted answer history
        // survives, so a historical-liveness check would count them and flip us offline
        // during the attach burst.
        //
        // The degraded window additionally requires the failure to be news: the ordering
        // answered recently and is not already judged Failing. Chronic single-transport
        // failers otherwise re-arm the window forever; a real local storm still counts
        // each node's first losses before the judge trips.
        let cur_ts = Timestamp::now();
        let routing_table = self.routing_table();
        let so = transport.sequence_ordering();
        let mut live_node_ids = Vec::new();
        let mut fresh_node_ids = Vec::new();
        for node_id in node_ids {
            let Some(nr) = routing_table.lookup_node_id(node_id.clone()).ok().flatten() else {
                continue;
            };
            let (responsive, fresh) = nr.operate(|e| {
                let responsive = e.state(cur_ts).is_responsive();
                let fresh = responsive
                    && e.per_sequence_ordering_stats().get(&so).is_some_and(|s| {
                        s.recent_lost_questions
                            < crate::routing_table::TRANSPORT_FAILING_LOST_QUESTIONS
                            && s.last_seen_ts.is_some_and(|ts| {
                                cur_ts.duration_since(ts)
                                    <= crate::routing_table::RELIABLE_PING_INTERVAL_MAX
                            })
                    });
                (responsive, fresh)
            });
            if responsive {
                live_node_ids.push(node_id.clone());
            }
            if fresh {
                fresh_node_ids.push(node_id);
            }
        }
        if live_node_ids.is_empty() {
            return;
        }
        let responsive_count = routing_table.get_routing_table_health().live_entry_count();
        self.process_event(
            routing_domain,
            OnlineEvent::Failure {
                live_node_ids,
                fresh_node_ids,
                responsive_count,
                sent_ts,
                framing_type: transport.framing_type(),
            },
        );
    }

    /// Local network addresses changed: presume offline until a new RPC succeeds.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    pub fn network_address_change(&self, routing_domain: RoutingDomain) {
        self.process_event(routing_domain, OnlineEvent::NetworkChange);
    }

    /// Re-arm for a new attach; online/offline history persists across detach.
    pub fn startup(&self) {
        *self.enabled_framing_types.lock() = FramingTypeSet::all();
    }

    /// Detached: mark every ping-detected domain offline so the detached period
    /// is credited to node reliability until we reconnect.
    pub fn shutdown(&self) {
        for routing_domain in RoutingDomain::all() {
            self.process_event(routing_domain, OnlineEvent::Detached);
        }
    }

    /// Report a measured local pipeline stall (executor tick lag, envelope build).
    ///
    /// A peer cannot answer inside a timeout we spent ourselves, so long stalls void
    /// timeout evidence. Short ones are filtered here, so call sites report unconditionally
    /// from their slow branches.
    pub fn record_local_stall(&self, duration: TimestampDuration) {
        if duration < TimestampDuration::new_ms(LOCAL_STALL_MIN_MS) {
            return;
        }
        let now = Timestamp::now();
        *self.last_local_stall.lock() = Some(now);
        // Commit promptly so gates and the transition log fire before the next read
        for routing_domain in RoutingDomain::all() {
            if !Self::uses_ping_detection(routing_domain) {
                continue;
            }
            let opt_transition = {
                let mut inner = self.inner.lock();
                let pd = inner.entry(routing_domain).or_default();
                let opt_transition = Self::commit_effective(pd, Some(now), now);
                self.publish_overlap_data(routing_domain, pd);
                opt_transition
            };
            self.log_effective_transition(routing_domain, opt_transition, "local stall");
        }
    }

    /// Whether blame writers should hold fire for this routing domain.
    pub fn blame_suppressed(&self, routing_domain: RoutingDomain) -> bool {
        self.online_state(routing_domain).suppresses_blame()
    }

    /// Current online state for a routing domain.
    pub fn online_state(&self, routing_domain: RoutingDomain) -> OnlineState {
        // Domains without ping detection are always considered online.
        if !Self::uses_ping_detection(routing_domain) {
            return OnlineState::Online;
        }
        let local_stall_ts = *self.last_local_stall.lock();
        let now = Timestamp::now();
        let (state, opt_transition) = {
            let mut inner = self.inner.lock();
            let pd = inner.entry(routing_domain).or_default();
            let opt_transition = Self::commit_effective(pd, local_stall_ts, now);
            self.publish_overlap_data(routing_domain, pd);
            (pd.effective_state, opt_transition)
        };
        self.log_effective_transition(routing_domain, opt_transition, "evidence aged");
        state
    }

    /// When this domain last came back online, if within the reliable ping span.
    /// None if currently offline or no recent reattach.
    pub fn online_since(&self, routing_domain: RoutingDomain) -> Option<Timestamp> {
        if !Self::uses_ping_detection(routing_domain) {
            return None;
        }
        let inner = self.inner.lock();
        let pd = inner.get(&routing_domain)?;
        if pd.offline_started_ts.is_some() {
            return None;
        }
        let (_, end) = pd.recent_offline_intervals.back()?;
        // Protection from a reattach only lasts the reliable ping span.
        if Timestamp::now().duration_since(*end) > crate::routing_table::RELIABLE_PING_INTERVAL_MAX
        {
            return None;
        }
        Some(*end)
    }

    /// Total time within `[from, to]` this domain was offline (couldn't ping).
    pub fn offline_overlap(
        &self,
        routing_domain: RoutingDomain,
        from: Timestamp,
        to: Timestamp,
    ) -> TimestampDuration {
        self.interval_overlap(routing_domain, from, to, false)
    }

    /// The same, plus degraded time, where the blame gates discarded what came back.
    ///
    /// Only for spans that condemn. Degraded time still carries positive evidence
    /// (successes are recorded throughout), so it must not be deducted from how long a
    /// node has been answering.
    pub fn blame_suppressed_overlap(
        &self,
        routing_domain: RoutingDomain,
        from: Timestamp,
        to: Timestamp,
    ) -> TimestampDuration {
        self.interval_overlap(routing_domain, from, to, true)
    }

    fn interval_overlap(
        &self,
        routing_domain: RoutingDomain,
        from: Timestamp,
        to: Timestamp,
        include_degraded: bool,
    ) -> TimestampDuration {
        if !Self::uses_ping_detection(routing_domain) || to <= from {
            return TimestampDuration::new(0);
        }
        // Snapshot, so per-entry credit math never contends with the state machine
        let Some(od) = self.overlap_data.read().get(&routing_domain).cloned() else {
            return TimestampDuration::new(0);
        };
        let empty: VecDeque<(Timestamp, Timestamp)> = VecDeque::new();
        let (degraded_intervals, opt_degraded_started) = if include_degraded {
            (&od.degraded_intervals, od.degraded_started_ts)
        } else {
            (&empty, None)
        };
        let mut overlap = 0u64;
        // Offline and degraded never overlap: entering one closes the other
        for (s, e) in od
            .offline_intervals
            .iter()
            .chain(degraded_intervals.iter())
            .copied()
            .chain(od.offline_started_ts.map(|s| (s, to)))
            .chain(opt_degraded_started.map(|s| (s, to)))
        {
            let lo = s.max(from);
            let hi = e.min(to);
            if hi > lo {
                overlap += hi.duration_since(lo).as_u64();
            }
        }
        TimestampDuration::new(overlap)
    }

    /// Stats snapshot: (online, degraded, transitions, time offline, time degraded).
    #[cfg(feature = "stats")]
    pub(crate) fn online_stats(
        &self,
        routing_domain: RoutingDomain,
        now: Timestamp,
    ) -> (bool, bool, u64, TimestampDuration, TimestampDuration) {
        let inner = self.inner.lock();
        match inner.get(&routing_domain) {
            Some(pd) => {
                let mut time_offline = pd.total_time_offline;
                if let Some(start) = pd.offline_started_ts {
                    time_offline = time_offline.saturating_add(now.duration_since(start));
                }
                let mut time_degraded = pd.total_time_degraded;
                if let Some(start) = pd.degraded_started_ts {
                    time_degraded = time_degraded.saturating_add(now.duration_since(start));
                }
                (
                    matches!(pd.online_state, OnlineState::Online),
                    matches!(pd.effective_state, OnlineState::Degraded),
                    pd.total_transitions,
                    time_offline,
                    time_degraded,
                )
            }
            None => (
                true,
                false,
                0,
                TimestampDuration::new(0),
                TimestampDuration::new(0),
            ),
        }
    }

    /// Recompute and commit the effective three-state answer; returns a
    /// transition for the caller to log outside the lock.
    fn commit_effective(
        pd: &mut OnlineDetectionPerDomain,
        local_stall_ts: Option<Timestamp>,
        now: Timestamp,
    ) -> Option<(OnlineState, OnlineState, u32)> {
        let evidence = pd.last_degraded_evidence_ts.max(local_stall_ts);
        let clean_secs = degraded_exit_clean_secs(pd.degraded_reentries);
        let new_state = effective_online_state(
            pd.online_state,
            evidence,
            pd.last_success_ts,
            clean_secs,
            now,
        );
        let old_state = pd.effective_state;
        if new_state == old_state {
            return None;
        }
        // Decided on entry, held for the whole degraded period
        match (old_state, new_state) {
            (OnlineState::Degraded, _) => pd.degraded_recovered_ts = Some(now),
            (_, OnlineState::Degraded) => {
                let rapid = pd.degraded_recovered_ts.is_some_and(|ts| {
                    now.duration_since(ts) <= TimestampDuration::new_secs(DEGRADED_REENTRY_SECS)
                });
                pd.degraded_reentries = if rapid {
                    pd.degraded_reentries.saturating_add(1)
                } else {
                    0
                };
            }
            _ => {}
        }
        pd.effective_state = new_state;
        if new_state == OnlineState::Degraded {
            pd.degraded_started_ts = Some(now);
        } else if let Some(start) = pd.degraded_started_ts.take() {
            veilid_stats!(
                pd.total_time_degraded = pd
                    .total_time_degraded
                    .saturating_add(now.duration_since(start))
            );
            pd.recent_degraded_intervals.push_back((start, now));
            while pd.recent_degraded_intervals.front().is_some_and(|(_, e)| {
                now.duration_since(*e) > crate::routing_table::RELIABLE_PING_INTERVAL_MAX
            }) {
                pd.recent_degraded_intervals.pop_front();
            }
        }
        Some((
            old_state,
            new_state,
            degraded_exit_clean_secs(pd.degraded_reentries),
        ))
    }

    /// Degraded transitions log here; online and offline log from the stored machine.
    fn log_effective_transition(
        &self,
        routing_domain: RoutingDomain,
        opt_transition: Option<(OnlineState, OnlineState, u32)>,
        why: &str,
    ) {
        let Some((old_state, new_state, clean_secs)) = opt_transition else {
            return;
        };
        match (old_state, new_state) {
            (_, OnlineState::Degraded) => {
                veilid_log!(self info "{:?} degraded detected ({}): blame suppressed, exit needs {}s clean", routing_domain, why, clean_secs);
            }
            (OnlineState::Degraded, OnlineState::Online) => {
                veilid_log!(self info "{:?} recovered from degraded", routing_domain);
            }
            _ => {}
        }
    }

    /// Drive the state machine with an event, dispatching to the current state's handler.
    fn process_event(&self, routing_domain: RoutingDomain, event: OnlineEvent) {
        if !Self::uses_ping_detection(routing_domain) {
            return;
        }
        let enabled_framing_types = *self.enabled_framing_types.lock();
        let local_stall_ts = *self.last_local_stall.lock();
        let now = Timestamp::now();

        let (opt_new_state, opt_flap_penalty, do_purge, purge_reason, do_wipe, opt_eff_transition) = {
            let mut inner = self.inner.lock();
            let pd = inner.entry(routing_domain).or_default();
            // Exiting Degraded needs a round trip after the evidence, so stamp in every state
            if matches!(event, OnlineEvent::Success) {
                pd.last_success_ts = Some(now);
            }
            let opt_new_state = match pd.online_state {
                OnlineState::Offline => Self::process_offline_event(&event),
                OnlineState::Online | OnlineState::Degraded => {
                    Self::process_online_event(pd, &event, enabled_framing_types, now)
                }
            };
            let mut opt_flap_penalty = None;
            let mut do_wipe = false;
            if let Some(new_state) = opt_new_state {
                match new_state {
                    // The stored machine is two-state; Degraded is the derived overlay
                    OnlineState::Degraded => unreachable!(),
                    OnlineState::Offline => {
                        pd.offline_started_ts = Some(now);
                        pd.offline_purged = false;
                    }
                    OnlineState::Online => {
                        if let Some(start) = pd.offline_started_ts.take() {
                            // Only a sustained outage invalidates transport evidence
                            do_wipe = now.duration_since(start)
                                >= TimestampDuration::new_secs(OFFLINE_SUSTAINED_SECS);
                            pd.recent_offline_intervals.push_back((start, now));
                            veilid_stats!(
                                pd.total_time_offline = pd
                                    .total_time_offline
                                    .saturating_add(now.duration_since(start))
                            );
                            // Prune intervals older than the reliable ping span.
                            while pd.recent_offline_intervals.front().is_some_and(|(_, e)| {
                                now.duration_since(*e)
                                    > crate::routing_table::RELIABLE_PING_INTERVAL_MAX
                            }) {
                                pd.recent_offline_intervals.pop_front();
                            }
                        }
                    }
                }
                pd.online_state = new_state;
                pd.last_transition_ts = now;
                veilid_stats!(pd.total_transitions += 1);
                // A deliberate detach is a clean break, not network flapping: reset the
                // flap baseline so pre-detach history doesn't combine with reattach turbulence.
                if matches!(event, OnlineEvent::Detached) {
                    pd.flap_detector.reset();
                } else {
                    opt_flap_penalty = pd.flap_detector.record(now.as_u64(), new_state);
                }
            }

            // Purge policy: a NAT rebind black-holes established flows, so a real outage
            // must close everything and a blip must not. An interface change is a confirmed
            // move (purge at once); ping-derived offline must persist first, rechecked
            // on each event while offline.
            let mut do_purge = false;
            let mut purge_reason = "";
            if pd.online_state == OnlineState::Offline && !matches!(event, OnlineEvent::Detached) {
                // A move purges even mid-outage: recovery attempts may have opened
                // fresh connections on the old interface since the last purge
                let confirmed_move = matches!(event, OnlineEvent::NetworkChange);
                let sustained = !pd.offline_purged
                    && pd.offline_started_ts.is_some_and(|start| {
                        now.duration_since(start)
                            >= TimestampDuration::new_secs(OFFLINE_SUSTAINED_SECS)
                    });
                if confirmed_move || sustained {
                    pd.offline_purged = true;
                    do_purge = true;
                    purge_reason = if confirmed_move {
                        "interface change"
                    } else {
                        "sustained offline"
                    };
                }
            }
            let opt_eff_transition = Self::commit_effective(pd, local_stall_ts, now);
            self.publish_overlap_data(routing_domain, pd);
            (
                opt_new_state,
                opt_flap_penalty,
                do_purge,
                purge_reason,
                do_wipe,
                opt_eff_transition,
            )
        };

        // Log the transition (and any flapping) outside the lock.
        if let Some(new_state) = opt_new_state {
            veilid_log!(self info "{:?} {} detected", routing_domain,
                if new_state == OnlineState::Online { "online" } else { "offline" });
        }
        self.log_effective_transition(routing_domain, opt_eff_transition, "broad failures");
        if do_purge {
            // close_all_connections is silent on an empty table; log the decision
            veilid_log!(self debug "{:?} purging connections: {}", routing_domain, purge_reason);
            if let Some(connection_manager) = self.network_manager().opt_connection_manager() {
                connection_manager.close_all_connections();
            }
        }
        if do_wipe {
            self.network_manager()
                .transport_stats()
                .reset_routing_domain(routing_domain, "sustained offline ended");
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
            OnlineEvent::Failure { .. } | OnlineEvent::NetworkChange | OnlineEvent::Detached => {
                None
            }
        }
    }

    /// Handle an event while online.
    fn process_online_event(
        pd: &mut OnlineDetectionPerDomain,
        event: &OnlineEvent,
        enabled_framing_types: FramingTypeSet,
        now: Timestamp,
    ) -> Option<OnlineState> {
        match event {
            OnlineEvent::Success => {
                pd.pending_failures.clear();
                None
            }
            OnlineEvent::Failure {
                live_node_ids,
                fresh_node_ids,
                responsive_count,
                sent_ts,
                framing_type,
            } => {
                // Ignore failures from RPCs sent before this online period began.
                if *sent_ts < pd.last_transition_ts {
                    return None;
                }
                let bucket = pd.pending_failures.entry(*framing_type).or_default();
                for node_id in live_node_ids {
                    bucket.insert(node_id.clone());
                }
                // Only fresh failures arm the degraded window; the offline breadth
                // above keeps the full live set
                let wbucket = pd.windowed_failures.entry(*framing_type).or_default();
                for node_id in fresh_node_ids {
                    wbucket.insert(node_id.clone(), now);
                }
                // Windowed breadth survives interleaved successes: the degraded signature
                let window = TimestampDuration::new_secs(DEGRADED_EVIDENCE_WINDOW_SECS);
                for wb in pd.windowed_failures.values_mut() {
                    wb.retain(|_, ts| now.duration_since(*ts) <= window);
                }
                // Degraded needs a table-relative slice of previously-clean peers
                // failing at once; the flat offline threshold below stays as-is
                let degraded_threshold = |ft: FramingType| {
                    failure_threshold(ft).max(responsive_count / DEGRADED_BREADTH_TABLE_DIVISOR)
                };
                let all_windowed = !enabled_framing_types.is_empty()
                    && enabled_framing_types.iter().all(|ft| {
                        pd.windowed_failures.get(&ft).map_or(0, BTreeMap::len)
                            >= degraded_threshold(ft)
                    });
                if all_windowed {
                    pd.last_degraded_evidence_ts = Some(now);
                }
                // Offline only when every enabled socket class has crossed its threshold, so
                // localized trouble on one class doesn't drive offline while another works.
                let all_failed = !enabled_framing_types.is_empty()
                    && enabled_framing_types.iter().all(|ft| {
                        pd.pending_failures.get(&ft).map_or(0, BTreeSet::len)
                            >= failure_threshold(ft)
                    });
                if all_failed {
                    pd.pending_failures.clear();
                    return Some(OnlineState::Offline);
                }
                None
            }
            OnlineEvent::NetworkChange | OnlineEvent::Detached => {
                pd.pending_failures.clear();
                // Degradation evidence belongs to the network we just left
                pd.windowed_failures.clear();
                pd.last_degraded_evidence_ts = None;
                pd.degraded_reentries = 0;
                pd.degraded_recovered_ts = None;
                Some(OnlineState::Offline)
            }
        }
    }
}
