mod state;
mod transport_state;

pub(crate) use state::*;
pub(crate) use transport_state::*;

use super::*;
use core::sync::atomic::{AtomicU32, Ordering};
use hashlink::LruCache;

fn default_routed_stats() -> LruCache<PublicKey, PerLocalRouteStats> {
    LruCache::new(ROUTED_STATS_LRU_SIZE)
}

impl_veilid_log_facility!("rtab");

/// Reliable pings are done with increased spacing between pings
///
/// - Start secs is the number of seconds between the first two pings
pub(crate) const RELIABLE_PING_INTERVAL_START_SECS: u32 = 10;
/// - Max secs is the maximum number of seconds between consecutive pings
pub(crate) const RELIABLE_PING_INTERVAL_MAX_SECS: u32 = 10 * 60;
/// - Multiplier changes the number of seconds between pings over time
///   making it longer as the node becomes more reliable
pub(crate) const RELIABLE_PING_INTERVAL_MULTIPLIER: f64 = 2.0;

/// Unreliable pings are done for a fixed amount of time while the
/// node is given a chance to come back online before it is made dead
/// If a node misses a single ping, it is marked unreliable and must
/// return reliable pings for the duration of the span before being
/// marked reliable again
///
/// - Span is the number of seconds total to attempt to validate the node
pub(crate) const UNRELIABLE_PING_SPAN_SECS: u32 = 60;
/// - Interval is the number of seconds between each ping
pub(crate) const UNRELIABLE_PING_INTERVAL_SECS: u32 = 5;
/// - Number of consecutive lost answers on a datagram socket we will
///   tolerate before we call something unreliable
pub(crate) const UNRELIABLE_LOST_ANSWERS_DATAGRAM: u32 = 2;
/// - Number of consecutive lost answers on a stream socket we will
///   tolerate before we call something unreliable
pub(crate) const UNRELIABLE_LOST_ANSWERS_STREAM: u32 = 0;

/// Default unreliable lost-answers threshold per low-level transport.
/// Will become adaptive later (per-network baseline).
pub(crate) fn default_unreliable_lost_answers_threshold(transport: LowLevelTransportType) -> u32 {
    match transport.socket_type() {
        SocketType::Stream => UNRELIABLE_LOST_ANSWERS_STREAM,
        SocketType::Datagram => UNRELIABLE_LOST_ANSWERS_DATAGRAM,
    }
}

/// Dead nodes are unreachable nodes, not 'never reached' nodes
///
/// How many times do we try to ping a never-reached node before we call it dead
pub(crate) const NEVER_SEEN_PING_COUNT: u32 = 3;

// Connectionless protocols like UDP are dependent on a NAT translation timeout
// We ping relays to maintain our UDP NAT state with a RELAY_KEEPALIVE_PING_INTERVAL_SECS=10 frequency
// since 30 seconds is a typical UDP NAT state timeout  .
// Non-relay flows are assumed to be alive for half the typical timeout and we regenerate the hole punch
// if it the flow hasn't had any activity in this amount of time.
pub(crate) const CONNECTIONLESS_TIMEOUT: TimestampDuration = TimestampDuration::new_secs(15);

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) struct LastFlowKey {
    pub transport: TransportType,
}

impl fmt::Display for LastFlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", f.to_string(self.transport))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) struct LastSenderInfoKey {
    pub routing_domain: RoutingDomain,
    pub transport: TransportType,
}

impl fmt::Display for LastSenderInfoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            f.to_string(self.routing_domain),
            f.to_string(self.transport)
        )
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub(crate) struct LastFlowEntry {
    pub flow: Flow,
    pub timestamp: Timestamp,
}

impl fmt::Display for LastFlowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {}",
            f.to_string(self.flow),
            f.to_string(self.timestamp)
        )
    }
}

/// Bucket entry information specific to the LocalNetwork RoutingDomain
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BucketEntryPublicInternet {
    /// The PublicInternet node info
    peer_info: Option<Arc<PeerInfo>>,
    /// The last node info timestamp of ours that this entry has seen
    last_seen_our_node_info_ts: Timestamp,
    /// Last known node status
    node_status: Option<NodeStatus>,
}

impl fmt::Display for BucketEntryPublicInternet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pi) = &self.peer_info {
            writeln!(f, "peer_info:")?;
            write!(f, "    {}", indent_string(f.to_string(&**pi)))?;
        } else {
            writeln!(f, "peer_info: None")?;
        }
        writeln!(
            f,
            "last_seen_our_node_info_ts: {}",
            f.to_string(self.last_seen_our_node_info_ts)
        )?;
        writeln!(f, "node_status: {:?}", self.node_status)?;
        Ok(())
    }
}

/// Bucket entry information specific to the LocalNetwork RoutingDomain
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BucketEntryLocalNetwork {
    /// The LocalNetwork peerinfo
    peer_info: Option<Arc<PeerInfo>>,
    /// The last node info timestamp of ours that this entry has seen
    last_seen_our_node_info_ts: Timestamp,
    /// Last known node status
    node_status: Option<NodeStatus>,
}

impl fmt::Display for BucketEntryLocalNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pi) = &self.peer_info {
            writeln!(f, "peer_info:")?;
            write!(f, "    {}", indent_string(f.to_string(&**pi)))?;
        } else {
            writeln!(f, "peer_info: None")?;
        }
        writeln!(
            f,
            "last_seen_our_node_info_ts: {}",
            f.to_string(self.last_seen_our_node_info_ts)
        )?;
        writeln!(f, "node_status: {:?}", self.node_status)?;
        Ok(())
    }
}

/// The data associated with each bucket entry
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BucketEntryInner {
    /// The node ids matching this bucket entry
    node_ids: NodeIdGroup,
    /// The set of envelope versions supported by the node inclusive of the requirements of any relay the node may be using
    envelope_support: Vec<EnvelopeVersion>,
    /// If this node has updated it's SignedNodeInfo since our network
    /// and dial info has last changed, for example when our IP address changes
    /// Used to determine if we should make this entry 'live' again when we receive a signednodeinfo update that
    /// has the same timestamp, because if we change our own IP address or network class it may be possible for nodes that were
    /// unreachable may now be reachable with the same SignedNodeInfo/DialInfo
    updated_since_last_network_change: bool,
    /// The last flows used to contact this node, per protocol type
    #[serde(skip)]
    last_flows: BTreeMap<LastFlowKey, LastFlowEntry>,
    /// Last seen senderinfo per protocol/address type
    #[serde(skip)]
    last_sender_info: HashMap<LastSenderInfoKey, SenderInfo>,
    /// The node info for this entry on the publicinternet routing domain
    public_internet: BucketEntryPublicInternet,
    /// The node info for this entry on the localnetwork routing domain
    local_network: BucketEntryLocalNetwork,
    /// Statistics gathered for the peer
    peer_stats: PeerStats,
    /// The accounting for the latency statistics
    #[serde(skip)]
    latency_stats_accounting: LatencyStatsAccounting,
    /// The accounting for protected-connection drop durations
    #[serde(skip)]
    protected_connection_drop_accounting: LatencyStatsAccounting,
    /// The accounting for the transfer statistics
    #[serde(skip)]
    transfer_stats_accounting: TransferStatsAccounting,
    /// The account for the state and reason statistics
    #[serde(skip)]
    state_stats_accounting: Mutex<StateStatsAccounting>,
    /// Per-transport reliability stats. Source of truth for per-transport state.
    #[serde(skip)]
    per_transport_stats: BTreeMap<LowLevelTransportType, BucketEntryTransportStats>,
    /// Per-local-route stats keyed by local-route pubkey (our outbound SR for outbound,
    /// our inbound reply-PR for inbound answers). Only populated for routed exchanges.
    #[serde(skip, default = "default_routed_stats")]
    routed_stats: LruCache<PublicKey, PerLocalRouteStats>,
    /// If the entry is being punished and should be considered dead
    #[serde(skip)]
    punishment: Option<PunishmentReason>,
    /// Node location
    #[cfg(feature = "geolocation")]
    #[serde(skip)]
    geolocation_info: GeolocationInfo,
    /// Tracking identifier for NodeRef debugging
    #[cfg(feature = "tracking")]
    #[serde(skip)]
    next_track_id: usize,
    /// Backtraces for NodeRef debugging
    #[cfg(feature = "tracking")]
    #[serde(skip)]
    node_ref_tracks: HashMap<usize, backtrace::Backtrace>,
}

impl fmt::Display for BucketEntryInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node_ids: {}", self.node_ids)?;
        writeln!(f, "envelope_support: {:?}", self.envelope_support)?;
        writeln!(
            f,
            "updated_since_last_network_change: {:?}",
            self.updated_since_last_network_change
        )?;
        writeln!(f, "last_flows:")?;
        for (key, entry) in &self.last_flows {
            writeln!(f, "    {}: {}", f.to_string(key), f.to_string(entry))?;
        }
        writeln!(f, "last_sender_info:")?;
        for (key, sender_info) in &self.last_sender_info {
            writeln!(
                f,
                "    {}: {}",
                f.to_string(key),
                sender_info.socket_address
            )?;
        }
        writeln!(f, "public_internet:")?;
        write!(
            f,
            "{}",
            indent_all_string(f.to_string(&self.public_internet))
        )?;
        writeln!(f, "local_network:")?;
        write!(f, "{}", indent_all_string(f.to_string(&self.local_network)))?;
        writeln!(f, "peer_stats:")?;
        write!(f, "{}", indent_all_string(f.to_string(&self.peer_stats)))?;
        if !self.routed_stats.is_empty() {
            writeln!(f, "routed_stats:")?;
            for (key, entry) in self.routed_stats.iter() {
                writeln!(f, "  {}:", key)?;
                write!(
                    f,
                    "{}",
                    indent_all_string(indent_all_string(f.to_string(entry)))
                )?;
                writeln!(f)?;
            }
        }
        writeln!(f, "punishment: {}", f.to_string_opt(self.punishment))?;

        Ok(())
    }
}

impl BucketEntryInner {
    #[cfg(feature = "tracking")]
    pub fn track(&mut self) -> usize {
        let track_id = self.next_track_id;
        self.next_track_id += 1;
        self.node_ref_tracks
            .insert(track_id, backtrace::Backtrace::new_unresolved());
        track_id
    }

    #[cfg(feature = "tracking")]
    pub fn untrack(&mut self, track_id: usize) {
        self.node_ref_tracks.remove(&track_id);
    }

    /// Get all node ids
    pub fn node_ids(&self) -> NodeIdGroup {
        self.node_ids.clone()
    }

    /// Get public keys
    pub fn public_keys(&self, routing_domain: RoutingDomain) -> PublicKeyGroup {
        match routing_domain {
            RoutingDomain::LocalNetwork => self
                .local_network
                .peer_info
                .as_ref()
                .map(|x| x.node_info().public_keys())
                .unwrap_or_default(),
            RoutingDomain::PublicInternet => self
                .public_internet
                .peer_info
                .as_ref()
                .map(|x| x.node_info().public_keys())
                .unwrap_or_default(),
        }
    }

    /// Get best node id
    pub fn best_node_id(&self) -> NodeId {
        self.node_ids
            .first()
            .expect_or_log("all entries must have one valid node id")
            .clone()
    }

    /// Get best public key
    pub fn best_public_key(&self, routing_domain: RoutingDomain) -> Option<PublicKey> {
        match routing_domain {
            RoutingDomain::LocalNetwork => self
                .local_network
                .peer_info
                .as_ref()
                .and_then(|x| x.node_info().public_keys().first().cloned()),
            RoutingDomain::PublicInternet => self
                .public_internet
                .peer_info
                .as_ref()
                .and_then(|x| x.node_info().public_keys().first().cloned()),
        }
    }

    /// Add a node id for a particular crypto kind.
    /// Returns Ok(Some(node)) any previous existing node id associated with that crypto kind
    /// Returns Ok(None) if no previous existing node id was associated with that crypto kind, or one existed but nothing changed.
    /// Results Err() if this operation would add more crypto kinds than we support
    pub fn add_node_id(&mut self, node_id: NodeId) -> EyreResult<Option<NodeId>> {
        if let Some(old_node_id) = self.node_ids.get(node_id.kind()) {
            // If this was already there we do nothing
            if old_node_id == node_id {
                return Ok(None);
            }
            // Won't change number of crypto kinds, but the node id changed
            self.node_ids.add(node_id);

            return Ok(Some(old_node_id));
        }
        self.node_ids.add(node_id);

        Ok(None)
    }

    /// Remove a node id for a particular crypto kind.
    /// Returns Some(node) any previous existing node id associated with that crypto kind
    /// Returns None if no previous existing node id was associated with that crypto kind
    pub fn remove_node_id(&mut self, crypto_kind: CryptoKind) -> Option<NodeId> {
        self.node_ids.remove(crypto_kind)
    }

    /// All-of capability check
    pub fn has_all_capabilities(
        &self,
        routing_domain: RoutingDomain,
        capabilities: &[VeilidCapability],
    ) -> bool {
        let Some(ni) = self.node_info(routing_domain) else {
            return false;
        };
        ni.has_all_capabilities(capabilities)
    }

    /// Any-of capability check
    pub fn has_any_capabilities(
        &self,
        routing_domain: RoutingDomain,
        capabilities: &[VeilidCapability],
    ) -> bool {
        let Some(ni) = self.node_info(routing_domain) else {
            return false;
        };
        ni.has_any_capabilities(capabilities)
    }

    pub fn update_peer_info(
        &mut self,
        routing_domain: RoutingDomain,
        peer_info: Arc<PeerInfo>,
    ) -> bool {
        // Get the correct PeerInfo for the chosen routing domain
        let opt_current_pi = match routing_domain {
            RoutingDomain::LocalNetwork => &mut self.local_network.peer_info,
            RoutingDomain::PublicInternet => &mut self.public_internet.peer_info,
        };

        // See if we have an existing PeerInfo to update or not
        let mut node_info_changed = false;
        // let mut had_previous_node_info = false;
        if let Some(current_pi) = opt_current_pi {
            // had_previous_node_info = true;

            // Always allow overwriting unsigned node (bootstrap)
            if !current_pi.signatures().is_empty() {
                // Current peer info is signed so accept only newer peer info (may be unsigned if bootstrapping)

                // If the timestamp hasn't changed or is less, ignore this update
                if peer_info.node_info().timestamp() <= current_pi.node_info().timestamp() {
                    // If we received a node update with the same timestamp
                    // we can make this node live again, but only if our network has recently changed
                    // which may make nodes that were unreachable now reachable with the same dialinfo
                    if !self.updated_since_last_network_change
                        && peer_info.node_info().timestamp() == current_pi.node_info().timestamp()
                    {
                        // No need to update the signednodeinfo though since the timestamp is the same
                        // Let the node try to live again but don't mark it as seen yet
                        self.updated_since_last_network_change = true;
                        self.make_not_dead(Timestamp::now());
                    }
                    return false;
                }

                // See if anything has changed in this update beside the timestamp
                if !peer_info.equivalent(current_pi) {
                    node_info_changed = true;
                }
            }
        }

        // Update the envelope version support we have to use
        let envelope_support = peer_info.node_info().envelope_support().to_vec();

        // Update the signed node info
        // Let the node try to live again but don't mark it as seen yet
        *opt_current_pi = Some(peer_info.clone());
        self.set_envelope_support(envelope_support);
        self.updated_since_last_network_change = true;
        self.make_not_dead(Timestamp::now());

        // Update geolocation info
        #[cfg(feature = "geolocation")]
        {
            self.geolocation_info = peer_info.node_info().get_geolocation_info(routing_domain);
        }

        // If we're updating an entry's node info, purge all
        // but the last connection in our last connections list
        // because the dial info could have changed and it's safer to just reconnect.
        // The latest connection would have been the one we got the new node info
        // over so that connection is still valid.
        if node_info_changed {
            self.clear_last_flows_except_latest();
        }

        node_info_changed
    }

    #[cfg(feature = "geolocation")]
    pub(super) fn update_geolocation_info(&mut self) {
        if let Some(ref peerinfo) = self.public_internet.peer_info {
            self.geolocation_info = peerinfo
                .node_info()
                .get_geolocation_info(RoutingDomain::PublicInternet);
        }
    }

    // pub fn exists_in_routing_domain(
    //     &self,
    //     rti: &RoutingTableInner,
    //     routing_domain: RoutingDomain,
    // ) -> bool {
    //     // Check node info
    //     if self.has_node_info(routing_domain.into()) {
    //         return true;
    //     }

    //     // Check connections
    //     let last_flows = self.last_flows(rti, true, NodeRefFilter::from(routing_domain));
    //     !last_flows.is_empty()
    // }

    pub fn node_info(&self, routing_domain: RoutingDomain) -> Option<&NodeInfo> {
        let opt_peer_info = match routing_domain {
            RoutingDomain::LocalNetwork => &self.local_network.peer_info,
            RoutingDomain::PublicInternet => &self.public_internet.peer_info,
        };
        opt_peer_info.as_ref().map(|s| s.node_info())
    }

    pub fn get_peer_info(&self, routing_domain: RoutingDomain) -> Option<Arc<PeerInfo>> {
        let opt_current_pi = match routing_domain {
            RoutingDomain::LocalNetwork => &self.local_network.peer_info,
            RoutingDomain::PublicInternet => &self.public_internet.peer_info,
        };

        // Return the peerinfo
        opt_current_pi.clone()
    }

    pub fn best_routing_domain(
        &self,
        routing_table: &RoutingTable,
        routing_domain_set: RoutingDomainSet,
    ) -> Option<RoutingDomain> {
        // Check node info
        for routing_domain in routing_domain_set {
            let opt_current_pi = match routing_domain {
                RoutingDomain::LocalNetwork => &self.local_network.peer_info,
                RoutingDomain::PublicInternet => &self.public_internet.peer_info,
            };
            if opt_current_pi.is_some() {
                return Some(routing_domain);
            }
        }
        // Check connections
        let mut best_routing_domain: Option<RoutingDomain> = None;
        let last_connections =
            self.last_flows(routing_table, true, NodeRefFilter::from(routing_domain_set));
        for lc in last_connections {
            if let Some(rd) = routing_table.routing_domain_for_flow(lc.0) {
                if let Some(brd) = best_routing_domain {
                    if rd < brd {
                        best_routing_domain = Some(rd);
                    }
                } else {
                    best_routing_domain = Some(rd);
                }
            }
        }
        best_routing_domain
    }

    fn flow_to_key(&self, last_flow: Flow) -> LastFlowKey {
        LastFlowKey {
            transport: last_flow.transport_type(),
        }
    }

    // Stores a flow in this entry's table of last flows
    pub(super) fn set_last_flow(&mut self, last_flow: Flow, timestamp: Timestamp) {
        if self.punishment.is_some() {
            // Don't record connection if this entry is currently punished
            return;
        }
        let key = self.flow_to_key(last_flow);
        self.last_flows.insert(
            key,
            LastFlowEntry {
                flow: last_flow,
                timestamp,
            },
        );
    }

    // Removes a flow in this entry's table of last flows
    pub(super) fn remove_last_flow(&mut self, last_flow: Flow) {
        let key = self.flow_to_key(last_flow);
        self.last_flows.remove(&key);
    }

    // Clears the table of last flows to ensure we create new ones and drop any existing ones
    // With a DialInfo::all filter specified, only clear the flows that match the filter
    pub(super) fn clear_last_flows(&mut self, dial_info_filter: DialInfoFilter) {
        if dial_info_filter != DialInfoFilter::all() {
            self.last_flows
                .retain(|k, _v| !dial_info_filter.contains_transport(k.transport));
        } else {
            self.last_flows.clear();
        }
    }

    // Clears the table of last flows except the most recent one
    pub(super) fn clear_last_flows_except_latest(&mut self) {
        if self.last_flows.is_empty() {
            // No last_connections
            return;
        }
        let mut dead_keys = Vec::with_capacity(self.last_flows.len() - 1);
        let mut most_recent_flow = None;
        let mut most_recent_flow_time = 0u64;
        for (k, entry) in &self.last_flows {
            let lct = entry.timestamp.as_u64();
            if lct > most_recent_flow_time {
                most_recent_flow = Some(k);
                most_recent_flow_time = lct;
            }
        }
        let Some(most_recent_flow) = most_recent_flow else {
            return;
        };
        for k in self.last_flows.keys() {
            if k != most_recent_flow {
                dead_keys.push(k.clone());
            }
        }
        for dk in dead_keys {
            self.last_flows.remove(&dk);
        }
    }

    // Gets all the 'last flows' that match a particular filter, and their accompanying timestamps of last use
    pub(super) fn last_flows(
        &self,
        routing_table: &RoutingTable,
        only_live: bool,
        filter: NodeRefFilter,
    ) -> Vec<(Flow, Timestamp)> {
        let opt_connection_manager = routing_table.network_manager().opt_connection_manager();

        let mut out: Vec<(Flow, Timestamp)> = self
            .last_flows
            .iter()
            .filter_map(|(k, entry)| {
                let include = routing_table
                    .routing_domain_for_flow(entry.flow)
                    .map(|rd| {
                        filter.routing_domain_set().contains(rd)
                            && filter.contains_transport(k.transport)
                    })
                    .unwrap_or(false);

                if !include {
                    return None;
                }

                if !only_live {
                    return Some((entry.flow, entry.timestamp));
                }

                let alive = if matches!(
                    entry.flow.protocol_type().sequence_ordering(),
                    SequenceOrdering::Ordered
                ) {
                    // Connection-oriented: must still be in the connection table
                    opt_connection_manager
                        .as_ref()
                        .map(|cm| cm.get_connection(entry.flow).is_some())
                        .unwrap_or(false)
                } else {
                    // Connectionless: last-seen must be within the mapping timeout
                    let cur_ts = Timestamp::now();
                    entry.timestamp.later(CONNECTIONLESS_TIMEOUT) >= cur_ts
                };

                if alive {
                    Some((entry.flow, entry.timestamp))
                } else {
                    None
                }
            })
            .collect();
        // Sort with newest timestamps
        out.sort_by_key(|b| std::cmp::Reverse(b.1));
        out
    }

    pub(super) fn add_envelope_version(&mut self, envelope_version: EnvelopeVersion) {
        assert!(VALID_ENVELOPE_VERSIONS.contains(&envelope_version));
        if self.envelope_support.contains(&envelope_version) {
            return;
        }
        self.envelope_support.push(envelope_version);
        self.envelope_support.sort_by(|a, b| {
            let a_sort = VALID_ENVELOPE_VERSIONS
                .iter()
                .position(|x| x == a)
                .unwrap_or_log();
            let b_sort = VALID_ENVELOPE_VERSIONS
                .iter()
                .position(|x| x == b)
                .unwrap_or_log();
            a_sort.cmp(&b_sort)
        });
    }

    pub(super) fn set_envelope_support(&mut self, mut envelope_support: Vec<EnvelopeVersion>) {
        envelope_support.sort();
        envelope_support.dedup();
        self.envelope_support = envelope_support;
    }

    pub fn best_envelope_version(&self) -> Option<EnvelopeVersion> {
        self.envelope_support
            .iter()
            .find(|x| VALID_ENVELOPE_VERSIONS.contains(x))
            .copied()
    }

    /// Node-level rollup of per-transport states. Cold start is Unreliable.
    pub fn state_reason(&self, cur_ts: Timestamp) -> BucketEntryStateReason {
        let reason = if let Some(p) = self.punishment {
            BucketEntryStateReason::Punished(p)
        } else if self.per_transport_stats.is_empty() {
            BucketEntryStateReason::Unreliable(
                BucketEntryTransportUnreliableReason::NotSeenConsecutively,
            )
        } else {
            let mut any_reliable = false;
            let mut last_unreliable: Option<BucketEntryTransportUnreliableReason> = None;
            let mut last_dead: Option<BucketEntryTransportDeadReason> = None;
            for r in self.iter_transport_state_reasons(cur_ts) {
                match r {
                    BucketEntryTransportStateReason::Reliable => any_reliable = true,
                    BucketEntryTransportStateReason::Unreliable(u) => last_unreliable = Some(u),
                    BucketEntryTransportStateReason::Dead(d) => last_dead = Some(d),
                }
            }
            if any_reliable {
                BucketEntryStateReason::Reliable
            } else if let Some(u) = last_unreliable {
                BucketEntryStateReason::Unreliable(u)
            } else {
                BucketEntryStateReason::Dead(last_dead.unwrap_or_log())
            }
        };

        self.state_stats_accounting
            .lock()
            .record_state_reason(cur_ts, reason);

        reason
    }

    pub fn state(&self, cur_ts: Timestamp) -> BucketEntryState {
        self.state_reason(cur_ts).into()
    }

    /// Create a point-in-time snapshot of mutable fields for sort stability
    pub(super) fn make_snapshot(
        &self,
        registry: VeilidComponentRegistry,
        entry: Arc<BucketEntry>,
        cur_ts: Timestamp,
    ) -> BucketEntrySnapshot {
        let mut routing_domain_snapshots = BTreeMap::new();
        if let Some(peer_info) = self.public_internet.peer_info.clone() {
            routing_domain_snapshots.insert(
                RoutingDomain::PublicInternet,
                BucketEntryRoutingDomainSnapshotInner {
                    peer_info,
                    node_status: self.public_internet.node_status.clone(),
                    last_seen_our_node_info_ts: self.public_internet.last_seen_our_node_info_ts,
                },
            );
        }
        if let Some(peer_info) = self.local_network.peer_info.clone() {
            routing_domain_snapshots.insert(
                RoutingDomain::LocalNetwork,
                BucketEntryRoutingDomainSnapshotInner {
                    peer_info,
                    node_status: self.local_network.node_status.clone(),
                    last_seen_our_node_info_ts: self.local_network.last_seen_our_node_info_ts,
                },
            );
        }
        let per_transport = self
            .per_transport_stats
            .iter()
            .map(|(t, s)| {
                let threshold = default_unreliable_lost_answers_threshold(*t);
                (
                    *t,
                    PerTransportSnapshot {
                        state: s.state(cur_ts, threshold),
                        last_question_ts: s.last_question_ts,
                        first_consecutive_seen_ts: s.first_consecutive_seen_ts,
                        failed_to_send: s.failed_to_send,
                    },
                )
            })
            .collect();
        BucketEntrySnapshot::new(
            cur_ts,
            NodeRef::new(registry, entry),
            self.peer_stats.clone(),
            self.state(cur_ts),
            self.node_ids.clone(),
            routing_domain_snapshots,
            per_transport,
        )
    }

    #[cfg(feature = "geolocation")]
    pub fn geolocation_info(&self) -> &GeolocationInfo {
        &self.geolocation_info
    }

    pub fn set_punished(&mut self, punished: Option<PunishmentReason>) {
        self.punishment = punished;
        if punished.is_some() {
            self.clear_last_flows(DialInfoFilter::all());
        }
    }

    pub fn peer_stats(&self) -> &PeerStats {
        &self.peer_stats
    }

    pub fn update_node_status(&mut self, routing_domain: RoutingDomain, status: NodeStatus) {
        match routing_domain {
            RoutingDomain::LocalNetwork => {
                self.local_network.node_status = Some(status);
            }
            RoutingDomain::PublicInternet => {
                self.public_internet.node_status = Some(status);
            }
        }
    }

    pub fn set_seen_our_node_info_ts(
        &mut self,
        routing_domain: RoutingDomain,
        seen_ts: Timestamp,
    ) -> Option<Timestamp> {
        match routing_domain {
            RoutingDomain::LocalNetwork => {
                let old_ts = self.local_network.last_seen_our_node_info_ts;
                if old_ts != seen_ts {
                    self.local_network.last_seen_our_node_info_ts = seen_ts;
                    Some(old_ts)
                } else {
                    None
                }
            }
            RoutingDomain::PublicInternet => {
                let old_ts = self.public_internet.last_seen_our_node_info_ts;
                if old_ts != seen_ts {
                    self.public_internet.last_seen_our_node_info_ts = seen_ts;
                    Some(old_ts)
                } else {
                    None
                }
            }
        }
    }

    pub fn has_seen_our_node_info_ts(
        &self,
        routing_domain: RoutingDomain,
        our_node_info_ts: Timestamp,
    ) -> bool {
        match routing_domain {
            RoutingDomain::LocalNetwork => {
                our_node_info_ts == self.local_network.last_seen_our_node_info_ts
            }
            RoutingDomain::PublicInternet => {
                our_node_info_ts == self.public_internet.last_seen_our_node_info_ts
            }
        }
    }

    pub fn reset_updated_since_last_network_change(&mut self) {
        self.updated_since_last_network_change = false;
    }

    ///// stats methods
    // called every ROLLING_TRANSFERS_INTERVAL_SECS seconds
    pub(super) fn roll_transfers(&mut self, last_ts: Timestamp, cur_ts: Timestamp) {
        self.transfer_stats_accounting.roll_transfers(
            last_ts,
            cur_ts,
            &mut self.peer_stats.transfer,
        );
        for (_key, entry) in self.routed_stats.iter_mut() {
            entry.roll_transfers(last_ts, cur_ts);
        }
    }

    pub(super) fn record_routed_up(&mut self, key: PublicKey, bytes: ByteCount) {
        self.routed_stats
            .entry(key)
            .or_insert_with(PerLocalRouteStats::default)
            .add_up(bytes);
    }
    pub(super) fn record_routed_round_trip(
        &mut self,
        key: PublicKey,
        send_ts: Timestamp,
        recv_ts: Timestamp,
        bytes: ByteCount,
    ) {
        let entry = self
            .routed_stats
            .entry(key)
            .or_insert_with(PerLocalRouteStats::default);
        entry.record_round_trip(recv_ts.duration_since(send_ts));
        entry.add_down(bytes);
    }

    #[expect(
        dead_code,
        reason = "expose via routing_table debug command when needed"
    )]
    pub fn routed_stats(&self, key: &PublicKey) -> Option<PerLocalRouteStats> {
        self.routed_stats.peek(key).cloned()
    }

    // Called for every round trip packet we receive
    fn record_latency(&mut self, latency: TimestampDuration) {
        self.peer_stats.latency = Some(self.latency_stats_accounting.record_latency(latency));
    }

    // Called when a protected connection to this peer is closed by the remote
    // side. Longer durations = more reliable peer.
    pub(super) fn record_protected_connection_drop(&mut self, duration: TimestampDuration) {
        self.peer_stats.protected_connection_drop = Some(
            self.protected_connection_drop_accounting
                .record_latency(duration),
        );
    }

    // Called every UPDATE_STATE_STATS_SECS seconds
    pub(super) fn update_state_stats(&mut self) {
        if let Some(state_stats) = self.state_stats_accounting.lock().take_stats() {
            self.peer_stats.state = state_stats;
        }
    }

    // called every ROLLING_ANSWERS_INTERVAL_SECS seconds
    pub(super) fn roll_answer_stats(&mut self, cur_ts: Timestamp) {
        for ts_stats in self.per_transport_stats.values_mut() {
            ts_stats.answer_stats = ts_stats.answer_stats_accounting.roll_answers(cur_ts);
        }
    }

    // Aggregate state is a rollup of per-transport states; Punished is node-level.

    /// All transports Dead (every entry in per_transport_stats has a Dead state
    /// reason). Empty per_transport_stats (cold start) is not Dead. Use for
    /// bucket-kick candidacy.
    pub fn is_dead(&self, cur_ts: Timestamp) -> bool {
        if self.per_transport_stats.is_empty() {
            return false;
        }
        self.iter_transport_state_reasons(cur_ts)
            .all(|r| matches!(r, BucketEntryTransportStateReason::Dead(_)))
    }

    fn iter_transport_state_reasons<'a>(
        &'a self,
        cur_ts: Timestamp,
    ) -> impl Iterator<Item = BucketEntryTransportStateReason> + 'a {
        self.per_transport_stats.iter().map(move |(t, stats)| {
            let threshold = default_unreliable_lost_answers_threshold(*t);
            stats.state_reason(cur_ts, threshold)
        })
    }

    fn transport_stats_mut(&mut self, transport: TransportType) -> &mut BucketEntryTransportStats {
        self.per_transport_stats
            .entry(transport.into())
            .or_default()
    }

    pub(super) fn touch_last_seen(&mut self, transport: TransportType, ts: Timestamp) {
        // Per-transport tracking
        let ts_stats = self.transport_stats_mut(transport);
        if ts_stats.first_consecutive_seen_ts.is_none() {
            ts_stats.first_consecutive_seen_ts = Some(ts);
        }
        ts_stats.last_seen_ts = Some(ts);

        // Legacy node-level view
        if self
            .peer_stats
            .rpc_stats
            .first_consecutive_seen_ts
            .is_none()
        {
            self.peer_stats.rpc_stats.first_consecutive_seen_ts = Some(ts);
        }
        self.peer_stats.rpc_stats.last_seen_ts = Some(ts);
    }

    pub(super) fn make_not_dead(&mut self, cur_ts: Timestamp) {
        if self.is_dead(cur_ts) {
            self.peer_stats.rpc_stats.last_seen_ts = None;
            self.peer_stats.rpc_stats.first_consecutive_seen_ts = None;
            self.peer_stats.rpc_stats.failed_to_send = 0;
            // Drop per-transport stats so each transport re-validates from
            // scratch on its next ping.
            self.per_transport_stats.clear();
            assert!(!self.is_dead(cur_ts));
        }
    }

    pub(super) fn _state_debug_info(&self, cur_ts: Timestamp) -> String {
        let first_consecutive_seen_ts = if let Some(first_consecutive_seen_ts) =
            self.peer_stats.rpc_stats.first_consecutive_seen_ts
        {
            format!("{} ago", cur_ts.duration_since(first_consecutive_seen_ts))
        } else {
            "never".to_owned()
        };
        let last_seen_ts_str = if let Some(last_seen_ts) = self.peer_stats.rpc_stats.last_seen_ts {
            format!("{} ago", cur_ts.duration_since(last_seen_ts))
        } else {
            "never".to_owned()
        };

        format!(
            "state: {:?}, first_consecutive_seen_ts: {}, last_seen_ts: {}",
            self.state_reason(cur_ts),
            first_consecutive_seen_ts,
            last_seen_ts_str
        )
    }

    ////////////////////////////////////////////////////////////////
    // Called when rpc processor things happen

    pub(super) fn question_sent(
        &mut self,
        ts: Timestamp,
        bytes: ByteCount,
        expects_answer: bool,
        transport: TransportType,
    ) {
        self.transfer_stats_accounting.add_up(bytes);

        let ts_stats = self.transport_stats_mut(transport);
        ts_stats.answer_stats_accounting.record_question(ts);
        ts_stats.failed_to_send = 0;
        if expects_answer {
            ts_stats.last_question_ts = Some(ts);
        }

        // Legacy node-level view
        self.peer_stats.rpc_stats.messages_sent += 1;
        self.peer_stats.rpc_stats.failed_to_send = 0;
        if expects_answer {
            self.peer_stats.rpc_stats.questions_in_flight += 1;
            self.peer_stats.rpc_stats.last_question_ts = Some(ts);
        }
    }
    pub(super) fn question_rcvd(
        &mut self,
        ts: Timestamp,
        bytes: ByteCount,
        transport: TransportType,
    ) {
        self.transfer_stats_accounting.add_down(bytes);
        self.peer_stats.rpc_stats.messages_rcvd += 1;
        self.touch_last_seen(transport, ts);
    }
    pub(super) fn answer_sent(&mut self, bytes: ByteCount, transport: TransportType) {
        self.transfer_stats_accounting.add_up(bytes);

        let ts_stats = self.transport_stats_mut(transport);
        ts_stats.failed_to_send = 0;

        // Legacy node-level view
        self.peer_stats.rpc_stats.messages_sent += 1;
        self.peer_stats.rpc_stats.failed_to_send = 0;
    }
    pub(super) fn answer_rcvd(
        &mut self,
        send_ts: Timestamp,
        recv_ts: Timestamp,
        bytes: ByteCount,
        transport: TransportType,
    ) {
        self.transfer_stats_accounting.add_down(bytes);

        let ts_stats = self.transport_stats_mut(transport);
        ts_stats.answer_stats_accounting.record_answer(recv_ts);
        ts_stats.recent_lost_answers = 0;

        self.peer_stats.rpc_stats.messages_rcvd += 1;
        self.peer_stats.rpc_stats.questions_in_flight -= 1;
        self.record_latency(recv_ts.duration_since(send_ts));
        self.touch_last_seen(transport, recv_ts);
    }
    pub(super) fn lost_answer(&mut self, transport: TransportType) {
        let cur_ts = Timestamp::now();

        let llt: LowLevelTransportType = transport.into();
        let threshold = default_unreliable_lost_answers_threshold(llt);
        let ts_stats = self.transport_stats_mut(transport);
        ts_stats.answer_stats_accounting.record_lost_answer(cur_ts);
        ts_stats.recent_lost_answers += 1;
        if ts_stats.recent_lost_answers > threshold {
            ts_stats.first_consecutive_seen_ts = None;
        }
        self.peer_stats.rpc_stats.questions_in_flight -= 1;
    }
    pub(super) fn failed_to_send(
        &mut self,
        ts: Timestamp,
        expects_answer: bool,
        transport: TransportType,
    ) {
        let ts_stats = self.transport_stats_mut(transport);
        if expects_answer {
            ts_stats.last_question_ts = Some(ts);
        }
        ts_stats.failed_to_send += 1;
        ts_stats.first_consecutive_seen_ts = None;

        // Legacy node-level view
        if expects_answer {
            self.peer_stats.rpc_stats.last_question_ts = Some(ts);
        }
        self.peer_stats.rpc_stats.failed_to_send += 1;
        self.peer_stats.rpc_stats.first_consecutive_seen_ts = None;
    }

    /// Send attempt aborted because no transport could be chosen (no routing domain,
    /// no peer info, no contact method). No transport was attempted so this doesn't
    /// feed per-transport stats. Not called for Punished, where we already chose not to talk.
    pub(super) fn unreachable(&mut self) {
        self.peer_stats.rpc_stats.unreachable += 1;
    }
    pub(super) fn report_sender_info(
        &mut self,
        key: LastSenderInfoKey,
        sender_info: SenderInfo,
    ) -> Option<SenderInfo> {
        let last_sender_info = self.last_sender_info.insert(key, sender_info);
        if last_sender_info != Some(sender_info) {
            // Return last senderinfo if this new one is different
            last_sender_info
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub(crate) struct BucketEntry {
    pub(super) ref_count: AtomicU32,
    inner: RwLock<BucketEntryInner>,
}

impl BucketEntry {
    pub(super) fn new(first_node_id: NodeId) -> Self {
        // First node id should always be one we support since TypedKeySets are sorted and we must have at least one supported key
        assert!(VALID_CRYPTO_KINDS.contains(&first_node_id.kind()));

        let now = Timestamp::now();
        let inner = BucketEntryInner {
            node_ids: NodeIdGroup::from(first_node_id),
            envelope_support: Vec::new(),
            updated_since_last_network_change: false,
            last_flows: BTreeMap::new(),
            last_sender_info: HashMap::new(),
            local_network: BucketEntryLocalNetwork {
                last_seen_our_node_info_ts: Timestamp::new(0u64),
                peer_info: None,
                node_status: None,
            },
            public_internet: BucketEntryPublicInternet {
                last_seen_our_node_info_ts: Timestamp::new(0u64),
                peer_info: None,
                node_status: None,
            },
            #[cfg(feature = "geolocation")]
            geolocation_info: Default::default(),
            peer_stats: PeerStats {
                time_added: now,
                rpc_stats: RPCStats::default(),
                latency: None,
                transfer: TransferStatsDownUp::default(),
                state: StateStats::default(),
                protected_connection_drop: None,
            },
            latency_stats_accounting: LatencyStatsAccounting::new(),
            protected_connection_drop_accounting: LatencyStatsAccounting::new(),
            transfer_stats_accounting: TransferStatsAccounting::new(),
            state_stats_accounting: Mutex::new(StateStatsAccounting::new()),
            per_transport_stats: BTreeMap::new(),
            routed_stats: LruCache::new(ROUTED_STATS_LRU_SIZE),
            punishment: None,
            #[cfg(feature = "tracking")]
            next_track_id: 0,
            #[cfg(feature = "tracking")]
            node_ref_tracks: HashMap::new(),
        };

        Self::new_with_inner(inner)
    }

    pub(super) fn new_with_inner(inner: BucketEntryInner) -> Self {
        Self {
            ref_count: AtomicU32::new(0),
            inner: RwLock::new(inner),
        }
    }

    /// Create a point-in-time snapshot of mutable fields for sort stability
    pub fn snapshot(
        self: &Arc<Self>,
        registry: VeilidComponentRegistry,
        cur_ts: Timestamp,
    ) -> BucketEntrySnapshot {
        let inner = self.inner.read();
        inner.make_snapshot(registry, self.clone(), cur_ts)
    }

    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&BucketEntryInner) -> R,
    {
        let inner = self.inner.read();
        f(&inner)
    }

    pub fn with_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BucketEntryInner) -> R,
    {
        let mut inner = self.inner.write();
        f(&mut inner)
    }
}

impl Drop for BucketEntry {
    fn drop(&mut self) {
        if self.ref_count.load(Ordering::Acquire) != 0 {
            #[cfg(feature = "tracking")]
            {
                veilid_log!(self info "NodeRef Tracking");
                for (id, bt) in &mut self.node_ref_tracks {
                    bt.resolve();
                    veilid_log!(self info "Id: {}\n----------------\n{:#?}", id, bt);
                }
            }

            panic!(
                "bucket entry dropped with non-zero refcount: {:#?}",
                &*self.inner.read()
            )
        }
    }
}
