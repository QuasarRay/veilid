use super::*;

#[derive(Debug)]
pub(crate) struct BucketEntryRoutingDomainSnapshotInner {
    pub peer_info: Arc<PeerInfo>,
    pub node_status: Option<NodeStatus>,
    pub last_seen_our_node_info_ts: Timestamp,
}

/// Frozen per-transport view used by ping scheduling and selection.
#[derive(Debug, Clone)]
pub(crate) struct PerTransportSnapshot {
    /// Reliability state of this transport.
    pub state: BucketEntryTransportState,
    /// Last time we asked this transport a question.
    pub last_question_ts: Option<Timestamp>,
    /// Timestamp of the first answer in the current consecutive-seen run.
    pub first_consecutive_seen_ts: Option<Timestamp>,
    /// Pending send failures since the last successful send on this transport.
    pub failed_to_send: u32,
}

#[derive(Debug)]
pub(crate) struct BucketEntrySnapshotInner {
    pub cur_ts: Timestamp,
    pub node_ref: NodeRef,
    pub peer_stats: PeerStats,
    pub state: BucketEntryState,
    pub node_ids: NodeIdGroup,
    pub routing_domain_snapshots: BTreeMap<RoutingDomain, BucketEntryRoutingDomainSnapshotInner>,
    pub per_transport: BTreeMap<LowLevelTransportType, PerTransportSnapshot>,
}

/// A point-in-time snapshot of mutable BucketEntry fields used for sorting and filtering.
/// Created once before sorting to avoid total-order violations from concurrent
/// updates between comparisons (Rust 1.81+ driftsort validates total ordering).
///
/// Contains a `NodeRef` for creating `FilteredNodeRef` in transforms, and frozen
/// copies of all mutable fields needed by sort/filter closures. `Option<BucketEntrySnapshot>`
/// where `None` represents the self node.
#[derive(Clone, Debug)]
pub(crate) struct BucketEntrySnapshot {
    inner: Arc<BucketEntrySnapshotInner>,
}

impl core::ops::Deref for BucketEntrySnapshot {
    type Target = BucketEntrySnapshotInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl BucketEntrySnapshot {
    pub(super) fn new(
        cur_ts: Timestamp,
        node_ref: NodeRef,
        peer_stats: PeerStats,
        state: BucketEntryState,
        node_ids: NodeIdGroup,
        routing_domain_snapshots: BTreeMap<RoutingDomain, BucketEntryRoutingDomainSnapshotInner>,
        per_transport: BTreeMap<LowLevelTransportType, PerTransportSnapshot>,
    ) -> Self {
        Self {
            inner: Arc::new(BucketEntrySnapshotInner {
                cur_ts,
                node_ref,
                peer_stats,
                state,
                node_ids,
                routing_domain_snapshots,
                per_transport,
            }),
        }
    }

    pub fn crypto_kinds(&self) -> Vec<CryptoKind> {
        self.node_ids.iter().map(|x| x.kind()).collect()
    }

    pub fn routing_domain_set(&self) -> RoutingDomainSet {
        self.routing_domain_snapshots.keys().cloned().collect()
    }

    pub fn is_reliable(&self) -> bool {
        self.state == BucketEntryState::Reliable
    }

    #[expect(dead_code)]
    pub fn is_reliable_for(&self, transport: LowLevelTransportType) -> bool {
        self.per_transport
            .get(&transport)
            .map(|t| t.state == BucketEntryTransportState::Reliable)
            .unwrap_or(false)
    }

    pub fn transport_state(
        &self,
        transport: LowLevelTransportType,
    ) -> Option<BucketEntryTransportState> {
        self.per_transport.get(&transport).map(|t| t.state)
    }

    /// Set of low-level transports the node can be reached through (directly or
    /// via any of its relays), filtered by our outbound dial-info filter.
    pub fn supported_low_level_transports(
        &self,
        routing_domain: RoutingDomain,
        outbound_dif: &DialInfoFilter,
    ) -> BTreeSet<LowLevelTransportType> {
        let Some(pi) = self.get_peer_info(routing_domain) else {
            return BTreeSet::new();
        };
        pi.node_info().low_level_transport_set(outbound_dif)
    }

    /// Best high-level TransportType for a given low-level transport on this node,
    /// considering own and relay dial infos. None if outbound_dif filters everything.
    pub fn preferred_transport_for(
        &self,
        routing_domain: RoutingDomain,
        low_level: LowLevelTransportType,
        outbound_dif: &DialInfoFilter,
    ) -> Option<TransportType> {
        let pi = self.get_peer_info(routing_domain)?;
        pi.node_info()
            .preferred_transport_for(low_level, outbound_dif)
    }

    pub fn has_node_info(&self, routing_domain_set: RoutingDomainSet) -> bool {
        routing_domain_set
            .iter()
            .any(|routing_domain| self.routing_domain_snapshots.contains_key(&routing_domain))
    }

    pub fn best_node_id(&self) -> Option<NodeId> {
        self.node_ids.first().cloned()
    }

    pub fn get_peer_info(&self, routing_domain: RoutingDomain) -> Option<Arc<PeerInfo>> {
        self.routing_domain_snapshots
            .get(&routing_domain)
            .map(|x| x.peer_info.clone())
    }

    pub fn node_status(&self, routing_domain: RoutingDomain) -> Option<NodeStatus> {
        self.routing_domain_snapshots
            .get(&routing_domain)
            .and_then(|x| x.node_status.clone())
    }

    pub fn is_tested(&self) -> bool {
        self.peer_stats
            .rpc_stats
            .first_consecutive_seen_ts
            .is_some()
            && self.peer_stats.latency.is_some()
    }

    pub fn has_all_capabilities(
        &self,
        routing_domain: RoutingDomain,
        capabilities: &[VeilidCapability],
    ) -> bool {
        let Some(pi) = self.get_peer_info(routing_domain) else {
            return false;
        };
        pi.node_info().has_all_capabilities(capabilities)
    }

    pub fn cmp_fastest(
        a: &Self,
        b: &Self,
        metric: impl Fn(&LatencyStats) -> TimestampDuration,
    ) -> std::cmp::Ordering {
        // Lower latency to the front
        if let Some(a_latency) = &a.peer_stats.latency {
            if let Some(b_latency) = &b.peer_stats.latency {
                metric(a_latency).cmp(&metric(b_latency))
            } else {
                std::cmp::Ordering::Less
            }
        } else if b.peer_stats.latency.is_some() {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    }

    // Less is more reliable then faster
    pub fn cmp_fastest_reliable(
        a: &Self,
        b: &Self,
        metric: impl Fn(&LatencyStats) -> TimestampDuration,
    ) -> std::cmp::Ordering {
        // Reverse compare so most reliable is at front
        let ret = b.state.cmp(&a.state);
        if ret != std::cmp::Ordering::Equal {
            return ret;
        }

        // Lower latency to the front
        Self::cmp_fastest(a, b, metric)
    }

    // Less is more reliable then older
    pub fn cmp_oldest_reliable(a: &Self, b: &Self) -> std::cmp::Ordering {
        // Reverse compare so most reliable is at front
        let ret = b.state.cmp(&a.state);
        if ret != std::cmp::Ordering::Equal {
            return ret;
        }

        // Lower timestamp to the front, recent or no timestamp is at the end
        // First check consecutive-ping reliability timestamp
        if let Some(a_ts) = &a.peer_stats.rpc_stats.first_consecutive_seen_ts {
            if let Some(b_ts) = &b.peer_stats.rpc_stats.first_consecutive_seen_ts {
                a_ts.cmp(b_ts)
            } else {
                std::cmp::Ordering::Less
            }
        } else if b.peer_stats.rpc_stats.first_consecutive_seen_ts.is_some() {
            std::cmp::Ordering::Greater
        } else {
            // Then check 'since added to routing table' timestamp
            a.peer_stats.time_added.cmp(&b.peer_stats.time_added)
        }
    }

    pub fn has_seen_our_node_info_ts(
        &self,
        routing_domain: RoutingDomain,
        our_node_info_ts: Timestamp,
    ) -> bool {
        let Some(rds) = self.routing_domain_snapshots.get(&routing_domain) else {
            return false;
        };
        our_node_info_ts == rds.last_seen_our_node_info_ts
    }

    /// Per-transport ping decision. Returns false if the transport has no stats yet
    /// (no DialInfo for it, or never used) - callers should check `supported_transports`
    /// against the peer info for cold-start pings.
    pub fn needs_ping_for(&self, transport: LowLevelTransportType) -> bool {
        let Some(t) = self.per_transport.get(&transport) else {
            return false;
        };
        match t.state {
            BucketEntryTransportState::Reliable => match t.last_question_ts {
                None => true,
                Some(latest_contact_time) => {
                    let first_consecutive_seen_ts = t.first_consecutive_seen_ts.unwrap_or_log();
                    let start_of_reliable_time =
                        first_consecutive_seen_ts.later(TimestampDuration::new_secs(
                            UNRELIABLE_PING_SPAN_SECS - UNRELIABLE_PING_INTERVAL_SECS,
                        ));
                    let reliable_cur = self.cur_ts.duration_since(start_of_reliable_time);
                    let reliable_last = latest_contact_time.duration_since(start_of_reliable_time);
                    retry_falloff_log(
                        reliable_last.as_u64(),
                        reliable_cur.as_u64(),
                        RELIABLE_PING_INTERVAL_START_SECS as u64 * 1_000_000u64,
                        RELIABLE_PING_INTERVAL_MAX_SECS as u64 * 1_000_000u64,
                        RELIABLE_PING_INTERVAL_MULTIPLIER,
                    )
                }
            },
            BucketEntryTransportState::Unreliable => match t.last_question_ts {
                None => true,
                Some(latest_contact_time) => {
                    self.cur_ts.duration_since(latest_contact_time)
                        >= TimestampDuration::new_secs(UNRELIABLE_PING_INTERVAL_SECS)
                }
            },
            BucketEntryTransportState::Dead => false,
        }
    }
}
