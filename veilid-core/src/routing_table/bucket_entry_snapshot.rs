use super::*;

#[derive(Debug)]
pub(crate) struct BucketEntryRoutingDomainSnapshotInner {
    pub peer_info: Arc<PeerInfo>,
    pub node_status: Option<NodeStatus>,
    pub last_seen_our_node_info_ts: Timestamp,
}

#[derive(Debug)]
pub(crate) struct BucketEntrySnapshotInner {
    pub cur_ts: Timestamp,
    pub node_ref: NodeRef,
    pub peer_stats: PeerStats,
    pub state: BucketEntryState,
    pub node_ids: NodeIdGroup,
    pub routing_domain_snapshots: BTreeMap<RoutingDomain, BucketEntryRoutingDomainSnapshotInner>,
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
    ) -> Self {
        Self {
            inner: Arc::new(BucketEntrySnapshotInner {
                cur_ts,
                node_ref,
                peer_stats,
                state,
                node_ids,
                routing_domain_snapshots,
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

    /// Return the last time we asked a node a question
    pub fn last_outbound_contact_time(&self) -> Option<Timestamp> {
        // This is outbound and inbound contact time which may be a reasonable optimization for nodes that have
        // a very low rate of 'lost answers', but for now we are reverting this to ensure outbound connectivity before
        // we claim a node is reliable
        //
        // self.peer_stats
        //     .rpc_stats
        //     .last_seen_ts
        //     .max(self.peer_stats.rpc_stats.last_question_ts)

        self.peer_stats.rpc_stats.last_question_ts
    }

    // /// Return the last time we asked a node a question
    // pub fn last_question_time(&self) -> Option<Timestamp> {
    //     self.peer_stats.rpc_stats.last_question_ts
    // }

    pub fn needs_constant_ping(&self, interval_duration: TimestampDuration) -> bool {
        // If we have not either seen the node in the last 'interval' then we should ping it
        let latest_contact_time = self.last_outbound_contact_time();

        match latest_contact_time {
            None => true,
            Some(latest_contact_time) => {
                // If we haven't done anything with this node in 'interval' seconds
                self.cur_ts.duration_since(latest_contact_time) >= interval_duration
            }
        }
    }

    // Check if this node needs a ping right now to validate it is still reachable
    pub fn needs_ping(&self) -> bool {
        // See which ping pattern we are to use
        match self.state {
            BucketEntryState::Reliable => {
                // If we are in a reliable state, we need a ping on an exponential scale
                let latest_contact_time = self.last_outbound_contact_time();

                match latest_contact_time {
                    None => {
                        // Peer may be appear reliable from a previous attach/detach
                        // But reliability uses last_seen_ts not the last_outbound_contact_time
                        // Regardless, if we haven't pinged it, we need to ping it.
                        // But it it was reliable before, and pings successfully then it can
                        // stay reliable, so we don't make it unreliable just because we haven't
                        // contacted it yet during this attachment.
                        true
                    }
                    Some(latest_contact_time) => {
                        let first_consecutive_seen_ts = self
                            .peer_stats
                            .rpc_stats
                            .first_consecutive_seen_ts
                            .unwrap_or_log();
                        let start_of_reliable_time =
                            first_consecutive_seen_ts.later(TimestampDuration::new_secs(
                                UNRELIABLE_PING_SPAN_SECS - UNRELIABLE_PING_INTERVAL_SECS,
                            ));
                        let reliable_cur = self.cur_ts.duration_since(start_of_reliable_time);
                        let reliable_last =
                            latest_contact_time.duration_since(start_of_reliable_time);

                        retry_falloff_log(
                            reliable_last.as_u64(),
                            reliable_cur.as_u64(),
                            RELIABLE_PING_INTERVAL_START_SECS as u64 * 1_000_000u64,
                            RELIABLE_PING_INTERVAL_MAX_SECS as u64 * 1_000_000u64,
                            RELIABLE_PING_INTERVAL_MULTIPLIER,
                        )
                    }
                }
            }
            BucketEntryState::Unreliable => {
                // If we are in an unreliable state, we need a ping every UNRELIABLE_PING_INTERVAL_SECS seconds
                self.needs_constant_ping(TimestampDuration::new_secs(UNRELIABLE_PING_INTERVAL_SECS))
            }
            BucketEntryState::Dead => {
                error!("Should not be asking this for dead nodes");
                false
            }
            BucketEntryState::Punished => {
                error!("Should not be asking this for punished nodes");
                false
            }
        }
    }
}
