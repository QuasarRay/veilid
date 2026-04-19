use super::*;

impl_veilid_log_facility!("rtab");

/// How frequently we optimize relays
const RELAY_OPTIMIZATION_INTERVAL: TimestampDuration = TimestampDuration::new_secs(10);
/// What percentile to keep our relays optimized to
const RELAY_OPTIMIZATION_PERCENTILE: f32 = 66.0;
/// What percentile to choose our relays from (must be greater than RELAY_OPTIMIZATION_PERCENTILE)
const RELAY_SELECTION_PERCENTILE: f32 = 85.0;

impl PublicInternetRoutingDomainController {
    fn check_relay_valid(
        &self,
        cur_ts: Timestamp,
        relay: &RoutingDomainRelay,
        mut relay_state: RoutingDomainRelayState,
        relay_node_filter: &impl Fn(&BucketEntrySnapshot) -> bool,
        snapshot: &EntrySnapshot,
    ) -> Option<RoutingDomainRelayState> {
        let routing_table = self.routing_table();
        let relay_node = relay.relay_node.clone();
        let state_reason = relay_node.state_reason(cur_ts);

        // No best node id
        let Some(relay_node_id) = relay_node.best_node_id() else {
            veilid_log!(self debug "Relay node no longer has best node id, dropping relay {}", relay_node);
            return None;
        };

        // Relay node is dead or no longer needed
        if matches!(
            state_reason,
            BucketEntryStateReason::Dead(_) | BucketEntryStateReason::Punished(_)
        ) {
            veilid_log!(self debug "Relay node is now {:?}, dropping relay {}", state_reason, relay_node);
            return None;
        }

        // Relay node no longer can relay
        let relay_snap = relay_node
            .entry()
            .snapshot(routing_table.registry(), cur_ts);
        if !relay_node_filter(&relay_snap) {
            veilid_log!(self debug
                "Relay node can no longer relay, dropping relay {}",
                relay.relay_node
            );
            return None;
        }

        // See if our relay was optimized last long enough ago to consider getting a new one
        // if it is no longer fast enough
        let last_optimized_duration = cur_ts.duration_since(relay_state.last_optimized);
        if last_optimized_duration > RELAY_OPTIMIZATION_INTERVAL {
            // See what our relay's current percentile is
            if let Some(relay_relative_performance) = routing_table.get_node_relative_performance(
                relay_node_id,
                snapshot,
                relay_node_filter,
                |ls| ls.tm90,
            ) {
                // Get latency numbers
                let latency_stats = if let Some(latency) = relay_node.peer_stats().latency {
                    latency.to_string()
                } else {
                    "[no stats]".to_owned()
                };

                // Get current relay reliability
                let state_reason = relay_node.state_reason(cur_ts);

                if relay_relative_performance.percentile < RELAY_OPTIMIZATION_PERCENTILE {
                    // Drop the current relay so we can get the best new one
                    veilid_log!(self debug
                        "Relay tm90 is ({:.2}% < {:.2}%) ({} out of {}) (latency {}, {:?}) optimizing relay {}",
                        relay_relative_performance.percentile,
                        RELAY_OPTIMIZATION_PERCENTILE,
                        relay_relative_performance.node_index,
                        relay_relative_performance.node_count,
                        latency_stats,
                        state_reason,
                        relay_node
                    );
                    return None;
                } else {
                    // Note that we tried to optimize the relay but it was good
                    #[cfg(feature = "verbose-tracing")]
                    veilid_log!(self debug
                        "Relay tm90 is ({:.2}% >= {:.2}%) ({} out of {}) (latency {}, {:?}) keeping {}",
                        relay_relative_performance.percentile,
                        RELAY_OPTIMIZATION_PERCENTILE,
                        relay_relative_performance.node_index,
                        relay_relative_performance.node_count,
                        latency_stats,
                        state_reason,
                        relay_node
                    );
                    relay_state.last_optimized = cur_ts;
                }
            } else {
                // Drop the current relay because it could not be measured
                veilid_log!(self debug
                    "Relay relative performance not found {}",
                    relay_node
                );
                return None;
            }
        }

        Some(relay_state)
    }

    // Keep relays assigned and accessible
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn relay_management_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        cur_ts: Timestamp,
    ) -> EyreResult<()> {
        let routing_table = self.routing_table();

        // Only do this if we've reached the state where we can allocate relays meaningfully
        let state = self.state();
        let mut relay_status = match state.inbound_stage {
            RoutingDomainInboundStage::Invalid
            | RoutingDomainInboundStage::NeedsDialInfoConfirmation
            | RoutingDomainInboundStage::Unusable => return Ok(()),
            RoutingDomainInboundStage::NeedsRelays | RoutingDomainInboundStage::ReadyToPublish => {
                state.relay_status.as_ref().clone()
            }
        };

        // Get existing relays
        let original_relays_and_states = self.read_dyn().relays_and_states();

        // All sync work using the snapshot is scoped in this block
        let (original_relays, state_updates, new_relays) = {
            // Snapshot once for relay validation and allocation
            let relay_snapshot =
                routing_table.snapshot_entries(cur_ts, BucketEntryState::Unreliable);

            // Validate existing relays
            let mut original_relays = vec![];
            let mut valid_relays = vec![];
            let mut state_updates = vec![];
            let relay_node_filter = self.make_relay_node_filter();
            for (relay, relay_state) in original_relays_and_states {
                if let Some(updated_relay_state) = self.check_relay_valid(
                    cur_ts,
                    &relay,
                    relay_state,
                    &relay_node_filter,
                    &relay_snapshot,
                ) {
                    if updated_relay_state != relay_state {
                        state_updates.push((relay.clone(), updated_relay_state));
                    }
                    valid_relays.push(relay.clone());
                }
                original_relays.push(relay);
            }

            // Handle outbound relay
            let mut has_outbound_relay = false;
            let mut attempted_relays = HashSet::<NodeId>::new();
            if let Some(outbound_relay_peerinfo) =
                routing_table.get_outbound_relay_peer(RoutingDomain::PublicInternet)
            {
                // Drop outbound relay if it changed
                valid_relays.retain(|rdr| {
                    if matches!(rdr.relay_kind, RelayKind::Outbound) {
                        if rdr
                            .relay_node
                            .node_ids()
                            .contains_any_from_iter(outbound_relay_peerinfo.node_ids().iter())
                        {
                            has_outbound_relay = true;
                            true
                        } else {
                            false
                        }
                    } else {
                        true
                    }
                });

                // Allocate outbound relay if one is needed
                if !has_outbound_relay {
                    match routing_table.register_node_with_peer_info(outbound_relay_peerinfo, false)
                    {
                        Ok(relay_node) => {
                            let outbound_relay = RoutingDomainRelay::new(
                                RoutingDomain::PublicInternet,
                                relay_node.unfiltered(),
                                RelayKind::Outbound,
                            );
                            for rid in outbound_relay.relay_node.node_ids().iter() {
                                attempted_relays.insert(rid.clone());
                            }
                            relay_status.apply_relay(outbound_relay);
                        }
                        Err(e) => {
                            veilid_log!(self error "failed to register outbound relay with peer info: {}", e);
                        }
                    };
                }
            }

            // Apply valid inbound relays to status
            for relay in valid_relays {
                for rid in relay.relay_node.node_ids().iter() {
                    attempted_relays.insert(rid.clone());
                }
                relay_status.apply_relay(relay);
            }

            // Allocate new inbound relays as needed
            while relay_status.wants_more_relays() {
                let next_relay_node_filter = |snap: &BucketEntrySnapshot| {
                    // Exclude any relays we have already
                    for nid in snap.node_ids.iter() {
                        if attempted_relays.contains(nid) {
                            return false;
                        }
                    }
                    relay_node_filter(snap)
                };
                // Find a node in our routing table that is an acceptable inbound relay
                if let Some(relay_node) = routing_table.get_random_fast_node(
                    &relay_snapshot,
                    next_relay_node_filter,
                    RELAY_SELECTION_PERCENTILE,
                    |ls| ls.tm90,
                ) {
                    for rid in relay_node.node_ids().iter() {
                        attempted_relays.insert(rid.clone());
                    }

                    let routing_domain_relay = RoutingDomainRelay::new(
                        RoutingDomain::PublicInternet,
                        relay_node,
                        RelayKind::Inbound,
                    );

                    relay_status.apply_relay(routing_domain_relay);
                } else {
                    // No relays left, we did our best
                    break;
                }
            }

            // Get final sorted list of relays
            let new_relays = relay_status.get_sorted_relays_list();

            (original_relays, state_updates, new_relays)
        };

        // Apply all changes in a single editor commit
        let mut editor = self.edit();

        for (relay, state) in state_updates {
            editor.set_relay_state(relay, state);
        }

        if new_relays != original_relays {
            editor.set_relays(new_relays);
        }

        editor.commit();
        self.publish_peer_info();

        Ok(())
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn make_relay_node_filter(&self) -> impl Fn(&BucketEntrySnapshot) -> bool {
        let ip6_prefix_size = self.config().network.max_connections_per_ip6_prefix_size as usize;

        // Get all our outbound protocol/address types
        let outbound_dif = self.read_dyn().outbound_dial_info_filter();

        // Get our own peer info
        let own_peer_info = self.read_dyn().get_peer_info();

        move |snap: &BucketEntrySnapshot| {
            // Ensure this node is not on the local network
            if snap
                .routing_domain_set()
                .contains(RoutingDomain::LocalNetwork)
            {
                return false;
            }

            // Exclude any nodes that don't have a 'best node id' for our enabled cryptosystems
            if snap.best_node_id().is_none() {
                return false;
            }

            // Exclude any nodes that have 'failed to send' state indicating a
            // connection drop or inability to reach the node
            if snap.peer_stats.rpc_stats.failed_to_send > 0 {
                return false;
            }

            // Get the public internet peer info so we can validate it
            let Some(peer_info) = snap.get_peer_info(RoutingDomain::PublicInternet) else {
                return false;
            };

            // Exclude any nodes that are relaying directly through us
            if own_peer_info
                .node_ids()
                .contains_any_from_iter(peer_info.node_info().relay_ids().iter())
            {
                return false;
            }

            // Disqualify nodes that don't have relay capability
            if !peer_info
                .node_info()
                .has_capability(VEILID_CAPABILITY_RELAY)
            {
                return false;
            }

            // Disqualify any nodes that don't speak all of the envelope versions we do
            let peer_envelope_support = peer_info.node_info().envelope_support();
            if own_peer_info
                .node_info()
                .envelope_support()
                .iter()
                .copied()
                .any(|x| !peer_envelope_support.contains(&x))
            {
                return false;
            }

            // Ensure there is a way to reach this relay
            let mut directly_reachable = false;
            for did in peer_info.node_info().dial_info_detail_list() {
                if did.class.requires_signal() {
                    continue;
                }
                // If this dial info can be contacted directly, then it is a relay candidate
                if did.dial_info.matches_filter(&outbound_dif) {
                    directly_reachable = true;
                    break;
                }
            }

            if !directly_reachable {
                return false;
            }

            // Exclude any nodes that have our same network block
            if own_peer_info
                .node_info()
                .is_on_same_ipblock(peer_info.node_info(), ip6_prefix_size)
            {
                return false;
            }

            true
        }
    }
}
