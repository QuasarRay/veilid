use super::*;

impl_veilid_log_facility!("rtab");

use futures_util::stream::StreamExt;
use stop_token::future::FutureExt as StopFutureExt;

impl PublicInternetRoutingDomainController {
    // Ask our remaining peers to give us more peers before we go
    // back to the bootstrap servers to keep us from bothering them too much
    // This only adds PublicInternet routing domain peers. The discovery
    // mechanism for LocalNetwork suffices for locating all the local network
    // peers that are available. This, however, may query other LocalNetwork
    // nodes for their PublicInternet peers, which is a very fast way to get
    // a new node online. This finds nodes that have connectivity capabilities
    // specifically, as those are required for most nodes to get online.
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip(self), err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub async fn peer_minimum_refresh_task_routine(
        &self,
        stop_token: StopToken,
        _last_ts: Timestamp,
        _cur_ts: Timestamp,
    ) -> EyreResult<()> {
        // Don't bother if the state changed and we don't need peer minimum refresh
        let nodes_needed = self.nodes_needed();
        if nodes_needed.needs_peer_minimum_refresh.is_empty() {
            return Ok(());
        }
        let crypto_kinds = nodes_needed.needs_peer_minimum_refresh;

        let routing_table = self.routing_table();
        let min_peer_count = self.config().network.dht.min_peer_count as usize;
        let min_peer_refresh_time =
            TimestampDuration::new_ms(self.config().network.dht.min_peer_refresh_time_ms.into());

        // For the PublicInternet routing domain, get list of all peers we know about
        // even the unreliable ones, and ask them to find nodes close to our node too
        let mut ord = FuturesOrdered::new();
        let cur_ts = Timestamp::now();

        let nodes_found_per_crypto_kind = Arc::new(Mutex::new(BTreeMap::<
            CryptoKind,
            (HashSet<NodeRef>, HashSet<NodeRef>),
        >::new()));

        // Snapshot once for all crypto kinds, extract what we need, then drop
        // We don't use the cached snapshot summary here because we need the noderefs themselves
        let (existing_node_ids, noderefs_per_kind) = {
            let snapshot = routing_table.snapshot_entries(cur_ts, BucketEntryState::Unreliable);
            let existing_node_ids = Arc::new(snapshot.existing_node_ids());

            let mut noderefs_per_kind = Vec::new();
            for crypto_kind in &crypto_kinds {
                // Filter from the shared snapshot
                let mut filtered: Vec<&BucketEntrySnapshot> = snapshot
                    .entries()
                    .iter()
                    .filter(|snap| {
                        // Keep only the entries that contain the crypto kind we're looking for
                        if !snap.node_ids.kinds().contains(crypto_kind) {
                            return false;
                        }
                        // Keep only the entries with connectivity capabilities
                        if !snap.has_all_capabilities(
                            RoutingDomain::PublicInternet,
                            CONNECTIVITY_CAPABILITIES,
                        ) {
                            return false;
                        }
                        // Keep only the entries we haven't talked to in the min_peer_refresh_time
                        if let Some(last_q_ts) = snap.peer_stats.rpc_stats.last_question_ts {
                            if cur_ts.duration_since(last_q_ts) < min_peer_refresh_time {
                                return false;
                            }
                        }
                        true
                    })
                    .collect();

                // Sort by most reliable first, then fastest
                filtered.sort_by(|a, b| {
                    BucketEntrySnapshot::cmp_fastest_reliable(a, b, |ls| ls.average)
                });

                // Take min_peer_count and get NodeRefs
                let noderefs: Vec<NodeRef> = filtered
                    .into_iter()
                    .take(min_peer_count)
                    .map(|snap| snap.node_ref.clone())
                    .collect();

                noderefs_per_kind.push((*crypto_kind, noderefs));
            }

            (existing_node_ids, noderefs_per_kind)
        };

        for (crypto_kind, noderefs) in noderefs_per_kind {
            for nr in noderefs {
                let registry = self.registry();
                let nodes_found_per_crypto_kind = nodes_found_per_crypto_kind.clone();
                let existing_node_ids = existing_node_ids.clone();
                ord.push_back(
                    async move {
                        let routing_table = registry.routing_table();

                        // Find nodes close to ourself
                        let close_node_refs = network_result_value_or_log!(nr match pin_future!(routing_table.find_new_nodes_close_to_self(crypto_kind, &existing_node_ids, nr.routing_domain_filtered(RoutingDomain::PublicInternet).with_sequencing(Sequencing::PreferOrdered), CONNECTIVITY_CAPABILITIES.to_vec())).await {
                            Err(e) => {
                                veilid_log!(nr debug "failed to find nodes close to self: {}", e);
                                NetworkResult::value(vec![])
                            }
                            Ok(v) => v,
                        } => {
                            vec![]
                        });

                        if !close_node_refs.is_empty() {
                            veilid_log!(nr debug target:"network_result", "peer minimum refresh: found {} nodes close to self for {} in {} with {:?}", close_node_refs.len(), crypto_kind, RoutingDomain::PublicInternet, CONNECTIVITY_CAPABILITIES);
                        }

                        // Now find nodes widely across the network
                        let wide_node_refs = match pin_future!(routing_table.find_new_nodes_wide(crypto_kind, &existing_node_ids, RoutingDomain::PublicInternet, None, CONNECTIVITY_CAPABILITIES.to_vec())).await {
                            Err(e) => {
                                veilid_log!(nr debug "failed to find nodes wide: {}", e);
                                vec![]
                            }
                            Ok(v) => v,
                        };

                        if !wide_node_refs.is_empty() {
                            veilid_log!(nr debug target:"network_result", "peer minimum refresh: found {} nodes wide for {} in {} with {:?}", wide_node_refs.len(), crypto_kind, RoutingDomain::PublicInternet, CONNECTIVITY_CAPABILITIES);
                        }

                        let mut nodes_found_mut = nodes_found_per_crypto_kind.lock();
                        let nodes_found_mut_entry = nodes_found_mut.entry(crypto_kind).or_insert((HashSet::new(), HashSet::new()));
                        nodes_found_mut_entry.0.extend(close_node_refs.into_iter());
                        nodes_found_mut_entry.1.extend(wide_node_refs.into_iter());
                    }
                    .instrument(Span::current()),
                );
            }
        }

        // Process the peer minimum refresh operations in parallel
        while let Ok(Some(_)) = ord.next().timeout_at(stop_token.clone()).await {}

        // Reset the low water mark for this routing domain
        routing_table.reset_low_water_mark(RoutingDomain::PublicInternet);

        // Log what we found
        for (crypto_kind, nodes_found) in nodes_found_per_crypto_kind.lock().iter() {
            let close_nodes_count = nodes_found.0.len();
            let wide_nodes_count = nodes_found.1.len();
            if close_nodes_count > 0 || wide_nodes_count > 0 {
                veilid_log!(self info "Peer minimum refresh found {} close nodes and {} wide nodes for {}", close_nodes_count, wide_nodes_count, crypto_kind);
            }
        }

        Ok(())
    }
}
