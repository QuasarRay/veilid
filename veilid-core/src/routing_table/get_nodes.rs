//! Utilities to get nodes and/or peer info in our existing routing table
//!
//! Does not use the network, only locate nodes within what we have already

use super::*;

impl_veilid_log_facility!("rtab");

impl RoutingTable {
    pub fn need_ping_priority(
        &self,
        routing_domain: RoutingDomain,
        opt_own_node_info_ts: Option<Timestamp>,
        snap: &BucketEntrySnapshot,
    ) -> Option<usize> {
        // If this entry doesn't have node info in the routing domain we are checking, don't include it
        if !snap.has_node_info(routing_domain.into()) {
            return None;
        }

        // If we don't have node status for this node, then we should ping it to get some node status
        if snap.node_status(routing_domain).is_none() {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug "Ping reason: node_status is none (rd={:?} ids={:?})", routing_domain, snap.node_ids);
            return Some(50);
        }

        // If this entry needs a ping because this node hasn't seen our latest node info, then do it
        if let Some(own_node_info_ts) = opt_own_node_info_ts {
            if !snap.has_seen_our_node_info_ts(routing_domain, own_node_info_ts) {
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(self debug "Ping reason: has not seen our node info timestamp (rd={:?} ids={:?} own_ni_ts={}",
                    routing_domain, snap.node_ids, own_node_info_ts);
                return Some(75);
            }
        }

        // If this entry needs need a ping by non-routing-domain-specific metrics then do it
        if snap.needs_ping() {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug "Ping reason: timing (rd={:?} ids={:?})", routing_domain, snap.node_ids);
            return Some(100);
        }

        None
    }

    /// See which nodes need to be pinged
    pub fn get_relability_ping_nodes(
        &self,
        routing_domain: RoutingDomain,
        cur_ts: Timestamp,
    ) -> BTreeMap<usize, Vec<FilteredNodeRef>> {
        let opt_own_node_info_ts = self
            .get_published_peer_info(routing_domain)
            .map(|pi| pi.node_info().timestamp());

        let mut filters = VecDeque::new();

        // Remove our own node from the results
        let filter_self =
            Box::new(move |v: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| v.is_some())
                as RoutingTableEntryFilter;
        filters.push_back(filter_self);

        let filter_ping = Box::new(move |v: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
            let snap = v.as_ref().unwrap_or_log();

            // See if this node needs a ping
            self.need_ping_priority(routing_domain, opt_own_node_info_ts, snap)
                .is_some()
        }) as RoutingTableEntryFilter;
        filters.push_back(filter_ping);

        // Sort by least recently contacted
        let compare = Box::new(
            |opt_a_snap: &Option<BucketEntrySnapshot>,
             opt_b_snap: &Option<BucketEntrySnapshot>,
             _cur_ts: Timestamp| {
                // Self node is always filtered out, so it is safe to unwrap here
                let a_snap = opt_a_snap.as_ref().unwrap_or_log();
                let b_snap = opt_b_snap.as_ref().unwrap_or_log();

                // Sort by least recently contacted regardless of reliability
                let ca = a_snap
                    .peer_stats
                    .rpc_stats
                    .last_question_ts
                    .unwrap_or(Timestamp::new(0))
                    .as_u64();
                let cb = b_snap
                    .peer_stats
                    .rpc_stats
                    .last_question_ts
                    .unwrap_or(Timestamp::new(0))
                    .as_u64();
                ca.cmp(&cb)
            },
        ) as RoutingTableEntrySort;

        let transform = |opt_snap: Option<BucketEntrySnapshot>| {
            // Self node is always filtered out, so it is safe to unwrap here
            let snap = opt_snap.unwrap_or_log();

            let ping_priority = self
                .need_ping_priority(routing_domain, opt_own_node_info_ts, &snap)
                .unwrap_or_log();

            (
                ping_priority,
                snap.node_ref.routing_domain_filtered(routing_domain),
            )
        };

        let pre_sort_filter = Box::new(
            |_all_snaps: &mut Vec<Option<BucketEntrySnapshot>>, _cur_ts: Timestamp| {
                //
            },
        ) as RoutingTableEntryPreSortFilter;

        let snapshot = self.snapshot_entries(cur_ts, BucketEntryState::Unreliable);

        let priority_nodes: Vec<(usize, FilteredNodeRef)> = snapshot
            .get_peers_with_sort_and_filter(
                usize::MAX,
                cur_ts,
                filters,
                pre_sort_filter,
                compare,
                transform,
            );

        let mut out: BTreeMap<usize, Vec<FilteredNodeRef>> = BTreeMap::new();
        for (priority, node) in priority_nodes {
            out.entry(priority).or_default().push(node);
        }

        out
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn find_fast_non_local_nodes_filtered(
        &self,
        routing_domain: RoutingDomain,
        node_count: usize,
        mut filters: VecDeque<RoutingTableEntryFilter>,
    ) -> Vec<NodeRef> {
        assert_ne!(
            routing_domain,
            RoutingDomain::LocalNetwork,
            "LocalNetwork is not a valid non-local RoutingDomain"
        );
        let public_node_filter =
            Box::new(move |v: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
                let snap = v.as_ref().unwrap_or_log();
                // skip nodes on local network
                if snap.has_node_info(RoutingDomain::LocalNetwork.into()) {
                    return false;
                }
                // skip nodes not on desired routing domain
                if !snap.has_node_info(routing_domain.into()) {
                    return false;
                }
                true
            }) as RoutingTableEntryFilter;
        filters.push_front(public_node_filter);

        self.get_preferred_fastest_nodes(node_count, filters, |v: Option<BucketEntrySnapshot>| {
            v.unwrap_or_log().node_ref.clone()
        })
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn get_preferred_fastest_nodes<T, O>(
        &self,
        node_count: usize,
        mut filters: VecDeque<RoutingTableEntryFilter>,
        transform: T,
    ) -> Vec<O>
    where
        T: FnMut(Option<BucketEntrySnapshot>) -> O + Send,
    {
        let cur_ts = Timestamp::now();

        // always filter out self peer, as it is irrelevant to the 'fastest nodes' search
        let filter_self =
            Box::new(move |v: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| v.is_some())
                as RoutingTableEntryFilter;
        filters.push_front(filter_self);

        // Fastest sort
        let sort = Box::new(
            |a_entry: &Option<BucketEntrySnapshot>,
             b_entry: &Option<BucketEntrySnapshot>,
             _cur_ts: Timestamp| {
                // both None (self) are equal
                let (Some(a), Some(b)) = (a_entry.as_ref(), b_entry.as_ref()) else {
                    if a_entry.is_none() && b_entry.is_none() {
                        return core::cmp::Ordering::Equal;
                    }
                    // our own node always comes last
                    return if a_entry.is_none() {
                        core::cmp::Ordering::Greater
                    } else {
                        core::cmp::Ordering::Less
                    };
                };

                // reliable nodes come first
                let ra = a.is_reliable();
                let rb = b.is_reliable();
                if ra != rb {
                    return if ra {
                        core::cmp::Ordering::Less
                    } else {
                        core::cmp::Ordering::Greater
                    };
                }

                // latency is the next metric, lower latency first
                // Both None = Equal (fixes the None/None total-order bug)
                BucketEntrySnapshot::cmp_fastest(a, b, |ls| ls.average)
            },
        ) as RoutingTableEntrySort;

        let pre_sort_filter = Box::new(
            |_all_entries: &mut Vec<Option<BucketEntrySnapshot>>, _cur_ts| {
                //
            },
        ) as RoutingTableEntryPreSortFilter;

        let snapshot = self.snapshot_entries(cur_ts, BucketEntryState::Unreliable);

        snapshot.get_peers_with_sort_and_filter(
            node_count,
            cur_ts,
            filters,
            pre_sort_filter,
            sort,
            transform,
        )
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub fn get_preferred_closest_nodes<T, O>(
        &self,
        node_count: usize,
        hash_coordinate: HashCoordinate,
        mut filters: VecDeque<RoutingTableEntryFilter>,
        transform: T,
    ) -> Vec<O>
    where
        T: FnMut(Option<BucketEntrySnapshot>) -> O + Send,
    {
        let cur_ts = Timestamp::now();
        let routing_table = self.routing_table();

        // Get the crypto kind
        let crypto_kind = hash_coordinate.kind();

        // Filter to ensure entries support the crypto kind in use
        // always filter out dead and punished nodes
        let filter = Box::new(
            move |opt_entry: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
                if let Some(snap) = opt_entry {
                    snap.node_ids.kinds().contains(&crypto_kind)
                } else {
                    VALID_CRYPTO_KINDS.contains(&crypto_kind)
                }
            },
        ) as RoutingTableEntryFilter;
        filters.push_front(filter);

        // Closest sort
        // Distance is done using the node id's distance metric which may vary based on crypto system
        let sort = Box::new(
            |a_entry: &Option<BucketEntrySnapshot>,
             b_entry: &Option<BucketEntrySnapshot>,
             _cur_ts: Timestamp| {
                // both None (self) are equal
                if a_entry.is_none() && b_entry.is_none() {
                    return core::cmp::Ordering::Equal;
                }

                // reliable nodes come first, pessimistically treating our own node as unreliable
                let ra = a_entry.as_ref().is_some_and(|x| x.is_reliable());
                let rb = b_entry.as_ref().is_some_and(|x| x.is_reliable());
                if ra != rb {
                    return if ra {
                        core::cmp::Ordering::Less
                    } else {
                        core::cmp::Ordering::Greater
                    };
                }

                // get keys
                let a_key = if let Some(a) = a_entry.as_ref() {
                    a.node_ids.get(crypto_kind).unwrap_or_log()
                } else {
                    routing_table.node_id(crypto_kind)
                };
                let b_key = if let Some(b) = b_entry.as_ref() {
                    b.node_ids.get(crypto_kind).unwrap_or_log()
                } else {
                    routing_table.node_id(crypto_kind)
                };

                // distance is the next metric, closer nodes first
                let da = a_key
                    .ref_value()
                    .to_bare_hash_coordinate()
                    .distance(hash_coordinate.ref_value());
                let db = b_key
                    .ref_value()
                    .to_bare_hash_coordinate()
                    .distance(hash_coordinate.ref_value());
                da.cmp(&db)
            },
        ) as RoutingTableEntrySort;

        let pre_sort_filter = Box::new(
            |_all_entries: &mut Vec<Option<BucketEntrySnapshot>>, _cur_ts: Timestamp| {
                //
            },
        ) as RoutingTableEntryPreSortFilter;

        let snapshot = self.snapshot_entries(cur_ts, BucketEntryState::Unreliable);

        let out = snapshot.get_peers_with_sort_and_filter(
            node_count,
            cur_ts,
            filters,
            pre_sort_filter,
            sort,
            transform,
        );
        veilid_log!(self trace ">> find_closest_nodes: node count = {}", out.len());
        out
    }

    #[expect(dead_code)]
    pub fn sort_and_clean_closest_noderefs(
        &self,
        hash_coordinate: HashCoordinate,
        closest_nodes: &[NodeRef],
    ) -> Vec<NodeRef> {
        let kind = hash_coordinate.kind();
        let mut closest_nodes: Vec<NodeRef> = closest_nodes
            .iter()
            .filter_map(|nr| {
                if nr.node_ids().kinds().contains(&kind) {
                    Some(nr.clone())
                } else {
                    None
                }
            })
            .collect();

        // Sort closest
        let sort = Self::make_closest_noderef_sort(hash_coordinate);
        closest_nodes.sort_by(sort);

        closest_nodes
    }

    pub fn make_closest_noderef_sort(
        hash_coordinate: HashCoordinate,
    ) -> impl Fn(&NodeRef, &NodeRef) -> core::cmp::Ordering {
        let kind = hash_coordinate.kind();

        move |a: &NodeRef, b: &NodeRef| -> core::cmp::Ordering {
            // same nodes are always the same
            if a.same_entry(b) {
                return core::cmp::Ordering::Equal;
            }

            a.operate(|a_entry| {
                b.operate(|b_entry| {
                    // get keys
                    let a_key = a_entry.node_ids().get(kind).unwrap_or_log();
                    let b_key = b_entry.node_ids().get(kind).unwrap_or_log();

                    // distance is the next metric, closer nodes first
                    let da = a_key
                        .ref_value()
                        .to_bare_hash_coordinate()
                        .distance(hash_coordinate.ref_value());
                    let db = b_key
                        .ref_value()
                        .to_bare_hash_coordinate()
                        .distance(hash_coordinate.ref_value());
                    da.cmp(&db)
                })
            })
        }
    }

    /// Utility to find the closest nodes to a particular hash coordinate, preferring reliable nodes first,
    /// including possibly our own node and nodes further away from the key than our own,
    /// returning their peer info
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab", skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn get_preferred_closest_nodes_peer_info(
        &self,
        routing_domain: RoutingDomain,
        hash_coordinate: HashCoordinate,
        capabilities: &[VeilidCapability],
    ) -> Vec<Arc<PeerInfo>> {
        let opt_published_peer_info = self.get_published_peer_info(routing_domain);
        let include_self = opt_published_peer_info
            .as_ref()
            .map(|x| x.node_info().has_all_capabilities(capabilities))
            .unwrap_or_default();

        // find N nodes closest to the target node in our routing table
        let filter = Box::new(
            |opt_entry: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
                // Ensure only things that are valid in the chosen routing domain,
                // and with matching capabilities are returned
                match opt_entry {
                    Some(snap) => snap.has_all_capabilities(routing_domain, capabilities),
                    None => include_self,
                }
            },
        ) as RoutingTableEntryFilter;
        let filters = VecDeque::from([filter]);

        let node_count = self.config().network.dht.max_find_node_count as usize;

        self.get_preferred_closest_nodes(
            node_count,
            hash_coordinate.clone(),
            filters,
            // transform
            |opt_entry| match opt_entry {
                Some(snap) => snap.get_peer_info(routing_domain).unwrap_or_log(),
                None => opt_published_peer_info.clone().unwrap_or_log(),
            },
        )
    }

    /// Utility to find nodes that are closer to a key than our own node,
    /// returning only reliable nodes, and returning their peer info
    /// Can filter based on a particular set of capabilities
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab", skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn get_reliable_nodes_closer_to_key_peer_info(
        &self,
        routing_domain: RoutingDomain,
        hash_coordinate: HashCoordinate,
        required_capabilities: Vec<VeilidCapability>,
    ) -> NetworkResult<Vec<Arc<PeerInfo>>> {
        let crypto_kind = hash_coordinate.kind();
        let own_node_id = self.node_id(crypto_kind);

        // find N nodes closest to the target node in our routing table
        // ensure the nodes returned are only the ones closer to the target node than ourself
        let own_distance = own_node_id.to_hash_coordinate().distance(&hash_coordinate);

        let hash_coordinate2 = hash_coordinate.clone();
        let filter = Box::new(
            move |opt_entry: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
                // Exclude our own node
                let Some(snap) = opt_entry else {
                    return false;
                };
                // Ensure only things that have a minimum set of capabilities are returned
                if !snap.has_all_capabilities(routing_domain, &required_capabilities) {
                    return false;
                }

                if !snap.is_reliable() {
                    return false;
                }

                // Ensure things further from the key than our own node are not included
                let Some(entry_node_id) = snap.node_ids.get(crypto_kind) else {
                    return false;
                };
                let entry_distance = entry_node_id
                    .to_hash_coordinate()
                    .distance(&hash_coordinate2);
                if entry_distance >= own_distance {
                    return false;
                }
                true
            },
        ) as RoutingTableEntryFilter;
        let filters = VecDeque::from([filter]);

        let node_count = self.config().network.dht.max_find_node_count as usize;

        //
        let closest_nodes = self.get_preferred_closest_nodes(
            node_count,
            hash_coordinate.clone(),
            filters,
            // transform
            |entry| {
                let snap = entry.unwrap_or_log();
                snap.get_peer_info(routing_domain).unwrap_or_log()
            },
        );

        // Validate peers returned are, in fact, closer to the key than the node we sent this to
        // This same test is used on the other side so we vet things here
        let valid = match self.verify_peer_infos_closer(
            own_node_id.to_hash_coordinate(),
            hash_coordinate.clone(),
            &closest_nodes,
        ) {
            Ok(v) => v,
            Err(e) => {
                veilid_log!(self error "missing cryptosystem in peers node ids: {}", e);
                return NetworkResult::invalid_message("missing cryptosystem in peer's node ids");
            }
        };
        if !valid {
            veilid_log!(self debug
                "non-closer peers returned: own_node_id={:#?} key={:#?} closest_nodes={:#?}",
                own_node_id, hash_coordinate, closest_nodes
            );
            return NetworkResult::invalid_message("non-closer peers returned");
        }

        NetworkResult::value(closest_nodes)
    }

    /// Utility to find the node that is closest to a hash coordinate
    /// Reliable nodes will be preferred, but if no reliable nodes are found the closest unreliable node will be returned
    /// Can filter based on a particular set of capabilities
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab", skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    #[expect(dead_code)]
    pub fn get_node_closest_to_hash_coordinate(
        &self,
        routing_domain: RoutingDomain,
        hash_coordinate: HashCoordinate,
        required_capabilities: Vec<VeilidCapability>,
    ) -> Option<FilteredNodeRef> {
        let filter = Box::new(
            move |opt_entry: &Option<BucketEntrySnapshot>, _cur_ts: Timestamp| {
                // Exclude our own node
                let Some(snap) = opt_entry else {
                    return false;
                };
                // Ensure only things that have a minimum set of capabilities are returned
                snap.has_all_capabilities(routing_domain, &required_capabilities)
            },
        ) as RoutingTableEntryFilter;
        let filters = VecDeque::from([filter]);

        let transform = |v: Option<BucketEntrySnapshot>| {
            let snap = v.unwrap_or_log();
            snap.node_ref.routing_domain_filtered(routing_domain)
        };

        // Get the closest node to the hash coordinate
        let closest_nodes =
            self.get_preferred_closest_nodes(1, hash_coordinate.clone(), filters, transform);

        closest_nodes.into_iter().next()
    }

    /// Find the closest node to each of multiple hash coordinates using a single snapshot.
    /// All coordinates must use the same crypto kind.
    /// Returns one Option<FilteredNodeRef> per coordinate (None if no matching node found).
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab", skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn get_nodes_closest_to_multiple_hash_coordinates(
        &self,
        routing_domain: RoutingDomain,
        hash_coordinates: &[HashCoordinate],
        required_capabilities: &[VeilidCapability],
        snapshot: &EntrySnapshot,
    ) -> Vec<Option<FilteredNodeRef>> {
        if hash_coordinates.is_empty() {
            return Vec::new();
        }
        let crypto_kind = hash_coordinates[0].kind();

        // Filter from the provided snapshot
        let filtered: Vec<&BucketEntrySnapshot> = snapshot
            .entries()
            .iter()
            .filter(|snap| {
                snap.node_ids.kinds().contains(&crypto_kind)
                    && snap.has_all_capabilities(routing_domain, required_capabilities)
            })
            .collect();

        // For each coordinate, find the closest entry (reliable-first, then by distance)
        hash_coordinates
            .iter()
            .map(|hc| {
                filtered
                    .iter()
                    .min_by(|a, b| {
                        // reliable first
                        let ra = a.is_reliable();
                        let rb = b.is_reliable();
                        if ra != rb {
                            return if ra {
                                core::cmp::Ordering::Less
                            } else {
                                core::cmp::Ordering::Greater
                            };
                        }
                        // then by distance
                        let da = a
                            .node_ids
                            .get(crypto_kind)
                            .unwrap_or_log()
                            .to_hash_coordinate()
                            .distance(hc);
                        let db = b
                            .node_ids
                            .get(crypto_kind)
                            .unwrap_or_log()
                            .to_hash_coordinate()
                            .distance(hc);
                        da.cmp(&db)
                    })
                    .map(|snap| {
                        snap.node_ref
                            .clone()
                            .routing_domain_filtered(routing_domain)
                    })
            })
            .collect()
    }

    /// Determine if set of peers is closer to key_near than key_far is to key_near
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn verify_peer_infos_closer(
        &self,
        hash_coordinate_far: HashCoordinate,
        hash_coordinate_near: HashCoordinate,
        peers: &[Arc<PeerInfo>],
    ) -> EyreResult<bool> {
        if hash_coordinate_far.kind() != hash_coordinate_near.kind() {
            bail!("keys all need the same cryptosystem");
        }

        let mut closer = true;
        let d_far = hash_coordinate_far.distance(&hash_coordinate_near);
        for peer in peers {
            let Some(key_peer) = peer.node_ids().get(hash_coordinate_far.kind()) else {
                bail!("peers need to have a key with the same cryptosystem");
            };
            let d_near = hash_coordinate_near.distance(&key_peer.to_hash_coordinate());
            if d_far < d_near {
                let warning = format!(
                    r#"peer: {}
near (key): {}
far (self): {}
    d_near: {}
     d_far: {}
       cmp: {:?}"#,
                    key_peer,
                    hash_coordinate_near,
                    hash_coordinate_far,
                    d_near,
                    d_far,
                    d_near.cmp(&d_far)
                );
                veilid_log!(self warn "{}", warning);
                closer = false;
                break;
            }
        }

        Ok(closer)
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", skip(self, filter, metric), ret, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn get_random_fast_node(
        &self,
        snapshot: &EntrySnapshot,
        filter: impl Fn(&BucketEntrySnapshot) -> bool,
        percentile: f32,
        metric: impl Fn(&LatencyStats) -> TimestampDuration,
    ) -> Option<NodeRef> {
        // Go through all entries and find all entries that matches filter function
        let mut all_filtered_nodes: Vec<&BucketEntrySnapshot> = snapshot
            .entries()
            .iter()
            .filter(|snap| filter(snap))
            .collect();

        // Sort by fastest tm90 reliable
        all_filtered_nodes.sort_by(|a, b| BucketEntrySnapshot::cmp_fastest_reliable(a, b, &metric));

        if all_filtered_nodes.is_empty() {
            return None;
        }

        let max_index =
            (((all_filtered_nodes.len() - 1) as f32) * (100.0 - percentile) / 100.0) as u32;
        let chosen_index = (get_random_u32() % (max_index + 1)) as usize;

        // Return the chosen node
        Some(all_filtered_nodes[chosen_index].node_ref.clone())
    }

    pub fn make_closest_node_id_sort(
        hash_coordinate: HashCoordinate,
    ) -> impl Fn(&NodeId, &NodeId) -> core::cmp::Ordering {
        move |a: &NodeId, b: &NodeId| -> core::cmp::Ordering {
            let da = a
                .ref_value()
                .to_bare_hash_coordinate()
                .distance(hash_coordinate.ref_value());
            let db = b
                .ref_value()
                .to_bare_hash_coordinate()
                .distance(hash_coordinate.ref_value());
            da.cmp(&db)
        }
    }
}
