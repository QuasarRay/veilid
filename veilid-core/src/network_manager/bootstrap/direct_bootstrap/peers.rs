use super::*;

impl_veilid_log_facility!("net");

impl NetworkManager {
    /// Up to `max_per_type` directly reachable nodes per protocol and address family for one
    /// crypto kind, the reliable and longest-known ones first
    fn find_bootstrap_nodes_filtered_per_crypto_kind(
        &self,
        crypto_kind: CryptoKind,
        max_per_type: usize,
    ) -> Vec<NodeRef> {
        let protocol_types: &[ProtocolType] = &[
            ProtocolType::UDP,
            ProtocolType::TCP,
            ProtocolType::WS,
            #[cfg(feature = "enable-protocol-wss")]
            ProtocolType::WSS,
            #[cfg(feature = "enable-protocol-webtransport")]
            ProtocolType::WTS,
            #[cfg(feature = "enable-protocol-webtransport")]
            ProtocolType::WTD,
        ];
        let node_count = protocol_types.len() * 2 * max_per_type;
        let mut counts = BTreeMap::<(ProtocolType, AddressType), usize>::new();

        let filter = Box::new(
            move |opt_snap: &Option<BucketEntrySnapshot>, cur_ts: Timestamp| {
                // None is this node, which the B02T reply adds on its own
                let Some(snap) = opt_snap.as_ref() else {
                    return false;
                };

                // skip nodes on our local network here
                if snap
                    .routing_domain_set()
                    .contains(RoutingDomain::LocalNetwork)
                {
                    return false;
                }

                // Ensure crypto kind is supported
                if !snap.node_ids.kinds().contains(&crypto_kind) {
                    return false;
                }

                // Only nodes with direct publicinternet node info
                let Some(pi) = snap.get_peer_info(RoutingDomain::PublicInternet) else {
                    return false;
                };
                let node_info = pi.node_info();

                if node_info.is_expired(cur_ts) {
                    return false;
                }

                // Bootstraps must have -only- inbound capable network class and direct dialinfo
                if !node_info.is_fully_direct_inbound() {
                    return false;
                }

                // Must have connectivity capabilities
                if !node_info.has_all_capabilities(CONNECTIVITY_CAPABILITIES) {
                    return false;
                }

                // Keep a node while it adds coverage of some protocol and address family
                let mut keep = false;
                for did in node_info.dial_info_detail_list() {
                    let key = (did.dial_info.protocol_type(), did.dial_info.address_type());
                    if !protocol_types.contains(&key.0) {
                        continue;
                    }
                    let count = counts.entry(key).or_default();
                    if *count < max_per_type {
                        *count += 1;
                        keep = true;
                    }
                }
                keep
            },
        ) as RoutingTableEntryFilter;
        let filters = VecDeque::from([filter]);

        // Reliable nodes first, then the ones this node has known longest
        let sort = Box::new(
            |a_entry: &Option<BucketEntrySnapshot>,
             b_entry: &Option<BucketEntrySnapshot>,
             _cur_ts: Timestamp| {
                let (Some(a), Some(b)) = (a_entry.as_ref(), b_entry.as_ref()) else {
                    return a_entry.is_some().cmp(&b_entry.is_some()).reverse();
                };
                b.is_reliable()
                    .cmp(&a.is_reliable())
                    .then_with(|| a.time_added.cmp(&b.time_added))
                    .then_with(|| a.node_ids.cmp(&b.node_ids))
            },
        ) as RoutingTableEntrySort;

        let pre_sort_filter =
            Box::new(|_all_entries: &mut Vec<Option<BucketEntrySnapshot>>, _cur_ts: Timestamp| {})
                as RoutingTableEntryPreSortFilter;

        let cur_ts = Timestamp::now();
        self.routing_table()
            .snapshot_entries(cur_ts, BucketEntryState::Initial)
            .get_peers_with_sort_and_filter(
                node_count,
                cur_ts,
                filters,
                pre_sort_filter,
                sort,
                |opt_snap: Option<BucketEntrySnapshot>| opt_snap.unwrap_or_log().node_ref.clone(),
            )
    }

    /// Up to `max_per_type` directly reachable nodes per protocol and address family across
    /// every crypto kind, without duplicates
    pub(in crate::network_manager) fn find_bootstrap_nodes_filtered(
        &self,
        max_per_type: usize,
    ) -> Vec<NodeRef> {
        let mut out =
            self.find_bootstrap_nodes_filtered_per_crypto_kind(VALID_CRYPTO_KINDS[0], max_per_type);

        // Merge list of nodes so we don't have duplicates
        for crypto_kind in &VALID_CRYPTO_KINDS[1..] {
            let nrs =
                self.find_bootstrap_nodes_filtered_per_crypto_kind(*crypto_kind, max_per_type);
            'nrloop: for nr in nrs {
                for nro in &out {
                    if nro.same_entry(&nr) {
                        continue 'nrloop;
                    }
                }
                out.push(nr);
            }
        }
        out
    }
}
