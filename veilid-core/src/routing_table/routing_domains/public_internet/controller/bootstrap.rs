use super::*;

impl_veilid_log_facility!("rtab");

/// The network state under which this node judged itself its only bootstrap
#[derive(Clone, Copy, Debug)]
pub(super) struct BootstrapStandoff {
    /// Our published peer info and online state when the round started
    epoch: LossEpoch,
}

impl BootstrapStandoff {
    fn holds(&self, epoch: &LossEpoch) -> bool {
        self.epoch.same_network(epoch)
    }
}

/// The dial infos one bootstrap entry expands to, grouped by protocol in the order to try them
pub(in crate::routing_table) struct BootstrapTarget {
    /// What the config said
    pub entry: String,
    /// One group per protocol, in `bootstrap_protocols` order; a url is one group
    pub groups: Vec<Vec<DialInfo>>,
}

/// Whether a round that finished through `via` is worth announcing: a node short of peers
/// bootstraps every tick, and the same peers again are no news. Records `via` as announced
pub(in crate::routing_table) fn bootstrap_peers_are_news(
    announced: &mut Option<String>,
    via: &str,
) -> bool {
    if announced.as_deref() == Some(via) {
        return false;
    }
    *announced = Some(via.to_owned());
    true
}

impl PublicInternetRoutingDomainController {
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub async fn bootstrap_task_routine(
        &self,
        stop_token: StopToken,
        _last_ts: Timestamp,
        _cur_ts: Timestamp,
    ) -> EyreResult<()> {
        // A round runs to fill the table, or to re-check the payload this node serves
        let nodes_needed = self.nodes_needed();
        let recheck = self.take_bootstrap_recheck();
        if nodes_needed.needs_bootstrap.is_empty() && !recheck {
            return Ok(());
        }
        let refresh_only = nodes_needed.needs_bootstrap.is_empty();
        let crypto_kinds = nodes_needed.needs_bootstrap;

        // Nothing to ask, or standing off as this node's only bootstrap
        let routing_table = self.routing_table();
        let network_manager = self.network_manager();
        let bootstraps = self.config().network.routing_table.bootstrap.clone();
        let config_nodes = network_manager.config_bootstrap();
        let epoch = routing_table.loss_epoch(None);
        let standing_off = self
            .bootstrap_standoff
            .lock()
            .is_some_and(|standoff| standoff.holds(&epoch));
        if standing_off || (bootstraps.is_empty() && config_nodes.is_empty()) {
            // A re-check with no one to ask still uses up its cache period
            if recheck {
                self.record_bootstrap_cache(BootstrapCache::default(), true);
            }
            return Ok(());
        }

        if !refresh_only {
            // Reset the low water mark for this routing domain
            routing_table.refresh_summaries(RoutingDomain::PublicInternet.into());
        }

        let mut targets = Vec::<BootstrapTarget>::new();
        for entry in bootstraps {
            // A hostname resolves on the blocking pool, which a stop cannot interrupt
            let Ok(target) = self
                .bootstrap_target(entry)
                .timeout_at(stop_token.clone())
                .await
            else {
                return Ok(());
            };
            if let Some(target) = target {
                targets.push(target);
            }
        }
        // The configured payload's nodes are asked directly, on their own dial infos
        for bsn in &config_nodes {
            targets.push(BootstrapTarget {
                entry: format!("payload node {}", bsn.node_ids()),
                groups: self.protocol_groups(bsn.dial_infos()),
            });
        }

        let mut unord = FuturesUnordered::<PinBoxFuture<EyreResult<BootstrapPeers>>>::new();
        for target in targets {
            unord.push(pin_dyn_future!(async {
                let target = target;
                veilid_log!(self debug "Bootstrap with: {}", target.entry);
                self.direct_bootstrap_ordered(target.groups).await
            }));
        }

        let mut found = BootstrapPeers::default();
        loop {
            match unord.next().timeout_at(stop_token.clone()).await {
                Ok(Some(res)) => match res {
                    Ok(peers) => found.extend(peers),
                    Err(e) => {
                        veilid_log!(self debug "Bootstrap error: {}", e);
                    }
                },
                Ok(None) => break,
                Err(_) => return Ok(()),
            }
        }

        // Nodes a payload named but no reply carried are asked directly, once
        let mut unord = FuturesUnordered::<PinBoxFuture<EyreResult<BootstrapPeers>>>::new();
        for bsn in core::mem::take(&mut found.unanswered) {
            if found
                .peers
                .iter()
                .any(|pi| bsn.node_ids().contains_any_from_iter(pi.node_ids().iter()))
            {
                continue;
            }
            let groups = self.protocol_groups(bsn.dial_infos());
            let node_ids = bsn.node_ids().clone();
            unord.push(pin_dyn_future!(async {
                let (groups, node_ids) = (groups, node_ids);
                veilid_log!(self debug "Bootstrap with payload node: {}", node_ids);
                self.direct_bootstrap_ordered(groups).await
            }));
        }
        loop {
            match unord.next().timeout_at(stop_token.clone()).await {
                Ok(Some(res)) => match res {
                    Ok(mut peers) => {
                        peers.unanswered.clear();
                        found.extend(peers);
                    }
                    Err(e) => {
                        veilid_log!(self debug "Bootstrap error: {}", e);
                    }
                },
                Ok(None) => break,
                Err(_) => return Ok(()),
            }
        }

        // Dedup the peers and notice our own node among them
        let mut bootstrapped_peer_id_set = HashSet::<NodeId>::new();
        let mut bootstrapped_peers = vec![];
        let mut own_node_seen = false;
        for peer in found.peers {
            if peer.routing_domain() != RoutingDomain::PublicInternet {
                continue;
            }
            let peer_node_ids = peer.node_ids();
            if peer_node_ids
                .iter()
                .any(|x| bootstrapped_peer_id_set.contains(x))
            {
                continue;
            }
            if routing_table.matches_own_node_id(peer_node_ids) {
                veilid_log!(self debug "Ignoring own node in bootstrap list");
                own_node_seen = true;
            } else {
                bootstrapped_peer_id_set.extend(peer_node_ids.iter().cloned());
                bootstrapped_peers.push(peer);
            }
        }

        // A learned payload replaces what is served; an empty round still starts a cache period
        let now = Timestamp::now();
        let bootstrap_cache = found
            .payload
            .as_ref()
            .map(|payload| BootstrapCache::from_payload(payload, Some(now)))
            .unwrap_or_default();
        let resolved_anything = found.payload.is_some() || own_node_seen;

        // A round that resolved anything decides whether this node is one of its own bootstraps
        if resolved_anything || !bootstrapped_peers.is_empty() {
            let was_own_bootstrap = self.read().swap_own_bootstrap(own_node_seen);
            if own_node_seen != was_own_bootstrap {
                if own_node_seen {
                    veilid_log!(self info "This node is one of its own bootstraps and answers direct bootstrap requests");
                }
                // The verdict is part of the advertised capabilities
                self.publish_peer_info();
            }
        }

        if refresh_only {
            self.record_bootstrap_cache(bootstrap_cache, recheck);
            return Ok(());
        }

        self.read_dyn().clear_bootstrap_peers();

        // Only this node among the bootstraps: nothing to bootstrap from until other nodes connect
        if own_node_seen && bootstrapped_peers.is_empty() {
            self.record_bootstrap_cache(bootstrap_cache, recheck);
            let standoff = BootstrapStandoff { epoch };
            if self.bootstrap_standoff.lock().replace(standoff).is_none() {
                veilid_log!(self info "This node is its only bootstrap, waiting for other nodes to connect");
            }
            return Ok(());
        }
        *self.bootstrap_standoff.lock() = None;

        if self
            .unlocked_inner
            .bootstrap_wait_detector
            .fetch_update(|opt_ts| {
                if opt_ts.is_none() {
                    Some(Some(Timestamp::now()))
                } else {
                    None
                }
            })
            .is_ok()
        {
            // A node short of peers bootstraps every tick, and only its first wait is news
            if self.bootstrap_announced_via.lock().is_none() {
                veilid_log!(self info "Waiting for bootstrap...");
            } else {
                veilid_log!(self debug "Waiting for bootstrap...");
            }
        }
        let valid_bootstraps = self
            .bootstrap_with_peer_list(bootstrapped_peers.clone(), crypto_kinds.clone(), stop_token)
            .await?;

        self.record_bootstrap_cache(bootstrap_cache, recheck);

        if valid_bootstraps.is_empty() {
            veilid_log!(self debug "No external bootstrap peers");

            // Leave bootstrap wait detector set so we don't spam logs
            return Ok(());
        }
        veilid_log!(self debug "External bootstrap peers: {:#?}", valid_bootstraps);

        // Get all node ids that have a peerinfo in this routing domain
        let mut rd_peer_ids = BTreeSet::new();
        for peer in bootstrapped_peers.iter() {
            if peer.routing_domain() == RoutingDomain::PublicInternet {
                for nid in peer.node_ids().iter().cloned() {
                    rd_peer_ids.insert(nid);
                }
            }
        }

        // Add valid bootstrap peers to routing domain
        for bootstrap_peer in valid_bootstraps.iter().cloned() {
            let mut add = false;
            if let Some(pi) = bootstrap_peer.get_peer_info(RoutingDomain::PublicInternet) {
                for nid in pi.node_ids().iter() {
                    if rd_peer_ids.contains(nid) {
                        add = true;
                        break;
                    }
                }
            }
            if add {
                self.read_dyn().add_bootstrap_peer(bootstrap_peer);
            }
        }
        let routing_table = self.routing_table();
        routing_table.flush(SaveReason::Bootstrap).await;

        // Reset the low water mark for this routing domain
        routing_table.refresh_summaries(RoutingDomain::PublicInternet.into());

        if let Some(old_ts) = self.unlocked_inner.bootstrap_wait_detector.swap(None) {
            let end_ts = Timestamp::now();
            let duration = end_ts.duration_since(old_ts);
            let signed = if self
                .config()
                .network
                .routing_table
                .bootstrap_keys
                .is_empty()
            {
                "unsigned"
            } else {
                "signed"
            };
            let mut via = valid_bootstraps
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>();
            via.sort();
            let via = via.join(",");
            if bootstrap_peers_are_news(&mut self.bootstrap_announced_via.lock(), &via) {
                veilid_log!(self info "Bootstrap finished ({}) in {:#} via {}", signed, duration, via);
            } else {
                veilid_log!(self debug "Bootstrap finished ({}) in {:#} via {}", signed, duration, via);
            }
        }

        Ok(())
    }

    /// Ask one bootstrap over its dial infos, a protocol group at a time: every address of a
    /// group at once, the next group only when none of them answered the way this node speaks
    async fn direct_bootstrap_ordered(
        &self,
        groups: Vec<Vec<DialInfo>>,
    ) -> EyreResult<BootstrapPeers> {
        for group in groups {
            let mut unord = FuturesUnordered::new();
            for dial_info in group {
                let registry = self.registry();
                unord.push(async move {
                    let network_manager = registry.network_manager();
                    let res =
                        pin_future!(network_manager.direct_bootstrap(dial_info.clone())).await;
                    (dial_info, res)
                });
            }
            let mut out = BootstrapPeers::default();
            let mut answered = false;
            while let Some((dial_info, res)) = unord.next().await {
                match res {
                    Ok(peers) => {
                        if peers.payload.is_some() || !peers.peers.is_empty() {
                            answered = true;
                        }
                        out.extend(peers);
                    }
                    Err(e) => {
                        veilid_log!(self debug "Direct bootstrap {} failed: {}", dial_info, e);
                    }
                }
            }
            if answered {
                return Ok(out);
            }
        }
        Ok(BootstrapPeers::default())
    }

    /// What a config entry expands to: a url as itself, a bare `host` or `host:port` as one dial
    /// info per configured protocol on every address it resolves to. A url over a protocol this
    /// node does not dial expands to nothing
    pub(in crate::routing_table) async fn bootstrap_target(
        &self,
        entry: String,
    ) -> Option<BootstrapTarget> {
        let dial_info_converter = BootstrapDialInfoConverter::default();
        if let Ok(mut dial_infos) = dial_info_converter.try_vec_from_url(&entry).await {
            let outbound_protocols = self.read_dyn().outbound_protocols();
            dial_infos.retain(|dial_info| outbound_protocols.contains(dial_info.protocol_type()));
            if dial_infos.is_empty() {
                veilid_log!(self debug "Bootstrap entry is over a protocol this node does not dial: {}", entry);
                return None;
            }
            return Some(BootstrapTarget {
                groups: vec![dial_infos],
                entry,
            });
        }
        let Some((host, port)) = split_bootstrap_entry(&entry) else {
            veilid_log!(self warn "Invalid bootstrap entry: {}", entry);
            return None;
        };
        let mut groups = Vec::new();
        for url in self.bootstrap_urls(&host, port) {
            match dial_info_converter.try_vec_from_url(&url).await {
                Ok(dial_infos) if !dial_infos.is_empty() => groups.push(dial_infos),
                Ok(_) => {}
                Err(e) => {
                    veilid_log!(self debug "Could not resolve bootstrap {}: {}", url, e);
                }
            }
        }
        if groups.is_empty() {
            veilid_log!(self debug "Bootstrap entry resolved to nothing: {}", entry);
            return None;
        }
        Some(BootstrapTarget { entry, groups })
    }

    /// The protocols this node bootstraps over, in order
    fn bootstrap_protocols(&self) -> Vec<ProtocolType> {
        self.config()
            .dialable_bootstrap_protocols()
            .into_iter()
            .filter_map(|bootstrap_protocol| bootstrap_protocol.protocol_type())
            .collect()
    }

    /// One url per bootstrap protocol for a bare name, with this node's own paths as the
    /// network's convention
    fn bootstrap_urls(&self, host: &str, port: u16) -> Vec<String> {
        let config = self.config();
        let protocol = &config.network.protocol;
        self.bootstrap_protocols()
            .into_iter()
            .map(|pt| match pt {
                ProtocolType::UDP => format!("udp://{}:{}", host, port),
                ProtocolType::TCP => format!("tcp://{}:{}", host, port),
                ProtocolType::WS => format!(
                    "ws://{}:{}/{}",
                    host,
                    port,
                    protocol.ws.path.trim_matches('/')
                ),
                #[cfg(feature = "enable-protocol-wss")]
                ProtocolType::WSS => format!(
                    "wss://{}:{}/{}",
                    host,
                    port,
                    protocol.wss.path.trim_matches('/')
                ),
                #[cfg(feature = "enable-protocol-webtransport")]
                ProtocolType::WTS | ProtocolType::WTD => format!(
                    "wts://{}:{}/{}",
                    host,
                    port,
                    protocol.webtransport.path.trim_matches('/')
                ),
            })
            .collect()
    }

    /// A payload node's dial infos grouped by the configured protocol order
    fn protocol_groups(&self, dial_infos: &[DialInfo]) -> Vec<Vec<DialInfo>> {
        self.bootstrap_protocols()
            .into_iter()
            .map(|pt| {
                dial_infos
                    .iter()
                    .filter(|di| di.protocol_type() == pt)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|group| !group.is_empty())
            .collect()
    }

    /// Whether a requested re-check has come due
    pub(crate) fn bootstrap_recheck_pending(&self) -> bool {
        self.bootstrap_recheck_at
            .lock()
            .is_some_and(|at| Timestamp::now() >= at)
    }

    /// Take a due re-check, so the round that runs it is the only one. A request made while
    /// the last round ran finds nothing left due
    fn take_bootstrap_recheck(&self) -> bool {
        let mut recheck_at = self.bootstrap_recheck_at.lock();
        let cur_ts = Timestamp::now();
        if !recheck_at.is_some_and(|at| cur_ts >= at) {
            return false;
        }
        *recheck_at = None;
        self.read_dyn()
            .get_served_bootstrap_cache()
            .recheck_due(cur_ts)
    }

    /// Record what this bootstrap produced, so a restart can serve it without a lookup. A
    /// re-check round starts a new cache period whether or not it learned anything newer
    fn record_bootstrap_cache(&self, bootstrap_cache: BootstrapCache, rechecked: bool) {
        veilid_log!(self debug "Bootstrap payload: {:?}", bootstrap_cache.payload_timestamp());
        self.read_dyn()
            .record_bootstrap_cache(bootstrap_cache, rechecked.then(Timestamp::now));
    }

    pub fn bootstrap_with_peer(
        &self,
        crypto_kinds: Vec<CryptoKind>,
        peer_info: Arc<PeerInfo>,
        existing_node_ids: Arc<HashSet<NodeId>>,
        unord: &FuturesUnordered<PinBoxFutureStatic<Option<NodeRef>>>,
    ) {
        veilid_log!(self trace
            "--- bootstrapping {} with {:?}",
            peer_info.node_ids(),
            peer_info.node_info().dial_info_detail_list()
        );

        let routing_domain = peer_info.routing_domain();
        let routing_table = self.routing_table();

        let nr = match routing_table.register_node_with_peer_info(
            Arc::new(UnverifiedPeerInfo::from_verified(&peer_info)),
            true,
        ) {
            Ok(nr) => nr,
            Err(e) => {
                veilid_log!(self error "failed to register bootstrap peer info: {}", e);
                return;
            }
        };

        // Add this our futures to process in parallel
        for crypto_kind in crypto_kinds {
            // Bootstrap this crypto kind
            let nr = nr.unfiltered();
            let existing_node_ids = existing_node_ids.clone();
            unord.push(Box::pin(
                async move {
                    let network_manager = nr.network_manager();
                    let routing_table = nr.routing_table();

                    // Get what contact method would be used for contacting the bootstrap
                    let bsdi = match network_manager.get_node_contact_method(
                        nr.sequencing_filtered(Sequencing::PreferOrdered),
                        ContactMethodIntent::Advisory,
                    ) {
                        Ok(NodeContactMethodResult::Resolved(ncm)) => {
                            let Some(di) = ncm.direct_dial_info() else {
                                veilid_log!(nr debug "invalid contact method for bootstrap, ignoring peer: {}", NodeContactMethodResult::Resolved(ncm));
                                return None;
                            };
                            di
                        }
                        Ok(v) => {
                            veilid_log!(nr debug "invalid contact method for bootstrap, ignoring peer: {}", v);
                            return None;
                        }
                        Err(e) => {
                            veilid_log!(nr warn "unable to bootstrap: {}", e);
                            return None;
                        }
                    };

                    // Need VALID signed peer info, so ask bootstrap to find_node of itself
                    // which will ensure it has the bootstrap's signed peer info as part of the response
                    let _ = Box::pin(routing_table.find_nodes_close_to_node_ref(crypto_kind, nr.sequencing_filtered(Sequencing::PreferOrdered), vec![])).await;

                    // Ensure we got the signed peer info
                    if !nr.peer_info_has_valid_signature(routing_domain) {
                        veilid_log!(nr debug "bootstrap server is not responding for dialinfo: {}", bsdi);
                        None
                    } else {
                        // otherwise this bootstrap is valid, lets ask it to find ourselves now
                        // We should prefer nodes that have relaying, signaling, routing and validation of dial info
                        // for our initial nodes in our routing table because we need these things in order to
                        // properly attach to the network

                        // Find nodes close to ourself
                        let close_node_refs = network_result_value_or_log!(nr match pin_future!(
                                routing_table.find_new_nodes_close_to_self(
                                    crypto_kind,
                                    &existing_node_ids,
                                    nr.routing_domain_filtered(RoutingDomain::PublicInternet).with_sequencing(Sequencing::PreferOrdered),
                                    CONNECTIVITY_CAPABILITIES.to_vec())
                                ).await {
                            Err(e) => {
                                veilid_log!(nr debug "failed to find nodes close to self: {}", e);
                                NetworkResult::value(vec![])
                            }
                            Ok(v) => v,
                        } => {
                            vec![]
                        });
                        veilid_log!(nr debug target:"network_result", "bootstrap: found {} nodes close to self for {} in {} with {:?}", close_node_refs.len(), crypto_kind, RoutingDomain::PublicInternet, CONNECTIVITY_CAPABILITIES);

                        // Now find nodes widely across the network
                        let wide_node_refs = match pin_future!(routing_table.find_new_nodes_wide(
                                crypto_kind,
                                &existing_node_ids,
                                RoutingDomain::PublicInternet,
                                None,
                                CONNECTIVITY_CAPABILITIES.to_vec())
                            ).await {
                            Err(e) => {
                                veilid_log!(nr debug "failed to find nodes wide: {}", e);
                                vec![]
                            }
                            Ok(v) => v,
                        };

                        veilid_log!(nr debug target:"network_result", "bootstrap: found {} nodes wide for {} in {} with {:?}", wide_node_refs.len(), crypto_kind, RoutingDomain::PublicInternet, CONNECTIVITY_CAPABILITIES);

                        veilid_log!(nr debug "Bootstrap of {} successful via {} with {} close nodes and {} wide nodes", crypto_kind, nr, close_node_refs.len(), wide_node_refs.len());
                        Some(nr)
                    }
                }
                .instrument(Span::current()),
            ));
        }
    }

    /// Takes in a list of bootstrap peer info, and attempts bootstrapping
    /// A list of valid bootstrap peer noderefs is returned
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip(self), err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub async fn bootstrap_with_peer_list(
        &self,
        bootstrap_peers: Vec<Arc<PeerInfo>>,
        crypto_kinds: Vec<CryptoKind>,
        stop_token: StopToken,
    ) -> EyreResult<Vec<NodeRef>> {
        if bootstrap_peers.is_empty() {
            veilid_log!(self debug "No peers suitable for bootstrap");
            return Ok(vec![]);
        }

        veilid_log!(self debug "Bootstrap peers: {:?}", &bootstrap_peers);

        // Snapshot once and extract existing node ids for dedup filtering
        let existing_node_ids = Arc::new(
            self.routing_table()
                .snapshot_entries(Timestamp::now(), BucketEntryState::Initial)
                .existing_node_ids(None),
        );

        // Run all bootstrap operations concurrently
        let mut unord = FuturesUnordered::<PinBoxFutureStatic<Option<NodeRef>>>::new();
        for peer in bootstrap_peers {
            let mut peer_crypto_kinds = vec![];
            for ck in crypto_kinds.iter().copied() {
                if peer.node_ids().get(ck).is_some() {
                    peer_crypto_kinds.push(ck);
                }
            }
            if peer_crypto_kinds.is_empty() {
                continue;
            }

            veilid_log!(self debug "Attempting bootstrap: {}", peer.node_ids());
            self.bootstrap_with_peer(peer_crypto_kinds, peer, existing_node_ids.clone(), &unord);
        }

        // Wait for all bootstrap operations to complete before we complete the singlefuture
        let mut valid_bootstraps = vec![];
        while let Ok(Some(res)) = unord.next().timeout_at(stop_token.clone()).await {
            if let Some(valid_bootstrap) = res {
                valid_bootstraps.push(valid_bootstrap);
            }
        }
        Ok(valid_bootstraps)
    }
}
