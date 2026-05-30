use super::*;

impl_veilid_log_facility!("rtab");

/// Context for calculating contact method
pub struct ContactMethodContext<'a> {
    pub peer_a: Arc<PeerInfo>,
    pub peer_a_published: bool,
    pub peer_b: Arc<PeerInfo>,
    pub node_a: &'a NodeInfo,
    pub node_b: &'a NodeInfo,
    pub dial_info_filter: DialInfoFilter,
    pub sequencing: Sequencing,
    pub context_sort: Option<&'a DialInfoDetailSort<'a>>,
    pub best_ck: CryptoKind,
    pub same_ipblock: bool,
    //node_a_id: NodeId,
    pub node_b_id: NodeId,
}
impl fmt::Debug for ContactMethodContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactMethodContext")
            .field("peer_a", &self.peer_a)
            .field("peer_a_published", &self.peer_a_published)
            .field("peer_b", &self.peer_b)
            .field("node_a", &self.node_a)
            .field("node_b", &self.node_b)
            .field("dial_info_filter", &self.dial_info_filter)
            .field("sequencing", &self.sequencing)
            //.field("context_sort", &self.context_sort)
            .field("best_ck", &self.best_ck)
            .field("same_ipblock", &self.same_ipblock)
            .field("node_b_id", &self.node_b_id)
            .finish()
    }
}

impl PublicInternetRoutingDomainController {
    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "rtab", skip(self, context_sort), fields(__VEILID_LOG_KEY = self.log_key()), ret))]
    pub fn get_contact_method(
        &self,
        peer_a: Arc<PeerInfo>,
        peer_a_published: bool,
        peer_b: Arc<PeerInfo>,
        dial_info_filter: DialInfoFilter,
        sequencing: Sequencing,
        context_sort: Option<&DialInfoDetailSort>,
    ) -> ContactMethod {
        let ip6_prefix_size = self.config().network.max_connections_per_ip6_prefix_size as usize;

        // Get the nodeinfos for convenience
        let node_a = peer_a.node_info();
        let node_b = peer_b.node_info();

        // Check to see if these nodes are on the same network
        let same_ipblock = node_a.is_on_same_ipblock(node_b, ip6_prefix_size);

        // Get the node ids that would be used between these peers
        let cck = common_crypto_kinds(&peer_a.node_ids().kinds(), &peer_b.node_ids().kinds());
        let Some(best_ck) = cck.first().copied() else {
            // No common crypto kinds between these nodes, can't contact
            return ContactMethod::Unreachable;
        };

        //let node_a_id = peer_a.node_ids().get(best_ck).unwrap_or_log();
        let node_b_id = peer_b.node_ids().get(best_ck).unwrap_or_log();

        let ctx = ContactMethodContext {
            peer_a: peer_a.clone(),
            peer_a_published,
            peer_b: peer_b.clone(),
            node_a,
            node_b,
            dial_info_filter,
            sequencing,
            context_sort,
            best_ck,
            same_ipblock,
            //node_a_id,
            node_b_id,
        };

        // Get the best match dial info for node B if we have it
        // To avoid hairpin NAT, if both nodes are on the same IP block
        // We should try to contact node B's relay(s) first before trying a direct address
        let mut tried_inbound_relaying = false;
        if same_ipblock {
            for node_b_relay in ctx.peer_b.node_info().relay_info_list() {
                if let Some(out) = self.get_indirect_contact_method(&ctx, node_b_relay) {
                    return out;
                }
            }
            tried_inbound_relaying = true;
        }

        // Now let's try to reach the node directly
        if let Some(target_did) = self.best_dial_info_detail_between_nodes(
            node_a,
            node_b,
            dial_info_filter,
            sequencing,
            context_sort,
        ) {
            if let Some(out) = self.get_direct_contact_method(&ctx, &target_did) {
                return out;
            }
        }

        if !tried_inbound_relaying {
            // If the node B can not be reached directly and we didn't try inbound relaying first, give it a shot
            for node_b_relay in ctx.peer_b.node_info().relay_info_list() {
                if let Some(out) = self.get_indirect_contact_method(&ctx, node_b_relay) {
                    return out;
                }
            }
        }

        // If node A can't reach the node by other means, it may need to use its outbound relay
        for node_a_relay in ctx.peer_a.node_info().relay_info_list() {
            if !matches!(node_a_relay.relay_kind(), RelayKind::Outbound) {
                continue;
            }
            if let Some(node_a_relay_id) = node_a_relay.node_ids().get(best_ck) {
                // Ensure it's not our relay we're trying to reach
                if node_a_relay_id != ctx.node_b_id {
                    return ContactMethod::OutboundRelay(node_a_relay_id);
                }
            }
        }

        ContactMethod::Unreachable
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "rtab", skip(self), fields(__VEILID_LOG_KEY = self.log_key()), ret))]
    pub fn get_direct_contact_method(
        &self,
        ctx: &ContactMethodContext,
        target_did: &DialInfoDetail,
    ) -> Option<ContactMethod> {
        // Never direct-dial one of our own addresses (would loop back); fall through to the relay
        if ctx
            .node_a
            .dial_info_detail_list()
            .iter()
            .any(|did| did.dial_info.socket_address() == target_did.dial_info.socket_address())
        {
            return None;
        }

        // Do we need to signal before going inbound?
        if !target_did.class.requires_signal() {
            // Go direct without signaling
            return Some(ContactMethod::Direct(target_did.dial_info.clone()));
        }

        // Get the target's inbound relay, it must have one or it is not reachable
        for node_b_relay in ctx.peer_b.node_info().relay_info_list() {
            // Note that relay_peer_info could be node_a, in which case a connection already exists
            // and we only get here if the connection had dropped, in which case node_a is unreachable until
            // it gets a new relay connection up
            if node_b_relay
                .node_ids()
                .contains_any_from_iter(ctx.peer_a.node_ids().iter())
            {
                return Some(ContactMethod::Existing);
            }

            // Get best node id to contact relay with
            if !node_b_relay.node_ids().contains_kind(ctx.best_ck) {
                // No best relay id
                return Some(ContactMethod::Unreachable);
            };

            // Can node A reach the inbound relay directly?
            if let Some(node_b_relay_did) = self.best_dial_info_detail_between_nodes(
                ctx.node_a,
                node_b_relay,
                ctx.dial_info_filter,
                ctx.sequencing,
                ctx.context_sort,
            ) {
                // Can node A receive anything inbound ever?
                // Requires both inbound dial info and the peer info to be published
                if ctx.node_a.has_dial_info() && ctx.peer_a_published {
                    ///////// Reverse connection

                    // Get the best match dial info for an reverse inbound connection from node B to node A
                    if let Some(reverse_did) = self.best_dial_info_detail_between_nodes(
                        ctx.node_b,
                        ctx.node_a,
                        ctx.dial_info_filter,
                        ctx.sequencing,
                        ctx.context_sort,
                    ) {
                        // Ensure we aren't on the same public IP address (no hairpin nat)
                        if reverse_did.dial_info.ip_addr() != target_did.dial_info.ip_addr() {
                            // Can we receive a direct reverse connection?
                            if !reverse_did.class.requires_signal() {
                                return Some(ContactMethod::SignalReverse(
                                    node_b_relay_did.dial_info,
                                ));
                            }
                        }
                    }

                    ///////// UDP hole-punch

                    // Does node B have a direct dialinfo node A can reach with a low level protocol type of UDP?
                    let udp_low_level_dial_info_filter = ctx.dial_info_filter.filtered(
                        DialInfoFilter::all()
                            .with_protocol_type_set(ProtocolType::low_level_udp_set()),
                    );

                    let target_udp_dids = self.best_dial_info_details_between_nodes(
                        ctx.node_a,
                        ctx.node_b,
                        udp_low_level_dial_info_filter,
                        ctx.sequencing,
                        ctx.context_sort,
                    );
                    let target_udp_proto_addr_types = target_udp_dids
                        .iter()
                        .map(|did| (did.dial_info.protocol_type(), did.dial_info.address_type()))
                        .collect::<HashSet<_>>();

                    // Does node A have a direct udp dialinfo that node B can reach?
                    let reverse_udp_dids = self.best_dial_info_details_between_nodes(
                        ctx.node_b,
                        ctx.node_a,
                        udp_low_level_dial_info_filter,
                        ctx.sequencing,
                        ctx.context_sort,
                    );
                    let reverse_udp_proto_addr_types = reverse_udp_dids
                        .iter()
                        .map(|did| (did.dial_info.protocol_type(), did.dial_info.address_type()))
                        .collect::<HashSet<_>>();

                    // Get the best forward and reverse dial info that have the same protocol type and address type
                    let intersected_udp_proto_addr_types = target_udp_proto_addr_types
                        .intersection(&reverse_udp_proto_addr_types)
                        .copied()
                        .collect::<HashSet<_>>();

                    if !intersected_udp_proto_addr_types.is_empty() {
                        let target_udp_di = target_udp_dids
                            .into_iter()
                            .find(|did| {
                                intersected_udp_proto_addr_types.contains(&(
                                    did.dial_info.protocol_type(),
                                    did.dial_info.address_type(),
                                ))
                            })
                            .unwrap_or_log()
                            .dial_info;
                        let reverse_udp_di = reverse_udp_dids
                            .into_iter()
                            .find(|did| {
                                intersected_udp_proto_addr_types.contains(&(
                                    did.dial_info.protocol_type(),
                                    did.dial_info.address_type(),
                                ))
                            })
                            .unwrap_or_log()
                            .dial_info;

                        // Ensure we aren't on the same public IP address (no hairpin nat)
                        // And that the reverse dialinfo has the same protocol type as the target dialinfo
                        if reverse_udp_di.ip_addr() != target_udp_di.ip_addr() {
                            // The target and ourselves have a udp dialinfo that they can reach
                            return Some(ContactMethod::SignalHolePunch(
                                node_b_relay_did.dial_info,
                                target_udp_di,
                                reverse_udp_di,
                            ));
                        }
                    }

                    // Otherwise we have to inbound relay
                }

                return Some(ContactMethod::InboundRelay(node_b_relay_did.dial_info));
            }
        }
        None
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "rtab", skip(self), fields(__VEILID_LOG_KEY = self.log_key()), ret))]
    pub fn get_indirect_contact_method(
        &self,
        ctx: &ContactMethodContext,
        node_b_relay: &RelayInfo,
    ) -> Option<ContactMethod> {
        // Note that node_b_relay could be node_a, in which case a connection already exists
        // and we only get here if the connection had dropped, in which case node_b is unreachable until
        // it gets a new relay connection up
        if node_b_relay
            .node_ids()
            .contains_any_from_iter(ctx.peer_a.node_ids().iter())
        {
            return Some(ContactMethod::Existing);
        }

        // Get best node id to contact relay with
        if !node_b_relay.node_ids().contains_kind(ctx.best_ck) {
            // No best relay id
            return Some(ContactMethod::Unreachable);
        };

        // Can we reach the inbound relay?
        if let Some(node_b_relay_did) = self.best_dial_info_detail_between_nodes(
            ctx.node_a,
            node_b_relay,
            ctx.dial_info_filter,
            ctx.sequencing,
            ctx.context_sort,
        ) {
            // Reverse connection (requires published peer info because signal rpc uses it)
            if ctx.peer_a_published {
                // Get the best match dial info for an reverse inbound connection from node B to node A
                // unless both nodes are on the same ipblock
                if let Some(reverse_did) = (!ctx.same_ipblock)
                    .then(|| {
                        self.best_dial_info_detail_between_nodes(
                            ctx.node_b,
                            ctx.node_a,
                            ctx.dial_info_filter,
                            ctx.sequencing,
                            ctx.context_sort,
                        )
                    })
                    .flatten()
                {
                    // Can we receive a direct reverse connection?
                    if !reverse_did.class.requires_signal() {
                        return Some(ContactMethod::SignalReverse(node_b_relay_did.dial_info));
                    }
                }
            }

            return Some(ContactMethod::InboundRelay(node_b_relay_did.dial_info));
        }

        None
    }
}
