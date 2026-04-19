use super::*;

impl_veilid_log_facility!("rtab");

#[derive(Debug, Clone)]
pub struct RelayPing {
    pub node_ref: FilteredNodeRef,
}

impl PartialEq for RelayPing {
    fn eq(&self, other: &Self) -> bool {
        self.node_ref.equivalent(&other.node_ref)
    }
}

impl Eq for RelayPing {}

impl fmt::Display for RelayPing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", f.to_string(&self.node_ref))
    }
}

/// The current node's relaying capabilities and requirements
#[derive(Debug, Clone)]
pub struct RelayStatus {
    /// Routing domain this is for
    pub routing_domain: RoutingDomain,
    /// Low level port info for this node
    /// This is which ports are mapped externally that we may need keepalive pings for
    pub low_level_port_info: LowLevelPortInfo,
    /// This node's outbound dial info filter
    /// Used to determine if a relay's dialinfo is directly reachable
    pub dial_info_filter: DialInfoFilter,
    /// All protocol/address types requiring inbound relays for this node
    pub want_relay_protocols: HashSet<(ProtocolType, AddressType)>,
    /// Ordering modes we still need for relaying, per address type
    pub want_relay_orderings: HashSet<(SequenceOrdering, AddressType)>,
    /// All the low level protocols and ports that require nat keepalive pings
    pub wants_nat_keepalives: LowLevelProtocolPorts,
    /// All of the relays and their configuration currently included in our status
    pub relays: Vec<RoutingDomainRelay>,
}

impl fmt::Display for RelayStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Low Level Port Info:\n{}\nDial Info Filter: {}\nWant Relay Protocols: {}\nWant Relay Orderings: {}\nWants NAT Keepalives: {}\nRelays:\n{}",
            indent_all_string(f.to_string(&self.low_level_port_info)),
            f.to_string(self.dial_info_filter),
            self.want_relay_protocols.iter().map(|(pt,at)| format!("{}:{}", f.to_string(pt), f.to_string(at))).collect::<Vec<_>>().join(", ").string_if_empty("None"),
            self.want_relay_orderings.iter().map(|(om,at)| format!("{}:{}", f.to_string(om), f.to_string(at))).collect::<Vec<_>>().join(", ").string_if_empty("None"),
            self.wants_nat_keepalives.iter().map(|(lpt,at,p)| format!("{}:{}:{}", f.to_string(lpt), f.to_string(at), p)).collect::<Vec<_>>().join(", ").string_if_empty("None"),
            indent_all_string(f.to_multiline_indexed_string(self.relays.iter()).string_if_empty("None"))
        )
    }
}

impl RelayStatus {
    pub fn new_from_routing_domain_detail(rdd: &dyn RoutingDomainDetail) -> Self {
        // Make temporary nodeinfo without relay info or keys
        let node_info = NodeInfo::new(
            Timestamp::now_non_decreasing(),
            VALID_ENVELOPE_VERSIONS.to_vec(),
            vec![],
            rdd.capabilities().iter().copied().collect(),
            rdd.outbound_protocols(),
            rdd.address_types(),
            rdd.dial_info_details().clone(),
            vec![],
        );

        Self::new_from_node_info(
            rdd.routing_domain(),
            &node_info,
            rdd.translated_address_types(),
        )
    }

    fn new_from_node_info(
        routing_domain: RoutingDomain,
        node_info: &NodeInfo,
        translated_address_types: AddressTypeSet,
    ) -> Self {
        let low_level_port_info = node_info.get_low_level_port_info();
        let dial_info_filter = DialInfoFilter::all()
            .with_protocol_type_set(node_info.outbound_protocols())
            .with_address_type_set(node_info.address_types());

        // Get the dial info list in preferred deterministic order
        let mut dial_info_list = node_info.dial_info_detail_list().to_vec();
        dial_info_list.sort_by(DialInfoDetail::ordered_sequencing_sort);

        // Start with all possible combinations we might need to have relays for
        let mut want_relay_protocols = HashSet::<(ProtocolType, AddressType)>::new();
        let mut want_relay_orderings = HashSet::<(SequenceOrdering, AddressType)>::new();
        for at in AddressTypeSet::all() {
            for pt in ProtocolTypeSet::all() {
                want_relay_protocols.insert((pt, at));
                want_relay_orderings.insert((pt.sequence_ordering(), at));
            }
        }

        // Figure out which dial info combinations we have that are direct-capable
        let mut wants_nat_keepalives = LowLevelProtocolPorts::new();
        for did in dial_info_list {
            let pt = did.dial_info.protocol_type();
            let at = did.dial_info.address_type();

            if !did.class.requires_signal() && !translated_address_types.contains(at) {
                // If this address type is NAT'd, then we need a relay for its
                // protocols even if it is directly reachable
                want_relay_protocols.remove(&(pt, at));
                want_relay_orderings.remove(&(pt.sequence_ordering(), at));
            }

            if did.class.wants_nat_keepalive() {
                wants_nat_keepalives.insert((
                    pt.low_level_protocol_type(),
                    at,
                    did.dial_info.port(),
                ));
            }
        }

        RelayStatus {
            routing_domain,
            low_level_port_info,
            dial_info_filter,
            want_relay_protocols,
            want_relay_orderings,
            wants_nat_keepalives,
            relays: vec![],
        }
    }

    /// Check if we would like more relays
    /// Beyond the bare minimum ordering mode relays, having relays to handle
    /// each protocol+address type combination we can't accept directly are also wanted
    pub fn wants_more_relays(&self) -> bool {
        // If we want more keepalives for NAT, we want more relays
        if !self.wants_nat_keepalives.is_empty() {
            return true;
        }
        // If there are any protocol/address type combinations we need
        // relaying for still, we want more relays
        !self.want_relay_protocols.is_empty()
    }

    /// Check if we need more relays before publication
    /// This is a stricter check than wants_more_relays() because the bare minimum
    /// relays we need are a subset of the relays we want, one relay per ordering mode
    /// per address type is enough to publish.
    pub fn needs_more_relays(&self) -> bool {
        // If we want more keepalives for NAT, we need more relays
        if !self.wants_nat_keepalives.is_empty() {
            return true;
        }

        // If we have any address types that still have ordering modes they need
        // relays for, then we need more relays
        !self.want_relay_orderings.is_empty()
    }

    /// Get the routing domain relays list when we're done
    pub fn get_sorted_relays_list(&self) -> Vec<RoutingDomainRelay> {
        let mut relays = self.relays.clone();

        // Sort things in order of relay preference, using least-capable relays first
        relays.sort_by(|ardr, brdr| {
            // Get address types and protocol types to sort by
            let mut aats = AddressTypeSet::new();
            let mut apts = ProtocolTypeSet::new();
            for did in &ardr.dial_info_details {
                aats |= did.dial_info.address_type();
                apts |= did.dial_info.protocol_type();
            }

            let mut bats = AddressTypeSet::new();
            let mut bpts = ProtocolTypeSet::new();
            for did in &brdr.dial_info_details {
                bats |= did.dial_info.address_type();
                bpts |= did.dial_info.protocol_type();
            }

            // Compare by address type set first (fewer address types is less)
            let c = aats.len().cmp(&bats.len());
            if c != cmp::Ordering::Equal {
                return c;
            }
            for at in AddressTypeSet::all() {
                let a = aats.contains(at);
                let b = bats.contains(at);
                let c = a.cmp(&b);
                if c != cmp::Ordering::Equal {
                    return c;
                }
            }

            // Compare by protocol types set second (fewer protocol types is less)
            let c = apts.len().cmp(&bpts.len());
            if c != cmp::Ordering::Equal {
                return c;
            }
            for pt in ProtocolTypeSet::all() {
                let a = apts.contains(pt);
                let b = bpts.contains(pt);
                let c = a.cmp(&b);
                if c != cmp::Ordering::Equal {
                    return c;
                }
            }

            // Then just compare by node id lists, so things are stable
            let a_nodes = ardr.relay_node.node_ids().to_vec();
            let b_nodes = brdr.relay_node.node_ids().to_vec();

            a_nodes.cmp(&b_nodes)
        });
        relays
    }

    /// Remove a relay's capabilities from our current requirements and determine which
    /// pings should be performed.
    /// Returns true if the requirements changed, or false if applying the relay had no effect
    pub fn apply_relay(&mut self, mut relay: RoutingDomainRelay) -> bool {
        // Make sure this relay is the correct routing domain and has peer info
        let Some(relay_peer_info) = relay.relay_node.get_peer_info(self.routing_domain) else {
            return false;
        };

        // Clear out the dial info details and the pings because we'll add new ones
        relay.dial_info_details.clear();
        relay.pings.clear();

        // For all for the relay's dial info, see if it matches a protocol+address type we need covered
        let mut dial_info_list = relay_peer_info.node_info().dial_info_detail_list().to_vec();
        dial_info_list.sort_by(DialInfoDetail::ordered_sequencing_sort);

        // Determine for this relay, if there are dialinfo that are reachable with our node's
        // dialinfo filter, and which ordering modes can be satisfied by those flows

        let mut possible_ordering_modes = SequenceOrderingSet::new();
        for did in &dial_info_list {
            if did.class.requires_signal() {
                continue;
            }
            let didpa = (did.dial_info.protocol_type(), did.dial_info.address_type());

            // If this dial info can be contacted directly, then it can be used for receiving
            // relaying and satsifying an ordering mode
            if did.dial_info.matches_filter(&self.dial_info_filter) {
                possible_ordering_modes.insert(didpa.0.sequence_ordering());
            }
        }

        // If we did not get a single ordering mode we need for relaying, then this relay is disqualified
        // because we can't connect to it with our outbound protocols/address types directly
        if possible_ordering_modes.is_empty() {
            return false;
        }

        let mut useful = false;

        // Determine relay dial infos we can use from this relay out of our set of needed relay combinations
        // Builds up a set of needed ordering modes to keep flows open for the dial infos we are getting relayed
        for did in &dial_info_list {
            if did.class.requires_signal() {
                continue;
            }
            let didpa = (did.dial_info.protocol_type(), did.dial_info.address_type());

            if self.want_relay_protocols.remove(&didpa) {
                // Still needed this protocol+address type
                useful = true;

                // Mark this dial info as one we're using
                relay.dial_info_details.push(did.clone());

                // Mark this ordering mode as satisfied
                self.want_relay_orderings
                    .remove(&(didpa.0.sequence_ordering(), didpa.1));
            }
        }

        // Collect pings we can use from this relay
        for did in &dial_info_list {
            if did.class.requires_signal() {
                continue;
            }
            let didpa = (did.dial_info.protocol_type(), did.dial_info.address_type());

            // If this dial info can be contacted directly, then it is a ping candidate
            if did.dial_info.matches_filter(&self.dial_info_filter) {
                // See if we should add this ping
                let mut add_ping = false;

                // See if we should add the ping for ordering mode coverage
                let ordering = didpa.0.sequence_ordering();
                add_ping |= possible_ordering_modes.remove(ordering);

                // See if we should add the ping for low level port mapping coverage
                if let Some((llpt, port)) = self
                    .low_level_port_info
                    .protocol_to_port
                    .get(&didpa)
                    .copied()
                {
                    let wnk = (llpt, didpa.1, port);
                    add_ping |= self.wants_nat_keepalives.remove(&wnk);
                }

                // Add the ping if we determined we could use it
                if add_ping {
                    relay.pings.push(RelayPing {
                        node_ref: relay.relay_node.unfiltered().custom_filtered(
                            NodeRefFilter::new()
                                .with_routing_domain(self.routing_domain)
                                .with_dial_info_filter(did.dial_info.make_filter()),
                        ),
                    });
                }
            }
        }

        // Add a relay info to our list if it turned out to be useful
        if useful {
            self.relays.push(relay);
        }

        useful
    }
}
