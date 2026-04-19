use super::*;

impl_veilid_log_facility!("rtab");

pub trait RoutingDomainDetailAccessors: RoutingDomainDetail {
    #[expect(dead_code)]
    fn common(&self) -> &RoutingDomainDetailCommon;
    fn common_mut(&mut self) -> &mut RoutingDomainDetailCommon;
}

pub struct RoutingDomainDetailCommon {
    /// The registry accessor for this routing domain detail
    registry: VeilidComponentRegistry,
    /// The routing domain identifier for this routing domain detail
    routing_domain: RoutingDomain,
    /// The network configuration for this routing domain
    network_config: RoutingDomainNetworkConfig,
    /// Relay nodes and their current state used to determine what actions a relay many need (keepalive, optimize, etc.)
    relays_and_states: Vec<(RoutingDomainRelay, RoutingDomainRelayState)>,
    /// The dial info details that are inbound reachable for this node in this domain
    dial_info_details: Vec<DialInfoDetail>,
    /// Dial info detail has been confirmed by the network manager as publishable/reachable
    confirmed: bool,
    /// The minimum number of nodes in the is routing domain since the last low water mark recording point
    /// Pair of (reset, low water mark)
    low_water_mark: Mutex<(bool, Arc<LowWaterMark>)>,
    /// The current peer info so we don't have recalculate it every time it is requested
    current_peer_info_cache: Mutex<Option<Arc<PeerInfo>>>,
    /// The last known bootstrap peers that seeded our routing table
    bootstrap_peers: Mutex<Vec<NodeRef>>,
    /// The last calculated summary of the routing table entries in this domain
    entry_summary: Mutex<Arc<EntrySummary>>,
}

impl fmt::Debug for RoutingDomainDetailCommon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingDomainDetailCommon")
            .field("routing_domain", &self.routing_domain)
            .field("network_config", &self.network_config)
            .field("relays_and_states", &self.relays_and_states)
            .field("dial_info_details", &self.dial_info_details)
            .field("confirmed", &self.confirmed)
            .field("low_water_mark", &self.low_water_mark)
            .field("current_peer_info_cache", &self.current_peer_info_cache)
            .field("bootstrap_peers", &self.bootstrap_peers)
            .field("entry_summary", &self.entry_summary)
            .finish()
    }
}

impl fmt::Display for RoutingDomainDetailCommon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Network Config:{}\nRelays And States:\n{}\nDial Info Details:\n{}\nConfirmed: {}\nLow Water Mark: {}\nBootstrap Peers: {}\nEntry Summary:\n{}",
            if f.alternate() {
                format!("\n{}",indent_all_string(f.to_string(&self.network_config)))
            } else {
                format!(" {}",f.to_string(&self.network_config))
            },
            indent_all_string(f.to_multiline_indexed_string(self.relays_and_states.iter().map(|(r,s)| format!("{}\n{}", f.to_string(r), f.to_string(s)))).string_if_empty("None")),
            indent_all_string(f.to_multiline_indexed_string(self.dial_info_details.iter().map(|d| f.to_string(d))).string_if_empty("None")),
            f.to_string(self.confirmed),
            f.to_string(self.low_water_mark.lock().1.clone()),
            self.bootstrap_peers.lock().clone().iter().map(|n| f.to_string(n)).collect::<Vec<_>>().join(",").string_if_empty("None"),
            indent_all_string(f.to_string(self.entry_summary.lock().clone()))
        )
    }
}

impl_veilid_component_accessors!(RoutingDomainDetailCommon);

impl RoutingDomainDetailCommon {
    pub fn new(registry: VeilidComponentRegistry, routing_domain: RoutingDomain) -> Self {
        Self {
            registry,
            routing_domain,
            network_config: Default::default(),
            relays_and_states: Default::default(),
            dial_info_details: Default::default(),
            confirmed: false,
            low_water_mark: Mutex::new((true, Default::default())),
            current_peer_info_cache: Mutex::new(Default::default()),
            bootstrap_peers: Mutex::new(Default::default()),
            entry_summary: Mutex::new(Default::default()),
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // Accessors

    pub fn confirmed(&self) -> bool {
        self.confirmed
    }

    pub fn network_config(&self) -> &RoutingDomainNetworkConfig {
        &self.network_config
    }

    pub fn outbound_protocols(&self) -> ProtocolTypeSet {
        self.network_config.outbound_protocols
    }

    pub fn inbound_protocols(&self) -> ProtocolTypeSet {
        self.network_config.inbound_protocols
    }

    pub fn address_types(&self) -> AddressTypeSet {
        self.network_config.address_types
    }

    pub fn capabilities(&self) -> BTreeSet<VeilidCapability> {
        self.network_config.capabilities.clone()
    }

    pub fn get_bootstrap_peers(&self) -> Vec<NodeRef> {
        self.bootstrap_peers.lock().clone()
    }

    pub fn clear_bootstrap_peers(&self) {
        self.bootstrap_peers.lock().clear()
    }

    pub fn add_bootstrap_peer(&self, bootstrap_peer: NodeRef) {
        let mut bootstrap_peers = self.bootstrap_peers.lock();
        bootstrap_peers.push(bootstrap_peer);
    }

    pub fn update_low_water_mark(&self, mut low_water_mark: Arc<LowWaterMark>) {
        let mut lwm = self.low_water_mark.lock();
        let (reset, last_low_water_mark) = lwm.clone();

        if !reset {
            let mut new_low_water_mark = low_water_mark.as_ref().clone();
            new_low_water_mark.merge(&last_low_water_mark);
            low_water_mark = Arc::new(new_low_water_mark);
        }

        if last_low_water_mark != low_water_mark {
            veilid_log!(self debug "[{:#}] changed low water mark from {} to {}", self.routing_domain, last_low_water_mark, low_water_mark);
            *lwm = (false, low_water_mark);
        }
    }

    pub fn reset_low_water_mark(&self) {
        self.low_water_mark.lock().0 = true;
    }

    pub fn get_low_water_mark(&self) -> Arc<LowWaterMark> {
        self.low_water_mark.lock().1.clone()
    }

    pub fn relays(&self) -> Vec<RoutingDomainRelay> {
        self.relays_and_states.iter().map(|x| x.0.clone()).collect()
    }

    pub fn relays_and_states(&self) -> Vec<(RoutingDomainRelay, RoutingDomainRelayState)> {
        self.relays_and_states.clone()
    }

    pub fn dial_info_details(&self) -> &Vec<DialInfoDetail> {
        &self.dial_info_details
    }

    pub fn inbound_dial_info_filter(&self) -> DialInfoFilter {
        DialInfoFilter::all()
            .with_protocol_type_set(self.network_config.inbound_protocols)
            .with_address_type_set(self.network_config.address_types)
    }

    pub fn outbound_dial_info_filter(&self) -> DialInfoFilter {
        DialInfoFilter::all()
            .with_protocol_type_set(self.network_config.outbound_protocols)
            .with_address_type_set(self.network_config.address_types)
    }

    pub fn get_current_peer_info(&self) -> Arc<PeerInfo> {
        let mut cpi = self.current_peer_info_cache.lock();
        if cpi.is_none() {
            // Regenerate peer info
            let pi = self.make_current_peer_info();

            // Cache the peer info
            *cpi = Some(Arc::new(pi));
        }
        cpi.as_ref().unwrap_or_log().clone()
    }

    pub fn get_entry_summary(&self) -> Arc<EntrySummary> {
        self.entry_summary.lock().clone()
    }

    pub fn set_entry_summary(&self, entry_summary: Arc<EntrySummary>) {
        *self.entry_summary.lock() = entry_summary;
    }

    ///////////////////////////////////////////////////////////////////////
    // Mutators

    pub fn set_network_config(&mut self, network_config: RoutingDomainNetworkConfig) {
        let changed = self.network_config != network_config;
        if changed {
            self.network_config = network_config;

            self.clear_current_peer_info_cache();
        }
    }

    pub fn set_confirmed(&mut self, confirmed: bool) {
        self.confirmed = confirmed;
    }

    pub fn clear_dial_info_details(
        &mut self,
        address_types: Option<AddressTypeSet>,
        protocol_types: Option<ProtocolTypeSet>,
    ) {
        let mut changed = false;
        self.dial_info_details.retain_mut(|e| {
            let mut remove = true;
            if let Some(pt) = protocol_types {
                if !pt.contains(e.dial_info.protocol_type()) {
                    remove = false;
                }
            }
            if let Some(at) = address_types {
                if !at.contains(e.dial_info.address_type()) {
                    remove = false;
                }
            }

            changed = changed || remove;
            !remove
        });

        if changed {
            self.dial_info_details.sort();
            self.dial_info_details.dedup();

            self.clear_current_peer_info_cache();
        }
    }
    pub fn add_dial_info_detail(&mut self, did: DialInfoDetail) {
        let changed = !self.dial_info_details.contains(&did);
        if changed {
            self.dial_info_details.push(did);
            self.dial_info_details.sort();
            self.dial_info_details.dedup();

            self.clear_current_peer_info_cache();
        }
    }
    // pub fn remove_dial_info_detail(&mut self, did: DialInfoDetail) {
    //     let mut changed = false;
    //     self.dial_info_details.retain(|e| {
    //         let remove = e == &did;
    //         changed = changed || remove;
    //         !remove
    //     });
    //     if changed {
    //         self.clear_current_peer_info_cache();
    //     }
    // }

    pub fn set_relays(&mut self, relays: Vec<RoutingDomainRelay>) {
        let changed = self.relays() != relays;
        if !changed {
            return;
        }

        let cur_ts = Timestamp::now();

        let mut new_relays_and_states = vec![];
        for relay in relays {
            // See if this relay exists already, if so, keep its state
            if let Some(existing_relay_state) =
                self.relays_and_states.iter().find_map(
                    |(r, s)| {
                        if r == &relay {
                            Some(*s)
                        } else {
                            None
                        }
                    },
                )
            {
                new_relays_and_states.push((relay, existing_relay_state));
            } else {
                // New relay, make a new state for it
                new_relays_and_states.push((
                    relay,
                    RoutingDomainRelayState {
                        last_keepalive: cur_ts,
                        last_optimized: cur_ts,
                    },
                ));
            }
        }
        self.relays_and_states = new_relays_and_states;
        self.clear_current_peer_info_cache();
    }

    pub fn set_relay_state(&mut self, relay: &RoutingDomainRelay, state: RoutingDomainRelayState) {
        let Some(existing_relay_state) = self.relays_and_states.iter_mut().find_map(|x| {
            if &x.0 == relay {
                Some(&mut x.1)
            } else {
                None
            }
        }) else {
            return;
        };
        *existing_relay_state = state;
    }

    pub fn clear_current_peer_info_cache(&self) {
        *self.current_peer_info_cache.lock() = None;
    }

    //////////////////////////////////////////////////////////////////////////////
    // Internal functions

    fn make_current_peer_info(&self) -> PeerInfo {
        let routing_table = self.routing_table();
        let cur_ts = Timestamp::now_non_decreasing();
        let mut relay_info_list = vec![];
        for relay in self.relays() {
            let relay_node_ids = relay.relay_node.node_ids();
            let Some(relay_node_info) = relay.relay_node.node_info(self.routing_domain) else {
                veilid_log!(self debug "not including relay node {} in peer info for routing domain {:?}", relay_node_ids, self.routing_domain);
                continue;
            };
            let relay_info = RelayInfo::new(
                relay_node_info.timestamp(),
                relay_node_ids,
                relay_node_info.outbound_protocols(),
                relay_node_info.address_types(),
                relay.dial_info_details,
                relay.relay_kind,
            );
            relay_info_list.push(relay_info);
        }

        let keypairs = routing_table.signing_key_pairs();
        let public_keys: Vec<_> = keypairs.iter().map(|x| x.key()).collect();
        let secret_keys =
            SecretKeyGroup::from(keypairs.iter().map(|x| x.secret()).collect::<Vec<_>>());
        let crypto_info_list: Vec<_> = public_keys
            .iter()
            .map(|pk| match pk.kind() {
                CRYPTO_KIND_VLD0 => CryptoInfo::VLD0 {
                    public_key: pk.value(),
                },
                _ => {
                    unimplemented!("Must implement cryptoinfo")
                }
            })
            .collect();

        let node_info = NodeInfo::new(
            cur_ts,
            VALID_ENVELOPE_VERSIONS.to_vec(),
            crypto_info_list,
            self.network_config.capabilities.iter().copied().collect(),
            self.network_config.outbound_protocols,
            self.network_config.address_types,
            self.dial_info_details.clone(),
            relay_info_list,
        );

        PeerInfo::new_from_node_info(&routing_table, self.routing_domain, &secret_keys, node_info)
            .expect_or_log("our own peerinfo should never fail")
    }
}
