use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolConfig {
    pub outbound: ProtocolTypeSet,
    pub inbound: ProtocolTypeSet,
    pub family_global: AddressTypeSet,
    pub family_local: AddressTypeSet,
    /// PublicInternet routing domain capabilities for this protocol
    pub public_internet_capabilities: BTreeSet<VeilidCapability>,
    /// LocalNetwork routing domain capabilities for this protocol
    pub local_network_capabilities: BTreeSet<VeilidCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressConfig {
    /// If network has IPV4 on any interface
    pub ipv4_local: bool,
    /// If network has IPV4 globally routable on any interface
    pub ipv4_global: bool,
    /// If network has IPV6 on any interface
    pub ipv6_local: bool,
    /// If network has IPV6 globally routable on any interface
    pub ipv6_global: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RoutingDomainNetworkState {
    /// If we are detecting address changes for this routing domain
    pub detect_address_changes: bool,
    /// The calculated routing domain network config
    pub routing_domain_network_config: RoutingDomainNetworkConfig,
    /// The static dialinfo details for protocols that have it
    pub static_dial_info_details: BTreeSet<DialInfoDetail>,
    /// The interface dialinfo details for protocols that have it
    pub interface_dial_info_details: BTreeSet<DialInfoDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetworkState {
    /// The calculated protocol configuration for inbound/outbound protocols
    pub protocol_config: ProtocolConfig,
    /// The calculated address configuration for IPV4/IPV6 on local interfaces
    pub address_config: AddressConfig,
    /// If we are enforcing inbound-relay-only mode (no IP information in peerinfo)
    pub require_inbound_relay: bool,
    /// The interface addresses (network+mask) most recently seen and default routing state
    pub interface_address_state: Arc<NetworkInterfaceAddressState>,
    /// The routing domain network states
    pub routing_domain_network_states: BTreeMap<RoutingDomain, RoutingDomainNetworkState>,
}

impl NetworkState {
    pub fn new(
        registry: VeilidComponentRegistry,
        protocol_config: ProtocolConfig,
        address_config: AddressConfig,
        interface_address_state: Arc<NetworkInterfaceAddressState>,
        routing_domain_detect_address_changes: BTreeSet<RoutingDomain>,
    ) -> Self {
        let config = registry.config();

        let mut routing_domain_network_states = BTreeMap::new();
        routing_domain_network_states.insert(
            RoutingDomain::PublicInternet,
            RoutingDomainNetworkState {
                detect_address_changes: routing_domain_detect_address_changes
                    .contains(&RoutingDomain::PublicInternet),
                routing_domain_network_config: RoutingDomainNetworkConfig::new(
                    protocol_config.outbound,
                    protocol_config.inbound,
                    protocol_config.family_global,
                    protocol_config.public_internet_capabilities.clone(),
                ),
                static_dial_info_details: BTreeSet::new(),
                interface_dial_info_details: BTreeSet::new(),
            },
        );
        routing_domain_network_states.insert(
            RoutingDomain::LocalNetwork,
            RoutingDomainNetworkState {
                detect_address_changes: routing_domain_detect_address_changes
                    .contains(&RoutingDomain::LocalNetwork),
                routing_domain_network_config: RoutingDomainNetworkConfig::new(
                    protocol_config.outbound,
                    protocol_config.inbound,
                    protocol_config.family_local,
                    protocol_config.local_network_capabilities.clone(),
                ),
                static_dial_info_details: BTreeSet::new(),
                interface_dial_info_details: BTreeSet::new(),
            },
        );

        Self {
            require_inbound_relay: config.network.privacy.require_inbound_relay,
            protocol_config,
            address_config,
            interface_address_state,
            routing_domain_network_states,
        }
    }

    #[expect(dead_code)]
    pub fn is_interface_ip_addr(&self, addr: IpAddr) -> bool {
        self.interface_address_state
            .interface_addresses
            .iter()
            .any(|x| x.ip() == addr)
    }

    pub fn translate_unspecified_socket_addr(&self, from: SocketAddr) -> Vec<SocketAddr> {
        if !from.ip().is_unspecified() {
            vec![from]
        } else {
            self.interface_address_state
                .interface_addresses
                .iter()
                .filter_map(|a| {
                    // We create sockets that are only ipv6 or ipv6 (not dual, so only translate matching unspecified address)
                    if (a.ip().is_ipv4() && from.ip().is_ipv4())
                        || (a.ip().is_ipv6() && from.ip().is_ipv6())
                    {
                        Some(SocketAddr::new(a.ip(), from.port()))
                    } else {
                        None
                    }
                })
                .collect()
        }
    }

    pub fn add_static_dial_info_detail(
        &mut self,
        dial_info_detail: DialInfoDetail,
    ) -> EyreResult<()> {
        let address = dial_info_detail.dial_info.address();

        let routing_domain = if address.is_global() {
            RoutingDomain::PublicInternet
        } else if address.is_local() {
            RoutingDomain::LocalNetwork
        } else {
            bail!(
                "No routing domain for static dial info: {}",
                dial_info_detail
            );
        };

        // It this is a static public address and we are not detecting address changes
        // then we can add this directly to the public internet routing domain
        // (otherwise we will add this during the 'confirm dial info' process)
        if let Some(routing_domain_network_state) =
            self.routing_domain_network_states.get_mut(&routing_domain)
        {
            routing_domain_network_state
                .static_dial_info_details
                .insert(dial_info_detail);
        }
        Ok(())
    }

    pub fn add_interface_dial_info_detail(
        &mut self,
        dial_info_detail: DialInfoDetail,
    ) -> EyreResult<()> {
        let address = dial_info_detail.dial_info.address();

        let routing_domain = if address.is_global() {
            RoutingDomain::PublicInternet
        } else if address.is_local() {
            RoutingDomain::LocalNetwork
        } else {
            // Ignoring addresses that are not in a routing domain we support
            bail!(
                "No routing domain for interface dial info: {}",
                dial_info_detail
            );
        };

        if let Some(routing_domain_network_state) =
            self.routing_domain_network_states.get_mut(&routing_domain)
        {
            routing_domain_network_state
                .interface_dial_info_details
                .insert(dial_info_detail);
        }
        Ok(())
    }

    pub fn static_dial_info_details(
        &self,
        routing_domain: RoutingDomain,
    ) -> BTreeSet<DialInfoDetail> {
        self.routing_domain_network_states
            .get(&routing_domain)
            .map(|x| x.static_dial_info_details.clone())
            .unwrap_or_default()
    }

    pub fn has_any_static_dial_info_details(&self, routing_domain: RoutingDomain) -> bool {
        self.routing_domain_network_states
            .get(&routing_domain)
            .map(|x| !x.static_dial_info_details.is_empty())
            .unwrap_or(false)
    }

    pub fn has_any_interface_dial_info_details(&self, routing_domain: RoutingDomain) -> bool {
        self.routing_domain_network_states
            .get(&routing_domain)
            .map(|x| !x.interface_dial_info_details.is_empty())
            .unwrap_or(false)
    }
}

impl NativeNetwork {
    pub(super) fn last_network_state(&self) -> Option<Arc<NetworkState>> {
        self.inner.lock().network_state.clone()
    }

    pub(super) async fn refresh_network_state(&self) -> EyreResult<Option<Arc<NetworkState>>> {
        // Get last network state
        let opt_last_network_state = self.inner.lock().network_state.clone();

        // Refresh network interfaces
        if !self
            .interfaces
            .refresh()
            .await
            .wrap_err("failed to refresh network interfaces")?
        {
            // Nothing changed
            return Ok(None);
        }

        let interface_address_state = self.interfaces.interface_address_state();

        let routing_domain_detect_address_changes = if let Some(last_interface_address_state) =
            opt_last_network_state.map(|x| x.interface_address_state.clone())
        {
            // Post-startup network refresh
            veilid_log!(self debug
                "Network interface address state changed: \nFrom:\n{}\n  To:\n{}\n",
                indent_all_string(format!("{:?}", last_interface_address_state)),
                indent_all_string(format!("{:?}", interface_address_state))
            );

            // Return the 'detect address changes' settings from when they were set up for all the other
            // post-startup calls to this routine
            self.routing_domains_detecting_address_changes()
        } else {
            // First time, pre-startup initial network refresh
            veilid_log!(self debug
                "Network interface address state:\n{}\n",
                indent_all_string(format!("{:?}", interface_address_state))
            );

            // The first time we get a network state, set up the 'detect address changes' settings for
            // each routing domain based on the config and the initial network state
            self.set_up_detect_address_changes(&interface_address_state)
        };

        // Create new network state
        let address_config = self.make_address_config();
        let protocol_config = self.make_protocol_config(&address_config);

        let mut new_network_state = NetworkState::new(
            self.registry(),
            protocol_config,
            address_config,
            interface_address_state.clone(),
            routing_domain_detect_address_changes,
        );

        // Get the updated dialinfo into the new network state
        self.add_interface_dial_info(&mut new_network_state)?;

        let new_network_state = Arc::new(new_network_state);
        self.inner.lock().network_state = Some(new_network_state.clone());

        Ok(Some(new_network_state))
    }

    // TODO: This, along with the binding code should be part of the protocol trait
    #[cfg_attr(feature = "instrument", instrument(level = "debug", err, skip_all, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub(super) fn add_interface_dial_info(
        &self,
        network_state: &mut NetworkState,
    ) -> EyreResult<()> {
        let config = self.config();

        // TODO: eventually this should move into registrable protocol handler state
        if network_state
            .protocol_config
            .inbound
            .contains(ProtocolType::UDP)
        {
            let opt_bound_addresses = self
                .inner
                .lock()
                .bound_address_per_protocol
                .get(&ProtocolType::UDP)
                .cloned();
            if let Some(bound_addresses) = opt_bound_addresses {
                self.add_udp_interface_dial_info(config.clone(), &bound_addresses, network_state)?;
            }
        }
        if network_state
            .protocol_config
            .inbound
            .contains(ProtocolType::WS)
        {
            let opt_bound_addresses = self
                .inner
                .lock()
                .bound_address_per_protocol
                .get(&ProtocolType::WS)
                .cloned();
            if let Some(bound_addresses) = opt_bound_addresses {
                self.add_ws_interface_dial_info(config.clone(), &bound_addresses, network_state)?;
            }
        }
        #[cfg(feature = "enable-protocol-wss")]
        if network_state
            .protocol_config
            .inbound
            .contains(ProtocolType::WSS)
        {
            let opt_bound_addresses = self
                .inner
                .lock()
                .bound_address_per_protocol
                .get(&ProtocolType::WSS)
                .cloned();
            if let Some(bound_addresses) = opt_bound_addresses {
                self.add_wss_interface_dial_info(config.clone(), &bound_addresses, network_state)?;
            }
        }
        if network_state
            .protocol_config
            .inbound
            .contains(ProtocolType::TCP)
        {
            let opt_bound_addresses = self
                .inner
                .lock()
                .bound_address_per_protocol
                .get(&ProtocolType::TCP)
                .cloned();
            if let Some(bound_addresses) = opt_bound_addresses {
                self.add_tcp_interface_dial_info(config.clone(), &bound_addresses, network_state)?;
            }
        }

        Ok(())
    }

    fn check_ipv4_routable() -> (bool, bool) {
        let ipv4addr = "1.2.3.4".parse::<Ipv4Addr>().unwrap();
        let sockaddrv4 = SocketAddr::V4(SocketAddrV4::new(ipv4addr, 5155));
        let res = std::net::UdpSocket::bind("0.0.0.0:0");
        if let Ok(socket) = res {
            return (true, socket.connect(sockaddrv4).is_ok());
        }
        (false, false)
    }

    fn check_ipv6_routable() -> (bool, bool) {
        let ipv6addr = "2222::1".parse::<Ipv6Addr>().unwrap();
        let sockaddrv6 = SocketAddr::V6(SocketAddrV6::new(ipv6addr, 5155, 0, 0));
        let res = std::net::UdpSocket::bind("[::]:0");
        if let Ok(socket) = res {
            return (true, socket.connect(sockaddrv6).is_ok());
        }
        (false, false)
    }

    pub(super) fn make_address_config(&self) -> AddressConfig {
        // Determine if we have ipv4/ipv6 addresses
        let (ipv4_local, ipv4_global) = Self::check_ipv4_routable();
        let (ipv6_local, ipv6_global) = Self::check_ipv6_routable();
        if ipv4_local {
            veilid_log!(self debug "Local IPV4 detected by bind test");
        }
        if ipv4_global {
            veilid_log!(self debug "Global IPV4 detected by connect test");
        }
        if ipv6_local {
            veilid_log!(self debug "Local IPV6 detected by bind test");
        }
        if ipv6_global {
            veilid_log!(self debug "Global IPV6 detected by connect test");
        }

        AddressConfig {
            ipv4_local,
            ipv4_global,
            ipv6_local,
            ipv6_global,
        }
    }

    pub(super) fn make_protocol_config(&self, address_config: &AddressConfig) -> ProtocolConfig {
        let config = self.config();
        let mut inbound = ProtocolTypeSet::new();

        if config.network.protocol.udp.enabled {
            inbound.insert(ProtocolType::UDP);
        }
        if config.network.protocol.tcp.listen {
            inbound.insert(ProtocolType::TCP);
        }
        if config.network.protocol.ws.listen {
            inbound.insert(ProtocolType::WS);
        }
        #[cfg(feature = "enable-protocol-wss")]
        if config.network.protocol.wss.listen {
            inbound.insert(ProtocolType::WSS);
        }

        let mut outbound = ProtocolTypeSet::new();
        if config.network.protocol.udp.enabled {
            outbound.insert(ProtocolType::UDP);
        }
        if config.network.protocol.tcp.connect {
            outbound.insert(ProtocolType::TCP);
        }
        if config.network.protocol.ws.connect {
            outbound.insert(ProtocolType::WS);
        }
        #[cfg(feature = "enable-protocol-wss")]
        if config.network.protocol.wss.connect {
            outbound.insert(ProtocolType::WSS);
        }

        let mut family_global = AddressTypeSet::new();
        let mut family_local = AddressTypeSet::new();
        if address_config.ipv4_local {
            family_local.insert(AddressType::IPV4);
        }
        if address_config.ipv4_global {
            family_global.insert(AddressType::IPV4);
        }
        if address_config.ipv6_local {
            family_local.insert(AddressType::IPV6);
        }
        if address_config.ipv6_global {
            family_global.insert(AddressType::IPV6);
        }

        // set up the routing table's network config
        // if we have static public dialinfo, upgrade our network class
        let public_internet_capabilities = {
            PUBLIC_INTERNET_CAPABILITIES
                .iter()
                .copied()
                .filter(|cap| !config.capabilities.disable.contains(cap))
                .collect::<BTreeSet<VeilidCapability>>()
        };
        let local_network_capabilities = {
            LOCAL_NETWORK_CAPABILITIES
                .iter()
                .copied()
                .filter(|cap| !config.capabilities.disable.contains(cap))
                .collect::<BTreeSet<VeilidCapability>>()
        };

        ProtocolConfig {
            outbound,
            inbound,
            family_global,
            family_local,
            public_internet_capabilities,
            local_network_capabilities,
        }
    }
}
