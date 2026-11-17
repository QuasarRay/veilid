use super::*;
use crate::tests::*;

/// No relay is wanted for WSS, so a public server, which holds no CA certificate and lists no
/// WSS dial info, needs none and goes on to publish
#[cfg(feature = "enable-protocol-wss")]
pub async fn test_relay_requirements_leave_out_wss() {
    let registry = mock_registry::init("rt_relay_requirements_wss").await;
    let routing_table = registry.routing_table();
    let controller = routing_table
        .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

    // With no dial info of its own a node wants a relay for every other protocol
    let wanted: ProtocolTypeSet = controller
        .read_dyn()
        .relay_requirements()
        .need_relay_transports
        .iter()
        .map(|transport| transport.protocol_type())
        .collect();
    assert_eq!(wanted, ProtocolTypeSet::all() - ProtocolType::WSS);

    make_public_internet_direct(&routing_table);
    let mut editor = controller.edit();
    editor.clear_dial_info_details(None, Some(ProtocolType::WSS.into()));
    editor.commit();

    assert!(!controller.read_dyn().relay_requirements().needs_relays());
    assert_eq!(
        controller.state().inbound_stage,
        RoutingDomainInboundStage::NeedsTransportMtus
    );

    mock_registry::terminate(registry).await;
}

/// A relay offering both address families is pinged at one address, the only one kept up
pub async fn test_keepalives_reach_one_relay_address() {
    let registry = mock_registry::init("rt_relay_keepalive_addresses").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        // No dial info of our own, dialing out over both families
        let mut editor = controller.edit();
        editor.set_network_config(RoutingDomainNetworkConfig::new(
            ProtocolTypeSet::all(),
            ProtocolTypeSet::all(),
            AddressTypeSet::all(),
            PUBLIC_INTERNET_CAPABILITIES.iter().copied().collect(),
        ));
        editor.commit();

        let v4 = SocketAddress::new(Address::IPV4(Ipv4Addr::new(8, 8, 4, 4)), 5150);
        let v6 = SocketAddress::new(
            Address::IPV6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
            5150,
        );
        let dial_info_details = [v4, v6]
            .into_iter()
            .flat_map(|address| [DialInfo::udp(address), DialInfo::tcp(address)])
            .map(|dial_info| DialInfoDetail {
                class: DialInfoClass::Direct,
                dial_info,
            })
            .collect();
        let (crypto_info_list, secret_keys) = fix_node_keys();
        let node_info = NodeInfo::new(
            Timestamp::new(0),
            vec![ENVELOPE_VERSION_ENV0],
            crypto_info_list,
            PUBLIC_INTERNET_CAPABILITIES.to_vec(),
            ProtocolTypeSet::new(),
            AddressTypeSet::new(),
            dial_info_details,
            vec![],
            TransportMtus::default(),
            None,
        );
        let peer_info = PeerInfo::try_new_from_node_info(
            &routing_table,
            RoutingDomain::PublicInternet,
            &secret_keys,
            node_info,
        )
        .expect("should build signed relay peer info");
        let relay_node = routing_table
            .register_node_with_peer_info(
                Arc::new(UnverifiedPeerInfo::from_verified(&peer_info)),
                false,
            )
            .expect("should register relay peer info")
            .unfiltered();

        let mut compiler = controller
            .read_dyn()
            .relay_requirements()
            .make_relay_compiler();
        assert!(compiler.apply_relay(RoutingDomainRelay::new(
            RoutingDomain::PublicInternet,
            relay_node,
            RelayKind::Inbound,
        )));
        let relay = &compiler.relays[0];

        // The relay serves both families
        let offered: HashSet<SocketAddress> = relay
            .dial_info_details
            .iter()
            .map(|did| did.dial_info.socket_address())
            .collect();
        assert_eq!(offered, HashSet::from([v4, v6]));

        // One ping per ordering, both at the address that sorts first
        let kept: HashSet<SocketAddress> = relay.keepalive_addresses().collect();
        assert_eq!(kept.len(), 1);
        assert!(kept.is_subset(&offered));
    }
    mock_registry::terminate(registry).await;
}
