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
        let v4 = SocketAddress::new(Address::IPV4(Ipv4Addr::new(8, 8, 4, 4)), 5150);
        let v6 = SocketAddress::new(
            Address::IPV6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
            5150,
        );
        let dial_infos = [v4, v6]
            .into_iter()
            .flat_map(|address| [DialInfo::udp(address), DialInfo::tcp(address)])
            .collect();
        let relay = compile_test_relay(
            &registry.routing_table(),
            ProtocolTypeSet::all(),
            dial_infos,
        );

        // The relay serves both families
        let offered: HashSet<SocketAddress> = relay
            .dial_info_details
            .iter()
            .map(|did| did.dial_info.socket_address())
            .collect();
        assert_eq!(offered, HashSet::from([v4, v6]));

        // One ping per ordering, both at the address that sorts first
        let kept: HashSet<SocketAddress> = relay
            .keepalive_addresses()
            .map(|peer_address| *peer_address.socket_address())
            .collect();
        assert_eq!(kept.len(), 1);
        assert!(kept.is_subset(&offered));
    }
    mock_registry::terminate(registry).await;
}
