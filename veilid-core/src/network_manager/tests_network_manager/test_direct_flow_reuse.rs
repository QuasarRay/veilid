use super::*;
use crate::routing_table::tests_routing_table::*;
use crate::tests::*;

const PEER_IP: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const PEER_PORT: u16 = 5150;
/// A port a NAT gave the peer's own connection, which no dial info names
const OTHER_PORT: u16 = 35490;

fn peer_socket_address(port: u16) -> SocketAddress {
    SocketAddress::new(Address::IPV4(PEER_IP), port)
}

fn tcp_dial_info() -> DialInfo {
    DialInfo::tcp(peer_socket_address(PEER_PORT))
}

fn ws_dial_info() -> DialInfo {
    DialInfo::try_ws(
        peer_socket_address(PEER_PORT),
        format!("ws://{}:{}/ws", PEER_IP, PEER_PORT),
    )
    .expect("ws dial info")
}

fn udp_dial_info() -> DialInfo {
    DialInfo::udp(peer_socket_address(PEER_PORT))
}

#[cfg(feature = "enable-protocol-webtransport")]
fn wts_dial_info() -> DialInfo {
    DialInfo::try_webtransport_stream(
        peer_socket_address(PEER_PORT),
        format!("https://{}:{}/wt", PEER_IP, PEER_PORT),
        vec![[1u8; 32]],
        None,
    )
    .expect("wts dial info")
}

fn flow_from(protocol_type: ProtocolType, port: u16) -> Flow {
    Flow::new_no_local(PeerAddress::new(peer_socket_address(port), protocol_type))
}

fn reaches(relays: &[SocketAddress], flow: Flow, dial_info: &DialInfo) -> bool {
    let relays = relays.iter().copied().collect::<HashSet<_>>();
    NetworkManager::flow_reaches_dial_info(&relays, &flow, dial_info)
}

/// A flow reaches a dial info on any protocol of its connection table slot and from any port of its
/// address, and a relay of ours only at its own dial info
pub fn test_flow_reaches_dial_info() {
    for dial_info in [tcp_dial_info(), ws_dial_info()] {
        for protocol_type in [ProtocolType::TCP, ProtocolType::WS] {
            assert!(
                reaches(&[], flow_from(protocol_type, OTHER_PORT), &dial_info),
                "{protocol_type} from another port reaches {dial_info}"
            );
        }
        assert!(
            !reaches(&[], flow_from(ProtocolType::UDP, PEER_PORT), &dial_info),
            "a datagram flow does not reach {dial_info}"
        );
    }
    assert!(reaches(
        &[],
        flow_from(ProtocolType::UDP, OTHER_PORT),
        &udp_dial_info()
    ));
    assert!(
        !reaches(
            &[],
            flow_from(ProtocolType::TCP, PEER_PORT),
            &udp_dial_info()
        ),
        "a connection does not reach a datagram dial info"
    );

    let elsewhere = Flow::new_no_local(PeerAddress::new(
        SocketAddress::new(Address::IPV4(Ipv4Addr::new(8, 8, 8, 8)), PEER_PORT),
        ProtocolType::TCP,
    ));
    assert!(!reaches(&[], elsewhere, &tcp_dial_info()));

    // Our relay's connection is the protected one at its dial info
    let relay_at_dial_info = [peer_socket_address(PEER_PORT)];
    assert!(!reaches(
        &relay_at_dial_info,
        flow_from(ProtocolType::TCP, OTHER_PORT),
        &tcp_dial_info()
    ));
    assert!(reaches(
        &relay_at_dial_info,
        flow_from(ProtocolType::TCP, PEER_PORT),
        &ws_dial_info()
    ));
    // A relayed envelope leaves our relay's flow under its sender
    assert!(!reaches(
        &[peer_socket_address(OTHER_PORT)],
        flow_from(ProtocolType::TCP, OTHER_PORT),
        &tcp_dial_info()
    ));

    #[cfg(feature = "enable-protocol-webtransport")]
    {
        let dial_info = wts_dial_info();
        assert!(reaches(
            &[],
            flow_from(ProtocolType::WTS, OTHER_PORT),
            &dial_info
        ));
        for protocol_type in [ProtocolType::TCP, ProtocolType::UDP, ProtocolType::WTD] {
            assert!(
                !reaches(&[], flow_from(protocol_type, PEER_PORT), &dial_info),
                "{protocol_type} does not reach a WebTransport stream dial info"
            );
        }
    }
}

/// A signed PublicInternet peer info publishing `dial_infos`
fn signed_peer_info(routing_table: &RoutingTable, dial_infos: Vec<DialInfo>) -> Arc<PeerInfo> {
    let (crypto_info_list, secret_keys) = fix_node_keys();
    let dial_info_detail_list = dial_infos
        .into_iter()
        .map(|dial_info| DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info,
        })
        .collect::<Vec<_>>();
    let node_info = NodeInfo::new(
        Timestamp::now(),
        vec![ENVELOPE_VERSION_ENV0],
        crypto_info_list,
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        dial_info_detail_list,
        vec![],
        TransportMtus::default(),
        None,
    );
    Arc::new(
        PeerInfo::try_new_from_node_info(
            routing_table,
            RoutingDomain::PublicInternet,
            &secret_keys,
            node_info,
        )
        .expect("peer info"),
    )
}

/// The method `pick_contact_method` chooses among `contact_methods`
fn pick(
    network_manager: &NetworkManager,
    peer: &FilteredNodeRef,
    contact_methods: &[ContactMethod],
) -> ContactMethod {
    match network_manager
        .pick_contact_method(
            peer.clone(),
            contact_methods.to_vec(),
            ContactMethodIntent::Advisory,
        )
        .expect("pick")
    {
        NodeContactMethodResult::Resolved(contact_method) => contact_method,
        other => panic!("no contact method picked: {other}"),
    }
}

/// A failed dial moves the pick down the peer's listener, and a flow from the peer's address on a
/// port no dial info names clears every failure on that listener, so the pick is the preferred
/// protocol there again; a failure on another listener stays
pub async fn test_flow_resets_the_pick_on_its_listener() {
    let registry = mock_registry::init("nm_direct_flow_reuse").await;
    let network_manager = registry.network_manager();
    let routing_table = registry.routing_table();
    // Node refs must go before the registry: a dropped ref queues a bucket kick
    {
        let own = signed_peer_info(
            &routing_table,
            vec![DialInfo::tcp(SocketAddress::new(
                Address::IPV4(Ipv4Addr::new(8, 8, 4, 4)),
                PEER_PORT,
            ))],
        );
        #[cfg(feature = "enable-protocol-webtransport")]
        let dial_infos = vec![tcp_dial_info(), ws_dial_info(), wts_dial_info()];
        #[cfg(not(feature = "enable-protocol-webtransport"))]
        let dial_infos = vec![tcp_dial_info(), ws_dial_info()];
        let peer_info = signed_peer_info(&routing_table, dial_infos);
        let peer = routing_table
            .register_node_with_peer_info(
                Arc::new(UnverifiedPeerInfo::from_verified(&peer_info)),
                false,
            )
            .expect("register");

        let contact_methods = routing_table.get_contact_methods(
            RoutingDomain::PublicInternet,
            ContactMethodRequest {
                peer_a: own,
                peer_a_published: false,
                peer_b: peer_info,
                dial_info_filter: DialInfoFilter::all(),
                sequencing: Sequencing::EnsureOrdered,
            },
        );
        // The listener's methods in the order the routing domain prefers them
        let on_listener = contact_methods
            .iter()
            .filter(|contact_method| {
                contact_method.direct_dial_info().is_some_and(|dial_info| {
                    dial_info.protocol_type().low_level_protocol_type() == LowLevelProtocolType::TCP
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(on_listener.len(), 2, "{contact_methods:?}");
        let preferred = on_listener[0].clone();
        assert_eq!(pick(&network_manager, &peer, &on_listener), preferred);

        peer.report_contact_method_result(&preferred, false);
        assert_eq!(pick(&network_manager, &peer, &on_listener), on_listener[1]);
        for contact_method in &contact_methods {
            peer.report_contact_method_result(contact_method, false);
        }

        network_manager.set_last_flow(
            peer.unfiltered(),
            flow_from(ProtocolType::TCP, OTHER_PORT),
            Timestamp::now(),
        );

        for contact_method in &contact_methods {
            assert_eq!(
                peer.get_contact_method_failure_ts(contact_method).is_none(),
                on_listener.contains(contact_method),
                "{contact_method}"
            );
        }
        assert_eq!(pick(&network_manager, &peer, &on_listener), preferred);
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_all() {
    test_flow_reaches_dial_info();
    test_flow_resets_the_pick_on_its_listener().await;
}
