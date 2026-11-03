use super::*;
use crate::tests::*;

const UNEXPIRED: Timestamp = Timestamp::new(4_000_000_000_000_000);
const EXPIRED: Timestamp = Timestamp::new(1);

fn node_a_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 160)), 5150)
}

fn node_b_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 170)), 5150)
}

fn direct(dial_info: DialInfo) -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info,
    }
}

fn webtransport_dial_info_detail(expiration: Timestamp) -> DialInfoDetail {
    direct(
        DialInfo::try_webtransport_stream(
            node_b_socket_address(),
            "https://18.218.0.170:5150/".to_string(),
            vec![[1u8; 32]],
            Some(expiration),
        )
        .expect("should build wts dial info"),
    )
}

fn peer_info(
    routing_table: &RoutingTable,
    valid_crypto: bool,
    dial_info_detail_list: Vec<DialInfoDetail>,
) -> Arc<PeerInfo> {
    let node_info = NodeInfo::new(
        Timestamp::new(0),
        vec![ENVELOPE_VERSION_ENV0],
        fix_crypto_info_list(valid_crypto),
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        dial_info_detail_list.clone(),
        vec![],
        TransportMtus::default(),
        NodeInfo::min_dial_info_expiration(&dial_info_detail_list),
    );

    Arc::new(
        PeerInfo::try_new_from_unsigned(routing_table, RoutingDomain::PublicInternet, node_info)
            .expect("should build unsigned peer info"),
    )
}

fn node_a(routing_table: &RoutingTable) -> Arc<PeerInfo> {
    peer_info(
        routing_table,
        true,
        vec![
            direct(DialInfo::udp(node_a_socket_address())),
            direct(DialInfo::tcp(node_a_socket_address())),
        ],
    )
}

fn contact_methods(
    routing_table: &RoutingTable,
    peer_a: Arc<PeerInfo>,
    peer_b: Arc<PeerInfo>,
) -> Vec<ContactMethod> {
    routing_table.get_contact_methods(
        RoutingDomain::PublicInternet,
        ContactMethodRequest {
            peer_a,
            peer_a_published: false,
            peer_b,
            dial_info_filter: DialInfoFilter::all(),
            sequencing: Sequencing::EnsureOrdered,
        },
    )
}

fn direct_protocol_types(contact_methods: &[ContactMethod]) -> Vec<ProtocolType> {
    contact_methods
        .iter()
        .filter_map(|cm| cm.direct_dial_info())
        .map(|di| di.protocol_type())
        .collect()
}

pub async fn test_expired_webtransport_dial_info_is_skipped_for_contact() {
    let registry = mock_registry::init("contact_method_expiration").await;
    {
        let routing_table = registry.routing_table();
        let peer_a = node_a(&routing_table);

        let expired_b = peer_info(
            &routing_table,
            false,
            vec![
                direct(DialInfo::udp(node_b_socket_address())),
                direct(DialInfo::tcp(node_b_socket_address())),
                webtransport_dial_info_detail(EXPIRED),
            ],
        );
        let protocol_types =
            direct_protocol_types(&contact_methods(&routing_table, peer_a.clone(), expired_b));
        assert!(
            protocol_types.contains(&ProtocolType::TCP),
            "TCP must still be offered: {protocol_types:?}"
        );
        assert!(
            !protocol_types.contains(&ProtocolType::WTS),
            "a WebTransport dial info past its expiration must not be offered: {protocol_types:?}"
        );

        let current_b = peer_info(
            &routing_table,
            false,
            vec![
                direct(DialInfo::udp(node_b_socket_address())),
                direct(DialInfo::tcp(node_b_socket_address())),
                webtransport_dial_info_detail(UNEXPIRED),
            ],
        );
        let protocol_types =
            direct_protocol_types(&contact_methods(&routing_table, peer_a, current_b));
        assert!(
            protocol_types.contains(&ProtocolType::WTS),
            "the same dial info within its expiration must be offered: {protocol_types:?}"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_peer_with_only_expired_dial_info_has_no_direct_contact() {
    let registry = mock_registry::init("contact_method_all_expired").await;
    {
        let routing_table = registry.routing_table();
        let peer_a = node_a(&routing_table);
        let peer_b = peer_info(
            &routing_table,
            false,
            vec![webtransport_dial_info_detail(EXPIRED)],
        );

        let out = contact_methods(&routing_table, peer_a, peer_b);
        assert!(
            out.is_empty(),
            "a peer whose every dial info has expired cannot be contacted directly: {out:?}"
        );
    }
    mock_registry::terminate(registry).await;
}
