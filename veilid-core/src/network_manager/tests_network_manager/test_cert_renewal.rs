use super::*;
use crate::network_manager::network::native::certificate_manager::CertificateAdvertisement;
use crate::network_manager::network::native::webtransport_listener::restamp_webtransport_dial_info;
use crate::routing_table::tests_routing_table::make_public_internet_ready_to_publish;
use crate::tests::*;

fn our_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 160)), 5150)
}

fn nat_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(52, 10, 20, 30)), 41000)
}

fn cert_expiration(hash_byte: u8) -> Option<Timestamp> {
    Some(Timestamp::new(
        1_700_000_000_000_000 + u64::from(hash_byte) * 86_400_000_000,
    ))
}

fn webtransport_dial_info_details(hash_byte: u8) -> Vec<DialInfoDetail> {
    let socket_address = our_socket_address();
    let url = "https://18.218.0.160:5150/".to_string();
    let hashes = vec![[hash_byte; 32]];
    let expiration = cert_expiration(hash_byte);
    vec![
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_stream(
                socket_address,
                url.clone(),
                hashes.clone(),
                expiration,
            )
            .expect("should build wts dial info"),
        },
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_datagram(socket_address, url, hashes, expiration)
                .expect("should build wtd dial info"),
        },
    ]
}

fn nat_webtransport_dial_info_details(hash_byte: u8) -> Vec<DialInfoDetail> {
    let socket_address = nat_socket_address();
    let url = "https://52.10.20.30:41000/".to_string();
    let hashes = vec![[hash_byte; 32]];
    let expiration = cert_expiration(hash_byte);
    vec![
        DialInfoDetail {
            class: DialInfoClass::FullConeNAT,
            dial_info: DialInfo::try_webtransport_stream(
                socket_address,
                url.clone(),
                hashes.clone(),
                expiration,
            )
            .expect("should build nat wts dial info"),
        },
        DialInfoDetail {
            class: DialInfoClass::FullConeNAT,
            dial_info: DialInfo::try_webtransport_datagram(socket_address, url, hashes, expiration)
                .expect("should build nat wtd dial info"),
        },
    ]
}

fn cert_advertisement(hash_byte: u8) -> CertificateAdvertisement {
    CertificateAdvertisement {
        cert_hashes: vec![[hash_byte; 32]],
        expiration: cert_expiration(hash_byte),
    }
}

fn assert_restamped_entry(
    dial_info_details: &[DialInfoDetail],
    class: DialInfoClass,
    protocol_type: ProtocolType,
    socket_address: SocketAddress,
    hash_byte: u8,
) {
    let opt_did = dial_info_details.iter().find(|did| {
        did.class == class
            && did.dial_info.protocol_type() == protocol_type
            && did.dial_info.socket_address() == socket_address
    });
    let Some(did) = opt_did else {
        panic!("expected a {class:?} {protocol_type:?} entry at {socket_address}: {dial_info_details:?}");
    };
    let (DialInfo::WebTransportStream(di) | DialInfo::WebTransportDatagram(di)) = &did.dial_info
    else {
        panic!("expected WebTransport dial info: {did:?}");
    };
    assert_eq!(
        di.cert_hashes,
        vec![[hash_byte; 32]],
        "the entry must carry the renewed certificate hashes"
    );
    assert_eq!(
        di.expiration,
        cert_expiration(hash_byte),
        "the entry must carry the renewed certificate window"
    );
}

fn udp_dial_info_detail() -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::udp(our_socket_address()),
    }
}

fn committed_cert_hashes(routing_table: &RoutingTable) -> Vec<Vec<[u8; 32]>> {
    routing_table
        .dial_info_details(RoutingDomain::PublicInternet)
        .iter()
        .filter_map(|did| match &did.dial_info {
            DialInfo::WebTransportStream(di) | DialInfo::WebTransportDatagram(di) => {
                Some(di.cert_hashes.clone())
            }
            _ => None,
        })
        .collect()
}

fn published_cert_hashes(peer_info: &PeerInfo) -> Vec<Vec<[u8; 32]>> {
    peer_info
        .node_info()
        .dial_info_detail_list()
        .iter()
        .filter_map(|did| match &did.dial_info {
            DialInfo::WebTransportStream(di) | DialInfo::WebTransportDatagram(di) => {
                Some(di.cert_hashes.clone())
            }
            _ => None,
        })
        .collect()
}

fn seed_dial_info(routing_table: &RoutingTable, dial_info_details: Vec<DialInfoDetail>) {
    let controller = routing_table
        .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
    let mut editor = controller.edit();
    editor.clear_dial_info_details(None, None);
    for did in dial_info_details {
        editor.add_dial_info_detail(did);
    }
    editor.commit();
}

/// A node behind NAT learns its WebTransport dial info from dial info confirmation, at a mapped
/// address and with a NAT class. Renewal restamps whatever the domain advertises, so those
/// entries keep their class, address and URL and gain the new certificate.
pub fn test_restamp_keeps_discovered_dial_info() {
    let mut webtransport_seeded = nat_webtransport_dial_info_details(1);
    webtransport_seeded.extend(webtransport_dial_info_details(1));
    let mut seeded = webtransport_seeded.clone();
    seeded.push(udp_dial_info_detail());

    let restamped = restamp_webtransport_dial_info(&seeded, &cert_advertisement(2));

    assert_eq!(
        restamped.len(),
        webtransport_seeded.len(),
        "restamping returns every WebTransport entry and nothing else: {restamped:?}"
    );
    assert!(
        !restamped.contains(&udp_dial_info_detail()),
        "restamping must not return dial info of other protocols: {restamped:?}"
    );

    for (before, after) in webtransport_seeded.iter().zip(restamped.iter()) {
        assert_eq!(after.class, before.class, "the class is left alone");
        assert_eq!(
            after.dial_info.protocol_type(),
            before.dial_info.protocol_type(),
            "the protocol type is left alone"
        );
        assert_eq!(
            after.dial_info.socket_address(),
            before.dial_info.socket_address(),
            "the socket address is left alone"
        );
        assert_eq!(
            after.dial_info.request(),
            before.dial_info.request(),
            "the request url is left alone"
        );
    }

    for protocol_type in [ProtocolType::WTS, ProtocolType::WTD] {
        assert_restamped_entry(
            &restamped,
            DialInfoClass::FullConeNAT,
            protocol_type,
            nat_socket_address(),
            2,
        );
        assert_restamped_entry(
            &restamped,
            DialInfoClass::Direct,
            protocol_type,
            our_socket_address(),
            2,
        );
    }
}

/// Rebuilding the renewed list from this node's static and interface addresses drops the
/// NAT-discovered entries, and dial info confirmation does not run again while other dial info
/// remains, so the node would stop advertising WebTransport entirely.
pub async fn test_renewal_keeps_discovered_dial_info_through_the_routing_table() {
    let registry = mock_registry::init("cert_renewal_nat_discovered").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        let mut seeded = nat_webtransport_dial_info_details(1);
        seeded.extend(webtransport_dial_info_details(1));
        seeded.push(udp_dial_info_detail());
        seed_dial_info(&routing_table, seeded);
        make_public_internet_ready_to_publish(&routing_table);
        assert!(
            controller.publish_peer_info(),
            "precondition: the domain publishes peer info once it is ready"
        );

        let renewed = restamp_webtransport_dial_info(
            &routing_table.dial_info_details(RoutingDomain::PublicInternet),
            &cert_advertisement(2),
        );
        assert!(
            routing_table.renew_dial_info_details(
                RoutingDomain::PublicInternet,
                WEBTRANSPORT_PROTOCOL_TYPES,
                renewed,
            ),
            "a renewal must republish peer info that was already published"
        );

        let committed = routing_table.dial_info_details(RoutingDomain::PublicInternet);
        let published = controller
            .get_published_peer_info()
            .expect("peer info is still published after the renewal");
        for dial_info_details in [
            committed.as_slice(),
            published.node_info().dial_info_detail_list(),
        ] {
            for protocol_type in [ProtocolType::WTS, ProtocolType::WTD] {
                assert_restamped_entry(
                    dial_info_details,
                    DialInfoClass::FullConeNAT,
                    protocol_type,
                    nat_socket_address(),
                    2,
                );
                assert_restamped_entry(
                    dial_info_details,
                    DialInfoClass::Direct,
                    protocol_type,
                    our_socket_address(),
                    2,
                );
            }
            assert!(
                dial_info_details.contains(&udp_dial_info_detail()),
                "a WebTransport renewal must leave other protocols' dial info in place: {dial_info_details:?}"
            );
        }
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_renewal_commits_without_publishing_unpublished_peer_info() {
    let registry = mock_registry::init("cert_renewal_unpublished").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        seed_dial_info(&routing_table, webtransport_dial_info_details(1));
        assert!(
            controller.get_published_peer_info().is_none(),
            "precondition: this domain has not published peer info"
        );

        let republished = routing_table.renew_dial_info_details(
            RoutingDomain::PublicInternet,
            WEBTRANSPORT_PROTOCOL_TYPES,
            webtransport_dial_info_details(2),
        );

        assert!(
            !republished,
            "a renewal must not publish peer info that was not already published"
        );
        assert!(
            controller.get_published_peer_info().is_none(),
            "a renewal must never turn unpublished peer info into published peer info"
        );
        assert_eq!(
            committed_cert_hashes(&routing_table),
            vec![vec![[2u8; 32]], vec![[2u8; 32]]],
            "the renewal must still commit the rehashed dial info, published or not"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_renewal_republishes_published_peer_info() {
    let registry = mock_registry::init("cert_renewal_published").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        seed_dial_info(&routing_table, webtransport_dial_info_details(1));
        make_public_internet_ready_to_publish(&routing_table);
        assert!(
            controller.publish_peer_info(),
            "precondition: the domain publishes peer info once it is ready"
        );
        let published_before = controller
            .get_published_peer_info()
            .expect("precondition: peer info is published");

        let republished = routing_table.renew_dial_info_details(
            RoutingDomain::PublicInternet,
            WEBTRANSPORT_PROTOCOL_TYPES,
            webtransport_dial_info_details(2),
        );

        assert!(
            republished,
            "a renewal must republish peer info that was already published"
        );
        let published_after = controller
            .get_published_peer_info()
            .expect("peer info is still published after the renewal");
        assert!(
            !published_after.equivalent(&published_before),
            "the republished peer info must carry the rotated certificate hashes"
        );
        assert_eq!(
            published_cert_hashes(&published_after),
            vec![vec![[2u8; 32]], vec![[2u8; 32]]],
            "the published peer info advertises the new hashes"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_renewal_leaves_other_dial_info_and_confirmation_alone() {
    let registry = mock_registry::init("cert_renewal_narrow").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        let mut seeded = webtransport_dial_info_details(1);
        seeded.push(udp_dial_info_detail());
        seed_dial_info(&routing_table, seeded);
        make_public_internet_ready_to_publish(&routing_table);
        assert!(
            controller.read_dyn().confirmed(),
            "precondition: this domain's dial info is confirmed"
        );

        routing_table.renew_dial_info_details(
            RoutingDomain::PublicInternet,
            WEBTRANSPORT_PROTOCOL_TYPES,
            webtransport_dial_info_details(2),
        );

        assert!(
            controller.read_dyn().confirmed(),
            "a renewal must leave dial info confirmation alone"
        );
        let committed = routing_table.dial_info_details(RoutingDomain::PublicInternet);
        assert!(
            committed.contains(&udp_dial_info_detail()),
            "a WebTransport renewal must leave other protocols' dial info in place: {committed:?}"
        );
        assert_eq!(
            committed_cert_hashes(&routing_table),
            vec![vec![[2u8; 32]], vec![[2u8; 32]]],
            "only the WebTransport dial info is replaced, and it carries the new hashes"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_renewal_refreshes_published_expiration() {
    let registry = mock_registry::init("cert_renewal_expiration").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        seed_dial_info(&routing_table, webtransport_dial_info_details(1));
        make_public_internet_ready_to_publish(&routing_table);
        assert!(
            controller.publish_peer_info(),
            "precondition: the domain publishes peer info once it is ready"
        );
        assert_eq!(
            controller
                .get_published_peer_info()
                .expect("precondition: peer info is published")
                .node_info()
                .expiration(),
            cert_expiration(1),
            "precondition: the published peer info expires with the certificate it advertises"
        );

        routing_table.renew_dial_info_details(
            RoutingDomain::PublicInternet,
            WEBTRANSPORT_PROTOCOL_TYPES,
            webtransport_dial_info_details(2),
        );

        assert_eq!(
            controller
                .get_published_peer_info()
                .expect("peer info is still published after the renewal")
                .node_info()
                .expiration(),
            cert_expiration(2),
            "the renewal must republish with the new certificate's window, not the old one"
        );
    }
    mock_registry::terminate(registry).await;
}

/// A node with a static public address has address-change detection auto-disabled, so its dial
/// info is confirmed at startup and the dial info confirmation task never runs for it. Those are
/// exactly the nodes that serve rotated self-signed certificates, so the renewal is the only
/// thing that can carry a rotated hash into their routing domain.
pub async fn test_renewal_reaches_a_domain_with_detection_disabled() {
    let registry = mock_registry::init("cert_renewal_no_detection").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        seed_dial_info(&routing_table, webtransport_dial_info_details(1));
        make_public_internet_ready_to_publish(&routing_table);
        assert!(
            controller.publish_peer_info(),
            "precondition: the domain publishes peer info once it is ready"
        );
        assert!(
            !matches!(
                controller.state().inbound_stage,
                RoutingDomainInboundStage::NeedsDialInfoConfirmation
            ),
            "precondition: a detection-disabled domain is confirmed at startup, so it never asks for dial info confirmation"
        );

        routing_table.renew_dial_info_details(
            RoutingDomain::PublicInternet,
            WEBTRANSPORT_PROTOCOL_TYPES,
            webtransport_dial_info_details(2),
        );

        assert_eq!(
            committed_cert_hashes(&routing_table),
            vec![vec![[2u8; 32]], vec![[2u8; 32]]],
            "the renewal alone must commit the rotated hashes, with no detection pass to do it"
        );
        assert_eq!(
            published_cert_hashes(
                &controller
                    .get_published_peer_info()
                    .expect("peer info is still published after the renewal")
            ),
            vec![vec![[2u8; 32]], vec![[2u8; 32]]],
            "the renewal alone must republish the rotated hashes"
        );
        assert!(
            !matches!(
                controller.state().inbound_stage,
                RoutingDomainInboundStage::NeedsDialInfoConfirmation
            ),
            "the renewal must not push a detection-disabled domain back into dial info confirmation"
        );
        assert!(
            controller.read_dyn().confirmed(),
            "the renewal must leave the startup confirmation in place"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_all() {
    test_restamp_keeps_discovered_dial_info();
    test_renewal_keeps_discovered_dial_info_through_the_routing_table().await;
    test_renewal_commits_without_publishing_unpublished_peer_info().await;
    test_renewal_republishes_published_peer_info().await;
    test_renewal_leaves_other_dial_info_and_confirmation_alone().await;
    test_renewal_refreshes_published_expiration().await;
    test_renewal_reaches_a_domain_with_detection_disabled().await;
}
