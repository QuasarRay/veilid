use super::*;
use crate::routing_table::*;
use crate::tests::*;

fn our_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 160)), 5150)
}

fn valid_dial_info_detail() -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::udp(our_socket_address()),
    }
}

fn invalid_ws_dial_info_detail() -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::WS(DialInfoWS {
            socket_address: our_socket_address(),
            request: "18.218.0.160:9999/ws".to_string(),
        }),
    }
}

#[cfg(feature = "enable-protocol-webtransport")]
fn invalid_webtransport_dial_info_detail() -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::WebTransportStream(Box::new(DialInfoWebTransport {
            socket_address: our_socket_address(),
            request: "https://18.218.0.99:5150/".to_string(),
            cert_hashes: vec![[1u8; 32]],
            expiration: None,
        })),
    }
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

pub fn test_dial_info_validate_is_per_kind() {
    assert!(
        valid_dial_info_detail().dial_info.validate().is_ok(),
        "a dial info its own constructor would accept is valid"
    );
    assert!(
        DialInfo::try_ws(
            our_socket_address(),
            "ws://18.218.0.160:5150/ws".to_string()
        )
        .expect("should build ws dial info")
        .validate()
        .is_ok(),
        "a WS dial info whose request URL agrees with its socket address is valid"
    );

    let invalid_ws = invalid_ws_dial_info_detail().dial_info;
    assert!(
        invalid_ws.is_valid(),
        "the malformed WS dial info passes the shared address and port check, so only its own \
         kind's rules can catch it"
    );
    assert!(
        invalid_ws.validate().is_err(),
        "a WS dial info whose request URL contradicts its socket address is invalid"
    );

    #[cfg(feature = "enable-protocol-webtransport")]
    {
        let invalid_wt = invalid_webtransport_dial_info_detail().dial_info;
        assert!(
            invalid_wt.is_valid(),
            "the malformed WebTransport dial info also passes the shared check"
        );
        assert!(
            invalid_wt.validate().is_err(),
            "a WebTransport dial info whose URL host contradicts its socket address is invalid"
        );
    }
}

#[cfg(feature = "enable-protocol-webtransport")]
fn cert_expiration(offset_days: u64) -> Option<Timestamp> {
    Some(Timestamp::new(
        1_700_000_000_000_000 + offset_days * 86_400_000_000,
    ))
}

#[cfg(feature = "enable-protocol-webtransport")]
fn webtransport_dial_info_detail(expiration: Option<Timestamp>) -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::try_webtransport_stream(
            our_socket_address(),
            "https://18.218.0.160:5150/".to_string(),
            vec![[1u8; 32]],
            expiration,
        )
        .expect("should build wts dial info"),
    }
}

#[cfg(feature = "enable-protocol-webtransport")]
pub async fn test_published_peer_info_expires_with_its_dial_info() {
    let registry = mock_registry::init("publish_peer_info_expiration").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        seed_dial_info(&routing_table, vec![valid_dial_info_detail()]);
        make_public_internet_ready_to_publish(&routing_table);
        assert!(controller.publish_peer_info(), "should publish");
        assert_eq!(
            controller
                .get_published_peer_info()
                .expect("peer info is published")
                .node_info()
                .expiration(),
            None,
            "peer info advertising nothing that expires must carry no expiration"
        );

        seed_dial_info(
            &routing_table,
            vec![
                valid_dial_info_detail(),
                webtransport_dial_info_detail(cert_expiration(7)),
            ],
        );
        assert!(controller.publish_peer_info(), "should republish");
        assert_eq!(
            controller
                .get_published_peer_info()
                .expect("peer info is published")
                .node_info()
                .expiration(),
            cert_expiration(7),
            "peer info carrying a WebTransport dial info must expire with that dial info"
        );

        seed_dial_info(&routing_table, vec![valid_dial_info_detail()]);
        assert!(controller.publish_peer_info(), "should republish");
        assert_eq!(
            controller
                .get_published_peer_info()
                .expect("peer info is published")
                .node_info()
                .expiration(),
            None,
            "dropping the expiring dial info must drop the expiration with it"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_publish_refuses_invalid_dial_info() {
    let registry = mock_registry::init("publish_invalid_di").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        seed_dial_info(&routing_table, vec![valid_dial_info_detail()]);
        make_public_internet_ready_to_publish(&routing_table);
        assert!(
            controller.publish_peer_info(),
            "precondition: valid peer info publishes"
        );
        let published_before = controller
            .get_published_peer_info()
            .expect("precondition: peer info is published");

        seed_dial_info(
            &routing_table,
            vec![valid_dial_info_detail(), invalid_ws_dial_info_detail()],
        );
        assert!(
            !controller.publish_peer_info(),
            "peer info advertising a dial info that fails its own kind's rules must not publish"
        );

        let published_after = controller
            .get_published_peer_info()
            .expect("the previous publication must stand after a refusal");
        assert!(
            published_after.equivalent(&published_before),
            "a refusal keeps the previously published peer info, it does not unpublish or \
             publish a stripped subset"
        );
    }
    mock_registry::terminate(registry).await;
}

#[cfg(feature = "enable-protocol-webtransport")]
pub async fn test_publish_refuses_invalid_webtransport_dial_info() {
    let registry = mock_registry::init("publish_invalid_wt_di").await;
    {
        let routing_table = registry.routing_table();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();

        seed_dial_info(&routing_table, vec![valid_dial_info_detail()]);
        make_public_internet_ready_to_publish(&routing_table);
        assert!(
            controller.publish_peer_info(),
            "precondition: valid peer info publishes"
        );
        let published_before = controller
            .get_published_peer_info()
            .expect("precondition: peer info is published");

        seed_dial_info(
            &routing_table,
            vec![
                valid_dial_info_detail(),
                invalid_webtransport_dial_info_detail(),
            ],
        );
        assert!(
            !controller.publish_peer_info(),
            "peer info advertising a WebTransport dial info whose URL contradicts its socket \
             address must not publish"
        );
        assert!(
            controller
                .get_published_peer_info()
                .expect("the previous publication must stand after a refusal")
                .equivalent(&published_before),
            "a refusal keeps the previously published peer info"
        );
    }
    mock_registry::terminate(registry).await;
}
