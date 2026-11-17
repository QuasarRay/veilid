//! When a node detects its PublicInternet dial info and when it states it itself.

use super::*;
use crate::tests::*;

fn interface(ip: &str) -> IfAddr {
    match ip.parse().expect("test address") {
        IpAddr::V4(ip) => IfAddr::V4(Ifv4Addr {
            ip,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: None,
        }),
        IpAddr::V6(ip) => IfAddr::V6(Ifv6Addr {
            ip,
            netmask: Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
            broadcast: None,
        }),
    }
}

fn configured(dial_infos: &[DialInfo]) -> BTreeSet<DialInfoDetail> {
    dial_infos
        .iter()
        .map(|dial_info| DialInfoDetail {
            dial_info: dial_info.clone(),
            class: DialInfoClass::Direct,
        })
        .collect()
}

fn udp(socket_addr: &str) -> DialInfo {
    DialInfo::udp_from_socketaddr(socket_addr.parse().expect("test address"))
}

fn tcp(socket_addr: &str) -> DialInfo {
    DialInfo::tcp_from_socketaddr(socket_addr.parse().expect("test address"))
}

fn v4() -> AddressTypeSet {
    AddressTypeSet::only(AddressType::IPV4)
}

/// A global address on an interface states a family's dial info, a private one does not
fn test_global_interface_address_needs_no_detection() {
    let inbound = ProtocolType::UDP | ProtocolType::TCP;
    let none = BTreeSet::new();
    let public = [interface("8.8.8.8"), interface("2001:4860:4860::8888")];
    assert!(families_needing_detection(AddressTypeSet::all(), &public, inbound, &none).is_empty());

    let natted = [interface("192.168.1.20"), interface("2001:4860:4860::8888")];
    assert_eq!(
        families_needing_detection(AddressTypeSet::all(), &natted, inbound, &none),
        v4()
    );
    // A family the node does not use is never detected
    assert!(families_needing_detection(
        AddressTypeSet::only(AddressType::IPV6),
        &natted,
        inbound,
        &none
    )
    .is_empty());
}

/// Behind a 1:1 NAT a configured public address states the dial info, once every inbound
/// protocol has one in that family
fn test_configured_public_address_needs_no_detection() {
    let inbound = ProtocolType::UDP | ProtocolType::TCP;
    let natted = [interface("10.0.0.20")];

    let both = configured(&[udp("8.8.8.8:5150"), tcp("8.8.8.8:5150")]);
    assert!(families_needing_detection(v4(), &natted, inbound, &both).is_empty());

    let udp_only = configured(&[udp("8.8.8.8:5150")]);
    assert_eq!(
        families_needing_detection(v4(), &natted, inbound, &udp_only),
        v4()
    );

    // An address of the other family says nothing about this one
    let other_family = configured(&[
        udp("[2001:4860:4860::8888]:5150"),
        tcp("[2001:4860:4860::8888]:5150"),
    ]);
    assert_eq!(
        families_needing_detection(v4(), &natted, inbound, &other_family),
        v4()
    );

    // A node that listens on nothing has no dial info to state
    assert_eq!(
        families_needing_detection(v4(), &natted, ProtocolTypeSet::new(), &both),
        v4()
    );
}

/// The node attached with `config`, its network up
async fn started_node(config: VeilidConfig, update_callback: UpdateCallback) -> VeilidAPI {
    let api = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api.attach().await.unwrap();
    while !api.get_state().await.unwrap().network.started {
        sleep(100).await;
    }
    api
}

/// Whether the node's PublicInternet dial info stands confirmed
fn public_internet_confirmed(registry: &VeilidComponentRegistry) -> bool {
    let routing_table = registry.routing_table();
    let controller = routing_table.get_routing_domain_controller(RoutingDomain::PublicInternet);
    let confirmed = controller.read_dyn().confirmed();
    confirmed
}

/// A node with a configured public address for every inbound protocol states its dial info
/// itself: `auto` detects nothing, and an emptied connection table asks for no confirmation,
/// which a network with no validators yet could not give
async fn test_static_public_addresses_need_no_validators() {
    let (update_callback, mut config) = fixture_veilid_core();
    config.network.detect_address_changes = None;
    config.network.routing_table.bootstrap = vec![];
    config.network.address_types = vec![VeilidConfigAddressType::Ipv4];
    config.network.protocol.udp.public_address = Some("8.8.8.8:5150".to_owned());
    config.network.protocol.tcp.public_address = Some("8.8.8.8:5150".to_owned());
    config.network.protocol.ws.listen = false;
    #[cfg(feature = "enable-protocol-wss")]
    {
        config.network.protocol.wss.listen = false;
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    {
        config.network.protocol.webtransport.listen = false;
    }
    let api = started_node(config, update_callback).await;

    let registry = api.core_context().expect("api not started").registry();
    let net = registry.network_manager().net();
    assert!(!net
        .routing_domains_detecting_address_changes()
        .contains(&RoutingDomain::PublicInternet));
    assert!(public_internet_confirmed(&registry));
    assert!(!net.request_confirm_after_empty_table());
    assert!(public_internet_confirmed(&registry));

    api.shutdown().await;
}

/// With detection ruled out by config, neither an emptied connection table nor a direct
/// request unconfirms the dial info the node started with
async fn test_detection_ruled_out_keeps_dial_info_confirmed() {
    let (update_callback, mut config) = fixture_veilid_core();
    config.network.detect_address_changes = Some(false);
    config.network.routing_table.bootstrap = vec![];
    let api = started_node(config, update_callback).await;

    let registry = api.core_context().expect("api not started").registry();
    let net = registry.network_manager().net();
    assert!(public_internet_confirmed(&registry));
    assert!(!net.request_confirm_after_empty_table());
    assert!(!net.routing_domain_request_confirm_dial_info(RoutingDomain::PublicInternet));
    assert!(public_internet_confirmed(&registry));

    api.shutdown().await;
}

pub async fn test_all() {
    test_global_interface_address_needs_no_detection();
    test_configured_public_address_needs_no_detection();
    test_static_public_addresses_need_no_validators().await;
    test_detection_ruled_out_keeps_dial_info_confirmed().await;
}
