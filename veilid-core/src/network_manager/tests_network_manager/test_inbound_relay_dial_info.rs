//! A node that requires an inbound relay keeps its own addresses out of its PublicInternet dial info.

use super::*;
use crate::network_manager::network::native::network_state::{
    AddressConfig, NetworkState, ProtocolConfig,
};
use crate::network_manager::network::native::NativeNetwork;
use crate::tests::*;

/// The static public address every protocol is configured with.
const STATIC_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
/// A globally routable address on a synthetic interface.
const GLOBAL_IP: Ipv4Addr = Ipv4Addr::new(5, 6, 7, 8);
/// A private address on a synthetic interface.
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

const UDP_PORT: u16 = 5150;
const TCP_PORT: u16 = 5151;
const WS_PORT: u16 = 5152;
#[cfg(feature = "enable-protocol-wss")]
const WSS_PORT: u16 = 5153;
#[cfg(feature = "enable-protocol-webtransport")]
const WT_PORT: u16 = 5154;

/// Gives every protocol that has one a static public address at `STATIC_IP`.
fn configure_static_addresses(config: &mut VeilidConfig, require_inbound_relay: bool) {
    config.network.privacy.require_inbound_relay = require_inbound_relay;
    config.network.protocol.udp.public_address = Some(format!("{STATIC_IP}:{UDP_PORT}"));
    config.network.protocol.tcp.public_address = Some(format!("{STATIC_IP}:{TCP_PORT}"));
    config.network.protocol.ws.url = Some(format!("ws://{STATIC_IP}:{WS_PORT}/ws"));
    #[cfg(feature = "enable-protocol-wss")]
    {
        config.network.protocol.wss.url = Some(format!("wss://{STATIC_IP}:{WSS_PORT}/ws"));
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    {
        config.network.protocol.webtransport.listen = true;
    }
}

/// A network state whose interfaces hold one global and one private IPv4 address.
fn synthetic_network_state(registry: &VeilidComponentRegistry) -> NetworkState {
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let interface_address_state = NetworkInterfaceAddressState {
        interface_addresses: vec![
            IfAddr::V4(Ifv4Addr {
                ip: GLOBAL_IP,
                netmask,
                broadcast: None,
            }),
            IfAddr::V4(Ifv4Addr {
                ip: LOCAL_IP,
                netmask,
                broadcast: None,
            }),
        ],
        ..Default::default()
    };
    NetworkState::new(
        registry.clone(),
        ProtocolConfig::default(),
        AddressConfig {
            ipv4_local: true,
            ipv4_global: true,
            ipv6_local: false,
            ipv6_global: false,
        },
        Arc::new(interface_address_state),
        BTreeSet::new(),
    )
}

/// A wildcard bind, which the network state translates to every interface address.
fn unspecified(port: u16) -> [SocketAddr; 1] {
    [SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)]
}

/// Runs every protocol's dial info registration against one synthetic network state.
async fn register_dial_info(namespace: &str, require_inbound_relay: bool) -> NetworkState {
    let registry = mock_registry::init_with_config(namespace, |config| {
        configure_static_addresses(config, require_inbound_relay);
        #[cfg(feature = "enable-protocol-webtransport")]
        {
            config.network.protocol.webtransport.url = None;
        }
    })
    .await;
    let mut network_state = synthetic_network_state(&registry);
    {
        let net = NativeNetwork::new(registry.clone());
        let config = registry.config();
        net.add_udp_interface_dial_info(config.clone(), &unspecified(UDP_PORT), &mut network_state)
            .expect("udp dial info");
        net.add_tcp_interface_dial_info(config.clone(), &unspecified(TCP_PORT), &mut network_state)
            .expect("tcp dial info");
        net.add_ws_interface_dial_info(config.clone(), &unspecified(WS_PORT), &mut network_state)
            .expect("ws dial info");
        #[cfg(feature = "enable-protocol-wss")]
        net.add_wss_interface_dial_info(config.clone(), &unspecified(WSS_PORT), &mut network_state)
            .expect("wss dial info");
        #[cfg(feature = "enable-protocol-webtransport")]
        {
            net.startup_certificate_manager()
                .await
                .expect("self-signed webtransport certificate");
            net.add_wt_interface_dial_info(&unspecified(WT_PORT), &mut network_state)
                .expect("webtransport interface dial info");
        }
    }
    mock_registry::terminate(registry).await;

    // A CA-signed WebTransport URL is WebTransport's static address, and it needs its own config
    #[cfg(feature = "enable-protocol-webtransport")]
    {
        let registry = mock_registry::init_with_config(format!("{namespace}_ca"), |config| {
            configure_static_addresses(config, require_inbound_relay);
            config.network.protocol.webtransport.url =
                Some(format!("https://{STATIC_IP}:{WT_PORT}/"));
        })
        .await;
        {
            let net = NativeNetwork::new(registry.clone());
            net.add_wt_url_dial_info(&unspecified(WT_PORT), &mut network_state)
                .expect("webtransport url dial info");
        }
        mock_registry::terminate(registry).await;
    }

    network_state
}

/// The static and interface dial info a routing domain would be given.
fn dial_info(
    network_state: &NetworkState,
    routing_domain: RoutingDomain,
) -> BTreeSet<DialInfoDetail> {
    let rd_network_state = network_state
        .routing_domain_network_states
        .get(&routing_domain)
        .expect("routing domain network state");
    rd_network_state
        .static_dial_info_details
        .union(&rd_network_state.interface_dial_info_details)
        .cloned()
        .collect()
}

/// Each dial info's protocol and socket address, leaving out certificate hashes that differ per run.
fn endpoints(dial_info_details: &BTreeSet<DialInfoDetail>) -> BTreeSet<(ProtocolType, SocketAddr)> {
    dial_info_details
        .iter()
        .map(|did| {
            (
                did.dial_info.protocol_type(),
                did.dial_info.to_socket_addr(),
            )
        })
        .collect()
}

/// The protocols that have dial info at `ip`.
fn protocols_at(dial_info_details: &BTreeSet<DialInfoDetail>, ip: Ipv4Addr) -> ProtocolTypeSet {
    let mut out = ProtocolTypeSet::new();
    for did in dial_info_details {
        if did.dial_info.to_socket_addr().ip() == IpAddr::V4(ip) {
            out.insert(did.dial_info.protocol_type());
        }
    }
    out
}

fn static_address_protocols() -> ProtocolTypeSet {
    let mut out = ProtocolTypeSet::new();
    out.insert(ProtocolType::UDP);
    out.insert(ProtocolType::TCP);
    out.insert(ProtocolType::WS);
    #[cfg(feature = "enable-protocol-wss")]
    out.insert(ProtocolType::WSS);
    #[cfg(feature = "enable-protocol-webtransport")]
    out.insert_all(WEBTRANSPORT_PROTOCOL_TYPES);
    out
}

fn interface_address_protocols() -> ProtocolTypeSet {
    let mut out = ProtocolTypeSet::new();
    out.insert(ProtocolType::UDP);
    out.insert(ProtocolType::TCP);
    out.insert(ProtocolType::WS);
    #[cfg(feature = "enable-protocol-webtransport")]
    out.insert_all(WEBTRANSPORT_PROTOCOL_TYPES);
    out
}

/// Without the flag, the static and global interface addresses reach PublicInternet, which
/// shows the inputs of the next test are ones that would be published.
pub async fn test_own_addresses_reach_public_internet_without_inbound_relay() {
    let network_state = register_dial_info("inbound_relay_dial_info_off", false).await;
    let public_internet = dial_info(&network_state, RoutingDomain::PublicInternet);
    assert_eq!(
        protocols_at(&public_internet, STATIC_IP),
        static_address_protocols(),
        "every static public address is PublicInternet dial info: {public_internet:?}"
    );
    assert_eq!(
        protocols_at(&public_internet, GLOBAL_IP),
        interface_address_protocols(),
        "every global interface address is PublicInternet dial info: {public_internet:?}"
    );
}

/// With the flag, no static or global interface address reaches PublicInternet, and
/// LocalNetwork keeps the same dial info it has without the flag.
pub async fn test_require_inbound_relay_withholds_own_public_internet_dial_info() {
    let network_state = register_dial_info("inbound_relay_dial_info_on", true).await;
    let public_internet = dial_info(&network_state, RoutingDomain::PublicInternet);
    assert!(
        public_internet.is_empty(),
        "require_inbound_relay must keep the node's own addresses out of PublicInternet: {public_internet:?}"
    );

    let local_network = dial_info(&network_state, RoutingDomain::LocalNetwork);
    assert_eq!(
        protocols_at(&local_network, LOCAL_IP),
        interface_address_protocols(),
        "the private interface address is still LocalNetwork dial info: {local_network:?}"
    );
    let without_flag = register_dial_info("inbound_relay_dial_info_on_control", false).await;
    assert_eq!(
        endpoints(&local_network),
        endpoints(&dial_info(&without_flag, RoutingDomain::LocalNetwork)),
        "require_inbound_relay leaves LocalNetwork dial info unchanged"
    );
}

pub async fn test_all() {
    test_own_addresses_reach_public_internet_without_inbound_relay().await;
    test_require_inbound_relay_withholds_own_public_internet_dial_info().await;
}
