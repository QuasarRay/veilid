use super::*;
use crate::tests::*;

/// A bootstrap url is dialed only over a protocol in the node's outbound set, which is where a
/// browser page's limits land
pub async fn test_bootstrap_url_follows_outbound_protocols() {
    let registry = mock_registry::init("rt_bootstrap_url_outbound").await;
    let routing_table = registry.routing_table();
    let controller = routing_table
        .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
    let mut editor = controller.edit();
    editor.set_network_config(RoutingDomainNetworkConfig::new(
        ProtocolType::TCP.into(),
        ProtocolTypeSet::new(),
        AddressTypeSet::all(),
        PUBLIC_INTERNET_CAPABILITIES.iter().copied().collect(),
    ));
    editor.commit();

    assert!(controller
        .bootstrap_target("ws://192.0.2.1:5150/ws".to_owned())
        .await
        .is_none());

    let target = controller
        .bootstrap_target("tcp://192.0.2.1:5150".to_owned())
        .await
        .expect("a url over an outbound protocol");
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 5150);
    assert_eq!(
        target.groups,
        vec![vec![DialInfo::tcp_from_socketaddr(socket_addr)]]
    );

    mock_registry::terminate(registry).await;
}

/// A node short of peers bootstraps every tick: a round is announced when its bootstrap peers
/// differ from the last announced round's, and again once the node has left the bootstrap stage
pub fn test_bootstrap_round_is_announced_once_per_peer_set() {
    let mut announced = None;
    assert!(bootstrap_peers_are_news(&mut announced, "A,B"));
    assert!(!bootstrap_peers_are_news(&mut announced, "A,B"));
    assert!(bootstrap_peers_are_news(&mut announced, "A"));
    assert!(!bootstrap_peers_are_news(&mut announced, "A"));

    announced.take();
    assert!(bootstrap_peers_are_news(&mut announced, "A"));
}
