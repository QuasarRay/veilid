//! A node started with `privacy.require_inbound_relay` puts none of its own addresses in its PublicInternet dial info.

use super::*;
use crate::routing_table::*;

const POLL_MS: u32 = 500;
/// Long enough for the network interfaces task to tick a few times after startup.
const SETTLE_MS: u32 = 3_000;
/// A global address that is never dialed, because the node has no peers.
const STATIC_IP: &str = "1.2.3.4";

/// One node with no bootstrap gives every protocol a static public address, so nothing leaves this machine.
pub async fn test_static_public_addresses_stay_out_of_public_internet() {
    let (update_callback, mut config) = fixture_veilid_core();
    config.network.privacy.require_inbound_relay = true;
    config.network.routing_table.bootstrap = vec![];
    config.network.routing_table.bootstrap_records = vec![];
    config.network.protocol.udp.public_address = Some(format!("{STATIC_IP}:5150"));
    config.network.protocol.tcp.public_address = Some(format!("{STATIC_IP}:5151"));
    config.network.protocol.ws.url = Some(format!("ws://{STATIC_IP}:5152/ws"));
    #[cfg(feature = "enable-protocol-wss")]
    {
        config.network.protocol.wss.listen = true;
        config.network.protocol.wss.url = Some(format!("wss://{STATIC_IP}:5153/ws"));
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    {
        config.network.protocol.webtransport.listen = true;
        config.network.protocol.webtransport.url = Some(format!("https://{STATIC_IP}:5154/"));
    }

    let api = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api.attach().await.unwrap();
    while !api.get_state().await.unwrap().network.started {
        sleep(POLL_MS).await;
    }
    sleep(SETTLE_MS).await;

    let routing_table = api.core_context().unwrap().registry().routing_table();
    let dial_info_details = routing_table.dial_info_details(RoutingDomain::PublicInternet);
    let peer_info = routing_table.get_current_peer_info(RoutingDomain::PublicInternet);

    api.detach().await.unwrap();
    api.shutdown().await;

    assert!(
        dial_info_details.is_empty(),
        "require_inbound_relay put the node's own addresses in PublicInternet dial info: {dial_info_details:?}"
    );
    assert!(
        peer_info.node_info().dial_info_detail_list().is_empty(),
        "require_inbound_relay put the node's own addresses in its PublicInternet peer info: {:?}",
        peer_info.node_info().dial_info_detail_list()
    );
}

pub async fn test_all() {
    test_static_public_addresses_stay_out_of_public_internet().await;
}
