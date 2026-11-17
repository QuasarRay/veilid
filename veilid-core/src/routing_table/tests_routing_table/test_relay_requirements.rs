use super::*;
use crate::tests::*;

/// No relay is wanted for WSS, so a public server, which holds no CA certificate and lists no
/// WSS dial info, needs none and goes on to publish
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
