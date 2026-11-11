use super::*;
use crate::tests::*;

fn udp_v4_mtus(mtu: u16) -> TransportMtus {
    let mut mtus = TransportMtus::default();
    mtus.set(
        LowLevelTransportType {
            low_level_protocol_type: LowLevelProtocolType::UDP,
            address_type: AddressType::IPV4,
        },
        mtu,
    );
    mtus
}

/// PublicInternet holds its peer info back until our mtus are known, then publishes them, and a
/// change publishes again
pub async fn test_publish_waits_for_transport_mtus() {
    let registry = mock_registry::init("rt_publish_waits_for_mtus").await;
    let routing_table = registry.routing_table();
    make_public_internet_direct(&routing_table);

    let controller = routing_table
        .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
    assert_eq!(
        controller.state().inbound_stage,
        RoutingDomainInboundStage::NeedsTransportMtus
    );
    assert!(
        !controller.publish_peer_info(),
        "nothing should publish before our mtus are known"
    );

    let mut editor = controller.edit();
    editor.set_receive_mtus(Some(udp_v4_mtus(1472)));
    editor.commit();
    assert_eq!(
        controller.state().inbound_stage,
        RoutingDomainInboundStage::ReadyToPublish
    );
    assert!(controller.publish_peer_info());
    assert_eq!(
        controller
            .get_published_peer_info()
            .expect("published")
            .node_info()
            .receive_mtus(),
        &udp_v4_mtus(1472)
    );

    let mut editor = controller.edit();
    editor.set_receive_mtus(Some(udp_v4_mtus(SAFE_TRANSPORT_MTU)));
    editor.commit();
    assert!(
        controller.publish_peer_info(),
        "a size change should publish again"
    );
    assert_eq!(
        controller
            .get_published_peer_info()
            .expect("published")
            .node_info()
            .receive_mtus(),
        &udp_v4_mtus(SAFE_TRANSPORT_MTU)
    );

    mock_registry::terminate(registry).await;
}
