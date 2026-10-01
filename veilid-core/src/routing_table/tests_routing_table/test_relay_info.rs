use crate::routing_table::*;

fn relay_info(timestamp: u64, relay_kind: RelayKind) -> RelayInfo {
    RelayInfo::new(
        Timestamp::new(timestamp),
        NodeIdGroup::from(NodeId::new(CRYPTO_KIND_VLD0, BareNodeId::default())),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        vec![],
        relay_kind,
    )
}

pub fn test_relay_info_equivalent() {
    info!("--- test_relay_info_equivalent ---");

    let inbound = relay_info(1, RelayKind::Inbound);
    assert!(inbound.equivalent(&relay_info(2, RelayKind::Inbound)));
    assert!(!inbound.equivalent(&relay_info(1, RelayKind::Outbound)));
    assert!(!relay_info(1, RelayKind::Outbound).equivalent(&inbound));
}
