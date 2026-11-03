use super::*;

pub fn test_protocol_type_set_persisted_width() {
    assert_eq!(
        core::mem::size_of::<ProtocolTypeSet>(),
        1,
        "ProtocolTypeSet persisted width changed: widening the ProtocolType repr requires a local table-store migration"
    );
}

pub fn test_webtransport_and_udp_are_low_level_udp() {
    assert_eq!(
        ProtocolType::UDP.low_level_protocol_type(),
        LowLevelProtocolType::UDP
    );
    #[cfg(feature = "enable-protocol-webtransport")]
    {
        assert_eq!(
            ProtocolType::WTS.low_level_protocol_type(),
            LowLevelProtocolType::UDP
        );
        assert_eq!(
            ProtocolType::WTD.low_level_protocol_type(),
            LowLevelProtocolType::UDP
        );
    }
    assert_eq!(
        ProtocolType::TCP.low_level_protocol_type(),
        LowLevelProtocolType::TCP
    );
}
