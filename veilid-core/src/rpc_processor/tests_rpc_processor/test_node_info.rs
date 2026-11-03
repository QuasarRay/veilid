use super::*;
use std::net::Ipv4Addr;

fn fix_node_info(expiration: Option<Timestamp>) -> NodeInfo {
    fix_node_info_with(expiration, vec![udp_dial_info_detail()], vec![])
}

fn fix_node_info_with(
    expiration: Option<Timestamp>,
    dial_info_detail_list: Vec<DialInfoDetail>,
    relay_info_list: Vec<RelayInfo>,
) -> NodeInfo {
    NodeInfo::new(
        Timestamp::new(1_600_000_000_000_000),
        VALID_ENVELOPE_VERSIONS.to_vec(),
        vec![CryptoInfo::VLD0 {
            public_key: BarePublicKey::from_str("W7ENB-SUWpPA7usY8ORVQf_si5QmFbD1Uqa89Jg2Uc0")
                .expect("should parse bare public key"),
        }],
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        dial_info_detail_list,
        relay_info_list,
        TransportMtus::default(),
        expiration,
    )
}

fn udp_dial_info_detail() -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::udp(SocketAddress::new(
            Address::IPV4(Ipv4Addr::new(10, 0, 0, 5)),
            4443,
        )),
    }
}

fn round_trip_node_info(node_info: &NodeInfo, canonical: bool) -> (NodeInfo, usize) {
    let (decoded, len) = try_round_trip_node_info(node_info, canonical);
    (decoded.unwrap(), len)
}

fn try_round_trip_node_info(
    node_info: &NodeInfo,
    canonical: bool,
) -> (Result<NodeInfo, RPCError>, usize) {
    let mut message_builder = capnp::message::Builder::new_default();
    {
        let mut builder = message_builder.init_root::<veilid_capnp::node_info::Builder>();
        encode_node_info(node_info, &mut builder).unwrap();
    }

    let mut out = capnp::message::Builder::new_default();
    if canonical {
        let root = message_builder
            .get_root_as_reader::<capnp::any_pointer::Reader>()
            .unwrap();
        out.set_root_canonical(root).unwrap();
    } else {
        let root = message_builder
            .get_root_as_reader::<capnp::any_pointer::Reader>()
            .unwrap();
        out.set_root(root).unwrap();
    }

    let mut buffer = Vec::new();
    capnp::serialize_packed::write_message(&mut buffer, &out).unwrap();
    let len = buffer.len();

    let mut cursor = &mut &buffer[..];
    let tmp_reader =
        capnp::serialize_packed::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .unwrap();
    let reader = tmp_reader
        .get_root::<veilid_capnp::node_info::Reader>()
        .unwrap();

    (decode_node_info(&reader), len)
}

pub fn test_encode_and_decode_node_info_expiration() {
    let expiration = Some(Timestamp::new(1_700_000_000_000_000));
    let node_info = fix_node_info(expiration);

    let (decoded, _) = round_trip_node_info(&node_info, false);

    assert_eq!(decoded.expiration(), expiration);
    assert_eq!(decoded, node_info, "the whole node info must round trip");
}

pub fn test_decode_node_info_absent_expiration_is_none() {
    let node_info = fix_node_info(None);

    let (decoded, canonical_len) = round_trip_node_info(&node_info, true);
    let (_, full_len) = round_trip_node_info(&fix_node_info(Some(Timestamp::new(1))), false);

    assert!(
        canonical_len < full_len,
        "the truncated encoding must be shorter than one carrying an expiration, or this test \
         is not exercising a short struct ({canonical_len} vs {full_len})"
    );
    assert_eq!(
        decoded.expiration(),
        None,
        "a node info with no expiration on the wire must decode as no expiration"
    );
    assert_eq!(
        decoded, node_info,
        "nothing else about the node info may change"
    );
}

#[cfg(feature = "enable-protocol-webtransport")]
fn webtransport_dial_info_detail(expiration: Option<Timestamp>) -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::try_webtransport_stream(
            SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 5)), 4443),
            "https://10.0.0.5:4443/wt".to_string(),
            vec![[1u8; 32]],
            expiration,
        )
        .expect("should build webtransport dial info"),
    }
}

#[cfg(feature = "enable-protocol-webtransport")]
fn relay_info_expiring_at(expiration: Option<Timestamp>) -> RelayInfo {
    let mut node_ids = NodeIdGroup::new();
    node_ids.add(NodeId::new(CRYPTO_KIND_VLD0, BareNodeId::new(&[7u8; 32])));
    RelayInfo::new(
        Timestamp::new(1_600_000_000_000_000),
        node_ids,
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        vec![webtransport_dial_info_detail(expiration)],
        RelayKind::Inbound,
        TransportMtus::default(),
    )
}

/// The node level value is the publisher's own signal, so decode keeps whatever it
/// states no matter what the dial infos say.
#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_decode_node_info_keeps_stated_expiration_independent_of_dial_info() {
    let window = Timestamp::new(1_700_000_000_000_000);

    for opt_expiration in [
        Some(Timestamp::new(window.as_u64() + 86_400_000_000)),
        Some(window),
        Some(Timestamp::new(window.as_u64() - 1)),
        None,
    ] {
        let node_info = fix_node_info_with(
            opt_expiration,
            vec![
                udp_dial_info_detail(),
                webtransport_dial_info_detail(Some(window)),
            ],
            vec![],
        );

        let (decoded, _) = round_trip_node_info(&node_info, false);

        assert_eq!(
            decoded.expiration(),
            opt_expiration,
            "the stated expiration must decode unchanged beside a dial info that states \
             its own window"
        );
        assert_eq!(
            decoded, node_info,
            "nothing else about the node info may change"
        );
    }
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_decode_node_info_ignores_relay_dial_info_expiration() {
    let relay_window = Timestamp::new(1_700_000_000_000_000);

    let no_expiration = fix_node_info_with(
        None,
        vec![udp_dial_info_detail()],
        vec![relay_info_expiring_at(Some(relay_window))],
    );
    let (decoded, _) = round_trip_node_info(&no_expiration, false);
    assert_eq!(
        decoded, no_expiration,
        "a node with no expiring dial info of its own does not expire because its relay does"
    );

    let outlives_relay = fix_node_info_with(
        Some(Timestamp::new(relay_window.as_u64() + 86_400_000_000)),
        vec![udp_dial_info_detail()],
        vec![relay_info_expiring_at(Some(relay_window))],
    );
    let (decoded, _) = round_trip_node_info(&outlives_relay, false);
    assert_eq!(
        decoded, outlives_relay,
        "a node info may outlive its relay's dial info, which it has no way to renew"
    );
}

/// Pins the publisher's default policy, which no receiver checks.
#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_min_dial_info_expiration() {
    let sa = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 5)), 4443);
    let url = "https://10.0.0.5:4443/wt".to_string();
    let direct = |dial_info| DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info,
    };
    let wt = |expiration_us| {
        direct(
            DialInfo::try_webtransport_stream(
                sa,
                url.clone(),
                vec![[1u8; 32]],
                Some(Timestamp::new(expiration_us)),
            )
            .unwrap(),
        )
    };

    assert_eq!(
        NodeInfo::min_dial_info_expiration(&[]),
        None,
        "no dial info at all yields no default"
    );
    assert_eq!(
        NodeInfo::min_dial_info_expiration(&[direct(DialInfo::udp(sa)), direct(DialInfo::tcp(sa))]),
        None,
        "dial info that states no window yields no default"
    );
    assert_eq!(
        NodeInfo::min_dial_info_expiration(&[direct(DialInfo::udp(sa)), wt(500)]),
        Some(Timestamp::new(500)),
        "one expiring dial info sets the default, even beside ones that do not expire"
    );
    assert_eq!(
        NodeInfo::min_dial_info_expiration(&[wt(900), wt(500), wt(700)]),
        Some(Timestamp::new(500)),
        "the earliest expiration wins"
    );
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_decode_node_info_skips_dial_info_with_wrong_length_cert_hash() {
    let node_info = fix_node_info_with(
        None,
        vec![udp_dial_info_detail(), webtransport_dial_info_detail(None)],
        vec![],
    );

    let mut message_builder = capnp::message::Builder::new_default();
    {
        let mut builder = message_builder.init_root::<veilid_capnp::node_info::Builder>();
        encode_node_info(&node_info, &mut builder).unwrap();

        let mut didl_builder = builder.reborrow().get_dial_info_detail_list().unwrap();
        let mut wt_builder = didl_builder
            .reborrow()
            .get(1)
            .get_dial_info()
            .unwrap()
            .get_detail()
            .get_as::<veilid_capnp::dial_info_web_transport::Builder>()
            .unwrap();
        let mut hashes_builder = wt_builder.reborrow().init_cert_hashes(1);
        hashes_builder.set(0, &[0u8; 31]);
    }

    let mut buffer = Vec::new();
    capnp::serialize_packed::write_message(&mut buffer, &message_builder).unwrap();

    let mut cursor = &mut &buffer[..];
    let tmp_reader =
        capnp::serialize_packed::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .unwrap();
    let reader = tmp_reader
        .get_root::<veilid_capnp::node_info::Reader>()
        .unwrap();

    let decoded = decode_node_info(&reader)
        .expect("one unusable dial info must not fail the whole node info");

    assert_eq!(
        decoded.dial_info_detail_list(),
        &[udp_dial_info_detail()],
        "the dial info with an unreadable cert hash must be dropped and the UDP one kept"
    );
}
