use super::*;
use std::net::Ipv4Addr;

fn round_trip_dial_info(dial_info: &DialInfo) {
    let mut message_builder = capnp::message::Builder::new_default();
    let mut builder = message_builder.init_root::<veilid_capnp::dial_info::Builder>();

    encode_dial_info(dial_info, &mut builder).unwrap();

    let buffer = canonical_message_builder_to_bytes_writer_packed(message_builder, |size| {
        BytesWriter::with_capacity(size)
    })
    .unwrap()
    .into_inner()
    .to_vec();

    let mut cursor = &mut &buffer[..];
    let tmp_reader =
        capnp::serialize_packed::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .unwrap();
    let reader = tmp_reader
        .get_root::<veilid_capnp::dial_info::Reader>()
        .unwrap();

    let decoded = decode_dial_info(&reader).unwrap();

    assert_eq!(dial_info, &decoded);
}

pub fn test_encode_and_decode_dial_info_udp() {
    let socket_address = SocketAddress::new(Address::IPV4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let dial_info = DialInfo::udp(socket_address);

    round_trip_dial_info(&dial_info);
}

pub fn test_encode_and_decode_dial_info_tcp() {
    let socket_address = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 1)), 443);
    let dial_info = DialInfo::tcp(socket_address);

    round_trip_dial_info(&dial_info);
}

pub fn test_encode_and_decode_dial_info_ws() {
    let socket_address = SocketAddress::new(Address::IPV4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let dial_info =
        DialInfo::try_ws(socket_address, "ws://192.168.1.1:8080/ws".to_string()).unwrap();

    round_trip_dial_info(&dial_info);
}

#[cfg(feature = "enable-protocol-wss")]
pub fn test_encode_and_decode_dial_info_wss() {
    let socket_address = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 1)), 443);
    let dial_info = DialInfo::try_wss(socket_address, "wss://10.0.0.1:443/ws".to_string()).unwrap();

    round_trip_dial_info(&dial_info);
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_encode_and_decode_dial_info_wts() {
    let socket_address = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 5)), 4443);
    let dial_info = DialInfo::try_webtransport_stream(
        socket_address,
        "https://10.0.0.5:4443/wt".to_string(),
        vec![[1u8; 32], [2u8; 32]],
        Some(Timestamp::new(1_700_000_000_000_000)),
    )
    .unwrap();

    round_trip_dial_info(&dial_info);
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_encode_and_decode_dial_info_wtd() {
    let socket_address = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 6)), 4443);
    let dial_info = DialInfo::try_webtransport_datagram(
        socket_address,
        "https://10.0.0.6:4443/wt".to_string(),
        vec![[3u8; 32]],
        Some(Timestamp::new(1_700_000_000_000_000)),
    )
    .unwrap();

    round_trip_dial_info(&dial_info);
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_webtransport_protocol_type_properties() {
    assert_eq!(
        ProtocolType::WTS.low_level_protocol_type(),
        LowLevelProtocolType::UDP
    );
    assert_eq!(
        ProtocolType::WTD.low_level_protocol_type(),
        LowLevelProtocolType::UDP
    );

    assert!(!WEBTRANSPORT_PROTOCOL_TYPES.contains(ProtocolType::UDP));
    assert!(WEBTRANSPORT_PROTOCOL_TYPES.contains(ProtocolType::WTS));
    assert!(WEBTRANSPORT_PROTOCOL_TYPES.contains(ProtocolType::WTD));

    // Only WTS frames its UDP socket as a connection
    assert_eq!(ProtocolType::WTS.framing_type(), FramingType::Connection);
    assert_eq!(ProtocolType::WTD.framing_type(), FramingType::Message);
    assert_eq!(
        ProtocolType::WTS.sequence_ordering(),
        SequenceOrdering::Ordered
    );
    assert_eq!(
        ProtocolType::WTD.sequence_ordering(),
        SequenceOrdering::Unordered
    );

    let tcp = ProtocolType::TCP.sort_order(Sequencing::EnsureOrdered);
    let ws = ProtocolType::WS.sort_order(Sequencing::EnsureOrdered);
    let wts = ProtocolType::WTS.sort_order(Sequencing::EnsureOrdered);
    assert!(wts > tcp, "WTS should rank below TCP");
    assert!(wts > ws, "WTS should rank below WS");
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_webtransport_url_validation() {
    let sa = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 5)), 4443);

    assert!(DialInfo::try_webtransport_stream(
        sa,
        "https://10.0.0.5:4443/".to_string(),
        vec![],
        None,
    )
    .is_ok());
    assert!(DialInfo::try_webtransport_datagram(
        sa,
        "https://10.0.0.5:4443/".to_string(),
        vec![],
        None,
    )
    .is_ok());

    assert!(DialInfo::try_webtransport_stream(
        sa,
        "https://10.0.0.5:9999/".to_string(),
        vec![],
        None,
    )
    .is_err());

    assert!(DialInfo::try_webtransport_stream(
        sa,
        "https://10.0.0.99:4443/".to_string(),
        vec![],
        None,
    )
    .is_err());

    assert!(
        DialInfo::try_webtransport_stream(sa, "https://10.0.0.5/".to_string(), vec![], None,)
            .is_err()
    );

    assert!(DialInfo::try_webtransport_stream(
        sa,
        "http://10.0.0.5:4443/".to_string(),
        vec![],
        None,
    )
    .is_err());

    let sa443 = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 5)), 443);
    assert!(DialInfo::try_webtransport_stream(
        sa443,
        "https://bootstrap.example.net/".to_string(),
        vec![],
        None,
    )
    .is_ok());

    assert!(DialInfo::try_webtransport_stream(
        sa,
        "https://bootstrap.example.net:443/".to_string(),
        vec![],
        None,
    )
    .is_err());

    let hash = [0u8; 32];
    assert!(
        DialInfo::try_webtransport_stream(
            sa443,
            "https://bootstrap.example.net/".to_string(),
            vec![hash],
            None,
        )
        .is_err(),
        "DNS host + cert hashes must be rejected (pinned mode requires an IP-literal host)"
    );
    assert!(
        DialInfo::try_webtransport_datagram(
            sa443,
            "https://bootstrap.example.net/".to_string(),
            vec![hash],
            None,
        )
        .is_err(),
        "DNS host + cert hashes must be rejected for datagram dial info too"
    );

    assert!(
        DialInfo::try_webtransport_stream(
            sa,
            "https://10.0.0.5:4443/".to_string(),
            vec![hash],
            None,
        )
        .is_ok(),
        "IP-literal host + cert hashes (self-signed pinned mode) must remain accepted"
    );

    assert!(
        DialInfo::try_webtransport_stream(
            sa443,
            "https://bootstrap.example.net/".to_string(),
            vec![],
            None,
        )
        .is_ok(),
        "DNS host in CA mode (empty cert hashes) must remain accepted"
    );
}

pub fn test_decode_dial_info_skips_unknown_protocol() {
    let mut message_builder = capnp::message::Builder::new_default();
    let mut builder = message_builder.init_root::<veilid_capnp::dial_info::Builder>();
    builder.set_protocol_type(u32::from_be_bytes(*b"pZZZ"));

    let buffer = canonical_message_builder_to_bytes_writer_packed(message_builder, |size| {
        BytesWriter::with_capacity(size)
    })
    .unwrap()
    .into_inner()
    .to_vec();

    let mut cursor = &mut &buffer[..];
    let tmp_reader =
        capnp::serialize_packed::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .unwrap();
    let reader = tmp_reader
        .get_root::<veilid_capnp::dial_info::Reader>()
        .unwrap();

    assert!(decode_dial_info(&reader).is_err());
}

fn build_dial_info_message_unspecified_ipv4() -> Vec<u8> {
    let mut message_builder = capnp::message::Builder::new_default();
    let mut builder = message_builder.init_root::<veilid_capnp::dial_info::Builder>();

    builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_UDP);
    let mut udp_builder = builder
        .reborrow()
        .init_detail()
        .init_as::<veilid_capnp::dial_info_u_d_p::Builder>();
    let mut sa_builder = udp_builder.reborrow().init_socket_address();
    let mut addr_builder = sa_builder.reborrow().init_address();
    addr_builder.set_address_type(FOURCC_ADDRESS_TYPE_IPV4);
    let mut v4_builder = addr_builder
        .reborrow()
        .init_detail()
        .init_as::<veilid_capnp::address_i_p_v4::Builder>();
    v4_builder.set_addr(0u32); // 0.0.0.0 in big endian
    sa_builder.set_port(8080);

    canonical_message_builder_to_bytes_writer_packed(message_builder, |size| {
        BytesWriter::with_capacity(size)
    })
    .unwrap()
    .into_inner()
    .to_vec()
}

fn build_dial_info_message_unspecified_ipv6() -> Vec<u8> {
    let mut message_builder = capnp::message::Builder::new_default();
    let mut builder = message_builder.init_root::<veilid_capnp::dial_info::Builder>();

    builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_UDP);
    let mut udp_builder = builder
        .reborrow()
        .init_detail()
        .init_as::<veilid_capnp::dial_info_u_d_p::Builder>();
    let mut sa_builder = udp_builder.reborrow().init_socket_address();
    let mut addr_builder = sa_builder.reborrow().init_address();
    addr_builder.set_address_type(FOURCC_ADDRESS_TYPE_IPV6);
    let mut v6_builder = addr_builder
        .reborrow()
        .init_detail()
        .init_as::<veilid_capnp::address_i_p_v6::Builder>();
    v6_builder.set_addr0(0u32);
    v6_builder.set_addr1(0u32);
    v6_builder.set_addr2(0u32);
    v6_builder.set_addr3(0u32);
    sa_builder.set_port(8080);

    canonical_message_builder_to_bytes_writer_packed(message_builder, |size| {
        BytesWriter::with_capacity(size)
    })
    .unwrap()
    .into_inner()
    .to_vec()
}

pub fn test_decode_dial_info_rejects_unspecified_ipv4() {
    let buffer = build_dial_info_message_unspecified_ipv4();

    let mut cursor = &mut &buffer[..];
    let tmp_reader =
        capnp::serialize_packed::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .unwrap();
    let reader = tmp_reader
        .get_root::<veilid_capnp::dial_info::Reader>()
        .unwrap();

    let result = decode_dial_info(&reader);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unspecified"));
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_decode_dial_info_caps_cert_hashes() {
    let ok_buffer = build_wt_dial_info_message_with_cert_hashes(MAX_CERT_HASHES as u32, 32);
    let decoded = decode_dial_info_from_packed_bytes(&ok_buffer)
        .expect("a cert-hash list at MAX_CERT_HASHES must decode");
    match decoded {
        DialInfo::WebTransportStream(wt) => {
            assert_eq!(
                wt.cert_hashes.len(),
                MAX_CERT_HASHES,
                "an at-cap list must decode intact, not truncated"
            );
        }
        _ => panic!("expected WebTransportStream variant"),
    }

    let over_buffer = build_wt_dial_info_message_with_cert_hashes(MAX_CERT_HASHES as u32 + 1, 32);
    assert!(
        decode_dial_info_from_packed_bytes(&over_buffer).is_err(),
        "a cert-hash list over MAX_CERT_HASHES must be rejected, not truncated"
    );
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_decode_dial_info_rejects_wrong_length_cert_hash() {
    for hash_len in [0u32, 16, 31, 33, 64] {
        let buffer = build_wt_dial_info_message_with_cert_hashes(1, hash_len);
        let result = decode_dial_info_from_packed_bytes(&buffer);
        assert!(
            matches!(result, Err(RPCError::Ignore(_))),
            "a {hash_len}-byte cert hash must drop this dial info, not fail the message: \
             {result:?}"
        );
    }

    let buffer = build_wt_dial_info_message_with_cert_hashes(1, 32);
    assert!(
        decode_dial_info_from_packed_bytes(&buffer).is_ok(),
        "a 32-byte cert hash must decode"
    );
}

#[cfg(feature = "enable-protocol-webtransport")]
fn decode_dial_info_from_packed_bytes(buffer: &[u8]) -> Result<DialInfo, RPCError> {
    let mut cursor = &mut &buffer[..];
    let tmp_reader =
        capnp::serialize_packed::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .unwrap();
    let reader = tmp_reader
        .get_root::<veilid_capnp::dial_info::Reader>()
        .unwrap();
    decode_dial_info(&reader)
}

#[cfg(feature = "enable-protocol-webtransport")]
fn build_wt_dial_info_message_with_cert_hashes(count: u32, hash_len: u32) -> Vec<u8> {
    let mut message_builder = capnp::message::Builder::new_default();
    let mut builder = message_builder.init_root::<veilid_capnp::dial_info::Builder>();
    builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_WTS);
    let mut wt_builder = builder
        .reborrow()
        .init_detail()
        .init_as::<veilid_capnp::dial_info_web_transport::Builder>();
    {
        let mut sa_builder = wt_builder.reborrow().init_socket_address();
        let mut addr_builder = sa_builder.reborrow().init_address();
        addr_builder.set_address_type(FOURCC_ADDRESS_TYPE_IPV4);
        let mut v4_builder = addr_builder
            .reborrow()
            .init_detail()
            .init_as::<veilid_capnp::address_i_p_v4::Builder>();
        v4_builder.set_addr(u32::from_be_bytes([10, 0, 0, 5]));
        sa_builder.set_port(443);
    }
    {
        let url = "https://10.0.0.5:443/";
        let mut req = wt_builder.reborrow().init_request(url.len() as u32);
        req.push_str(url);
    }
    {
        let mut hashesb = wt_builder.reborrow().init_cert_hashes(count);
        let hash = vec![0u8; hash_len as usize];
        for i in 0..count {
            hashesb.set(i, hash.as_slice());
        }
    }
    canonical_message_builder_to_bytes_writer_packed(message_builder, |size| {
        BytesWriter::with_capacity(size)
    })
    .unwrap()
    .into_inner()
    .to_vec()
}

pub fn test_decode_dial_info_rejects_unspecified_ipv6() {
    let buffer = build_dial_info_message_unspecified_ipv6();

    let mut cursor = &mut &buffer[..];
    let tmp_reader =
        capnp::serialize_packed::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .unwrap();
    let reader = tmp_reader
        .get_root::<veilid_capnp::dial_info::Reader>()
        .unwrap();

    let result = decode_dial_info(&reader);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unspecified"));
}

#[cfg(feature = "enable-protocol-webtransport")]
pub fn test_decode_dial_info_absent_webtransport_expiration_is_none() {
    let buffer = build_wt_dial_info_message_with_cert_hashes(1, 32);
    let decoded = decode_dial_info_from_packed_bytes(&buffer)
        .expect("a WebTransport dial info without an expiration must still decode");
    assert_eq!(
        decoded.expiration(),
        None,
        "an unwritten expiration must decode as no expiration"
    );
}

pub fn test_dial_info_expiration_is_webtransport_only() {
    let socket_address = SocketAddress::new(Address::IPV4(Ipv4Addr::new(10, 0, 0, 5)), 4443);
    assert_eq!(DialInfo::udp(socket_address).expiration(), None);
    assert_eq!(DialInfo::tcp(socket_address).expiration(), None);
    assert_eq!(
        DialInfo::try_ws(socket_address, "ws://10.0.0.5:4443/ws".to_string())
            .unwrap()
            .expiration(),
        None
    );
    #[cfg(feature = "enable-protocol-webtransport")]
    {
        let expiration = Some(Timestamp::new(1_700_000_000_000_000));
        assert_eq!(
            DialInfo::try_webtransport_stream(
                socket_address,
                "https://10.0.0.5:4443/wt".to_string(),
                vec![[1u8; 32]],
                expiration,
            )
            .unwrap()
            .expiration(),
            expiration
        );
    }
}
