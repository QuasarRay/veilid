use super::*;
use crate::tests::*;

/// A peer whose node info carries a bad receive mtu list is dropped, and the answer keeps the rest
pub async fn test_ignored_node_info_drops_only_its_peer() {
    let (update_callback, config) = fixture_veilid_core();
    let api = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    let registry = api.core_context().unwrap().registry();
    let routing_table = registry.routing_table();
    let crypto = api.crypto().unwrap();
    let keypair = crypto.get(CRYPTO_KIND_VLD0).unwrap().generate_keypair();

    let node_info = NodeInfo::new(
        Timestamp::now(),
        VALID_ENVELOPE_VERSIONS.to_vec(),
        vec![CryptoInfo::VLD0 {
            public_key: keypair.key().value(),
        }],
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        vec![DialInfoDetail {
            class: DialInfoClass::Mapped,
            dial_info: DialInfo::udp(SocketAddress::new(
                Address::IPV4(Ipv4Addr::new(18, 218, 0, 160)),
                53,
            )),
        }],
        vec![],
        TransportMtus::default(),
        None,
    );
    let peer_info = PeerInfo::try_new_from_node_info(
        &routing_table,
        RoutingDomain::PublicInternet,
        &SecretKeyGroup::from(keypair.secret()),
        node_info,
    )
    .unwrap();

    // The same node info with a udp size below the wire range
    let mut bad_message_builder = capnp::message::Builder::new_default();
    {
        let mut builder = bad_message_builder.init_root::<veilid_capnp::node_info::Builder>();
        encode_node_info(peer_info.node_info(), &mut builder).unwrap();
        let mut list = builder.init_receive_mtus(1);
        let mut tm = list.reborrow().get(0);
        tm.set_protocol_type(FOURCC_PROTOCOL_TYPE_UDP);
        tm.set_address_type(FOURCC_ADDRESS_TYPE_IPV4);
        tm.set_mtu(MIN_TRANSPORT_MTU - 1);
    }
    let mut bad_message = Vec::new();
    capnp::serialize_packed::write_message(&mut bad_message, &bad_message_builder).unwrap();

    let opt_bad = UnverifiedPeerInfo::try_new_from_wire(
        &routing_table,
        RoutingDomain::PublicInternet,
        &bad_message,
        peer_info.signatures().clone(),
    )
    .expect("an ignored node info is not an error");
    assert!(opt_bad.is_none(), "the bad node info must be ignored");

    // A find node answer carrying the bad peer after a good one
    let good = UnverifiedPeerInfo::from_verified(&peer_info);
    let mut answer_builder = capnp::message::Builder::new_default();
    {
        let builder = answer_builder.init_root::<veilid_capnp::operation_find_node_a::Builder>();
        let mut peers_builder = builder.init_peers(2);
        encode_peer_info(&good, &mut peers_builder.reborrow().get(0)).unwrap();
        let mut bad_builder = peers_builder.reborrow().get(1);
        encode_peer_info(&good, &mut bad_builder).unwrap();
        bad_builder.set_node_info_message(&bad_message);
    }
    let reader = answer_builder
        .get_root_as_reader::<veilid_capnp::operation_find_node_a::Reader>()
        .unwrap();
    let decode_context = RPCDecodeContext {
        registry: registry.clone(),
        origin_routing_domain: RoutingDomain::PublicInternet,
    };
    let peers = RPCOperationFindNodeA::decode(&decode_context, &reader)
        .expect("one ignored peer must not fail the answer")
        .destructure();
    assert_eq!(peers.len(), 1, "only the bad peer is dropped");
    assert_eq!(peers[0].node_info_message(), good.node_info_message());

    api.shutdown().await;
}
