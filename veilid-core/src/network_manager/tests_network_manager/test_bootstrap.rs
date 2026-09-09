use super::*;
use crate::crypto::tests_crypto::*;
use crate::tests::*;

fn make_mock_bootstrap_record(include_timestamp: bool) -> BootstrapRecord {
    let public_keys = PublicKeyGroup::from(mock_public_keys());
    let envelope_support = VALID_ENVELOPE_VERSIONS.to_vec();
    let dial_info_details = vec![
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_ws(
                SocketAddress::new(Address::IPV4(Ipv4Addr::UNSPECIFIED), 5150),
                "ws://example.com:5150/ws".to_owned(),
            )
            .expect("should make ws dialinfo"),
        },
        #[cfg(feature = "enable-protocol-wss")]
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_wss(
                SocketAddress::new(Address::IPV4(Ipv4Addr::UNSPECIFIED), 5150),
                "wss://example.com:5150/wss".to_owned(),
            )
            .expect("should make wss dialinfo"),
        },
    ];
    let opt_timestamp = if include_timestamp {
        Some(Timestamp::now().as_u64() / 1_000_000u64)
    } else {
        None
    };
    BootstrapRecord::new(
        public_keys,
        envelope_support,
        dial_info_details,
        opt_timestamp,
        vec![],
    )
}

pub async fn test_bootstrap_v0() {
    let registry = mock_registry::init("").await;
    let network_manager = registry.network_manager();
    let dial_info_converter = MockDialInfoConverter::default();

    let bsrec = make_mock_bootstrap_record(false);
    let v0str = bsrec
        .to_v0_string(&dial_info_converter)
        .await
        .expect("should make string");
    let bsrec2 = BootstrapRecord::new_from_v0_str(&network_manager, &dial_info_converter, &v0str)
        .await
        .expect("should parse string")
        .expect("should be valid record");
    assert_eq!(bsrec, bsrec2);

    mock_registry::terminate(registry).await;
}

pub async fn test_bootstrap_v1() {
    let registry = mock_registry::init("").await;
    let network_manager = registry.network_manager();
    let dial_info_converter = MockDialInfoConverter::default();

    let bsrec = make_mock_bootstrap_record(true);
    let signing_key_pairs = mock_keypairs();
    println!("signing_key_pairs: {:?}", signing_key_pairs);
    let signing_keys = signing_key_pairs
        .iter()
        .map(|skp| PublicKey::new(skp.kind(), skp.ref_value().key()))
        .collect::<Vec<_>>();
    let v1str = bsrec
        .to_v1_string(
            &network_manager,
            &dial_info_converter,
            signing_key_pairs[0].clone(),
        )
        .await
        .expect("should make string");
    let bsrec2 = BootstrapRecord::new_from_v1_str(
        &network_manager,
        &dial_info_converter,
        &v1str,
        &signing_keys,
    )
    .await
    .expect("should parse string")
    .expect("should be valid record");
    assert_eq!(bsrec.with_signed_strings(vec![v1str]), bsrec2);

    // Persisted with the routing domain state
    let bsrec3: BootstrapRecord =
        deserialize_json(&serialize_json(&bsrec2)).expect("should round trip");
    assert_eq!(bsrec2, bsrec3);

    mock_registry::terminate(registry).await;
}

/// B01T answers only from the routing domain's stored records and never resolves anything
pub async fn test_boot_v1_response() {
    let registry = mock_registry::init("").await;
    let network_manager = registry.network_manager();
    let routing_table = registry.routing_table();
    let dial_info_converter = MockDialInfoConverter::default();

    // Nothing stored, nothing served
    assert!(network_manager.boot_v1_response().is_none());

    let signing_key_pairs = mock_keypairs();
    let signing_keys = signing_key_pairs
        .iter()
        .map(|skp| PublicKey::new(skp.kind(), skp.ref_value().key()))
        .collect::<Vec<_>>();
    let v1str = make_mock_bootstrap_record(true)
        .to_v1_string(
            &network_manager,
            &dial_info_converter,
            signing_key_pairs[0].clone(),
        )
        .await
        .expect("should make string");
    let bsrec = BootstrapRecord::new_from_v1_str(
        &network_manager,
        &dial_info_converter,
        &v1str,
        &signing_keys,
    )
    .await
    .expect("should parse string")
    .expect("should be valid record");

    routing_table
        .get_routing_domain_controller(RoutingDomain::PublicInternet)
        .read_dyn()
        .set_bootstrap_records(vec![bsrec.clone(), bsrec]);

    let response = network_manager
        .boot_v1_response()
        .expect("should serve stored records");
    assert_eq!(response.records, vec![v1str]);
    // The record's node is not in the routing table and is not us
    assert!(response.peers.is_empty());

    mock_registry::terminate(registry).await;
}
