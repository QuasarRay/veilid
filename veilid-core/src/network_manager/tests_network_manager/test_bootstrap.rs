use super::*;
use crate::crypto::tests_crypto::*;
use crate::routing_table::tests_routing_table::fix_crypto_info_list;
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
        #[cfg(feature = "enable-protocol-webtransport")]
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_stream(
                SocketAddress::new(Address::IPV4(Ipv4Addr::UNSPECIFIED), 5150),
                "https://example.com:5150/wt".to_owned(),
                vec![],
                None,
            )
            .expect("should make webtransport dialinfo"),
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

fn mock_signing_keys() -> Vec<PublicKey> {
    mock_keypairs()
        .iter()
        .map(|skp| PublicKey::new(skp.kind(), skp.ref_value().key()))
        .collect()
}

async fn mock_v1_string(
    network_manager: &NetworkManager,
    dial_info_converter: &dyn DialInfoConverter,
) -> String {
    make_mock_bootstrap_record(true)
        .to_v1_string(
            network_manager,
            dial_info_converter,
            mock_keypairs()[0].clone(),
        )
        .await
        .expect("should make string")
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
    let bsrec2 =
        BootstrapRecord::try_new_from_v0_str(&network_manager, Some(&dial_info_converter), &v0str)
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
    let bsrec2 = BootstrapRecord::try_new_from_v1_str(
        &network_manager,
        Some(&dial_info_converter),
        &v1str,
        &signing_keys,
    )
    .await
    .expect("should parse string")
    .expect("should be valid record");
    assert_eq!(bsrec, bsrec2);

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
    let bsrec = BootstrapRecord::try_new_from_v1_str(
        &network_manager,
        Some(&dial_info_converter),
        &v1str,
        &signing_keys,
    )
    .await
    .expect("should parse string")
    .expect("should be valid record");

    // A v0 string and a version this build cannot parse are cached and served just the same,
    // so a node passes on what it was told rather than only what it understood
    let v0str = make_mock_bootstrap_record(false)
        .to_v0_string(&dial_info_converter)
        .await
        .expect("should make string");
    let future_str = "2|0|VLD0:something|example.com|T5150|1746492253|sig".to_owned();

    routing_table
        .get_routing_domain_controller(RoutingDomain::PublicInternet)
        .read_dyn()
        .record_bootstrap_cache(BootstrapCache::new(
            vec![
                v1str.clone(),
                v1str.clone(),
                v0str.clone(),
                future_str.clone(),
            ],
            vec![bsrec.clone(), bsrec],
        ));

    let response = network_manager
        .boot_v1_response()
        .expect("should serve stored records");
    let mut expected = vec![v1str, v0str, future_str];
    expected.sort_unstable();
    assert_eq!(response.records, expected);
    // The record's node is not in the routing table and is not us
    assert!(response.peers.is_empty());

    mock_registry::terminate(registry).await;
}

/// A JSON bootstrap peer's node info and ids come from its signed bytes, not from the JSON
pub async fn test_bootstrap_peer_json_binding() {
    let registry = mock_registry::init("jsonbind").await;
    let network_manager = registry.network_manager();
    let routing_table = registry.routing_table();

    let keypair = mock_keypairs()[0].clone();
    let node_info = NodeInfo::new(
        Timestamp::now(),
        VALID_ENVELOPE_VERSIONS.to_vec(),
        vec![CryptoInfo::VLD0 {
            public_key: keypair.ref_value().key(),
        }],
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        vec![DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::udp(SocketAddress::new(
                Address::IPV4(Ipv4Addr::new(1, 2, 3, 4)),
                5150,
            )),
        }],
        vec![],
        TransportMtus::default(),
        None,
    );
    let secret_keys =
        SecretKeyGroup::from(SecretKey::new(keypair.kind(), keypair.ref_value().secret()));
    let peer_info = PeerInfo::try_new_from_node_info(
        &routing_table,
        RoutingDomain::PublicInternet,
        &secret_keys,
        node_info,
    )
    .expect("should sign peer info");
    let json = serialize_json(&peer_info);

    // Fields beside the signed bytes are ignored
    let mut tampered: serde_json::Value = serde_json::from_str(&json).expect("should parse");
    tampered["node_info"]["timestamp"] =
        serde_json::to_value(Timestamp::new(u64::MAX / 2)).expect("should serialize");
    tampered["node_info"]["dial_info_detail_list"] = serde_json::json!([]);
    let tampered: PeerInfo =
        deserialize_json(&tampered.to_string()).expect("should parse tampered peer info");
    assert_ne!(tampered.node_info(), peer_info.node_info());
    let bound = network_manager
        .bind_bootstrap_peer(&tampered)
        .expect("signed bytes are intact");
    assert_eq!(bound.node_info(), peer_info.node_info());
    assert_eq!(bound.node_ids(), peer_info.node_ids());

    // A changed signed byte is refused
    let mut tampered: serde_json::Value = serde_json::from_str(&json).expect("should parse");
    let byte = tampered["node_info_message"][0]
        .as_u64()
        .expect("bytes serialize as numbers");
    tampered["node_info_message"][0] = serde_json::Value::from(byte ^ 1);
    let tampered: PeerInfo =
        deserialize_json(&tampered.to_string()).expect("should parse tampered peer info");
    assert!(network_manager.bind_bootstrap_peer(&tampered).is_none());

    mock_registry::terminate(registry).await;
}

/// A short dial info or hostname with a multibyte character fails to parse instead of panicking
pub async fn test_short_dial_info_multibyte() {
    let dial_info_converter = MockDialInfoConverter::default();
    for (short_url, hostname) in [
        ("é5150", "example.org"),
        ("Ué150", "example.org"),
        ("U5150", "é.example.org"),
        ("U5150", "example.orgé"),
        ("W5150", "[::1]é"),
    ] {
        let short_dial_info = ShortDialInfo {
            short_url: short_url.to_owned(),
            hostname: hostname.to_owned(),
        };
        assert!(dial_info_converter
            .try_vec_from_short(&short_dial_info)
            .await
            .is_err());
    }
}

/// A record parsed for serving is verified but never resolved
pub async fn test_bootstrap_record_unresolved() {
    let registry = mock_registry::init("unresolved").await;
    let network_manager = registry.network_manager();
    let dial_info_converter = MockDialInfoConverter::default();
    let signing_keys = mock_signing_keys();

    let v1str = mock_v1_string(&network_manager, &dial_info_converter).await;
    let baseline = dial_info_converter.resolve_count();

    // Parsing for serving consults no converter at all
    let unresolved =
        BootstrapRecord::try_new_from_v1_str(&network_manager, None, &v1str, &signing_keys)
            .await
            .expect("should parse string")
            .expect("should be valid record");
    assert!(unresolved.dial_info_details().is_empty());
    assert_eq!(dial_info_converter.resolve_count(), baseline);

    // Same record, resolved, differs only in its dial info
    let resolved = BootstrapRecord::try_new_from_v1_str(
        &network_manager,
        Some(&dial_info_converter),
        &v1str,
        &signing_keys,
    )
    .await
    .expect("should parse string")
    .expect("should be valid record");
    assert_eq!(resolved.public_keys(), unresolved.public_keys());
    assert!(!resolved.dial_info_details().is_empty());
    assert!(dial_info_converter.resolve_count() > baseline);

    // A config file is a likely source of trailing whitespace, and the signature covers
    // the record exactly as written
    let padded = format!("  {}\n", v1str);
    assert!(
        BootstrapRecord::try_new_from_v1_str(&network_manager, None, &padded, &signing_keys)
            .await
            .expect("should parse string")
            .is_some()
    );

    // A record no configured key signed is refused
    let mut tampered = v1str.clone();
    tampered.insert(tampered.rfind('|').expect("has a signature") + 1, 'A');
    assert!(
        BootstrapRecord::try_new_from_v1_str(&network_manager, None, &tampered, &signing_keys)
            .await
            .is_err()
    );

    mock_registry::terminate(registry).await;
}

/// Configured records are served without a bootstrap ever running, and without claiming one did.
/// Both record versions are accepted: what a node serves is not limited to what it can verify.
pub async fn test_config_bootstrap_records() {
    // Mint the records to configure the next node with
    let registry = mock_registry::init("configsrc").await;
    let dial_info_converter = MockDialInfoConverter::default();
    let v1str = mock_v1_string(&registry.network_manager(), &dial_info_converter).await;
    let v0str = make_mock_bootstrap_record(false)
        .to_v0_string(&dial_info_converter)
        .await
        .expect("should make string");
    mock_registry::terminate(registry).await;

    let configured = vec![v1str.clone(), v0str.clone()];
    let registry = mock_registry::init_with_config("configured", move |config| {
        config.network.routing_table.bootstrap_keys = mock_signing_keys();
        config.network.routing_table.bootstrap_records = configured;
    })
    .await;
    let network_manager = registry.network_manager();
    let routing_table = registry.routing_table();

    // What RoutingTable::startup does with them
    let cache = network_manager.config_bootstrap_cache().await;
    let rdc = routing_table.get_routing_domain_controller(RoutingDomain::PublicInternet);
    rdc.read_dyn().set_config_bootstrap_cache(cache);

    let response = network_manager
        .boot_v1_response()
        .expect("should serve configured records");
    let mut expected = vec![v1str, v0str];
    expected.sort_unstable();
    assert_eq!(response.records, expected);

    // Configuring records is not the same as having bootstrapped
    assert!(rdc.read_dyn().get_bootstrap_cache().is_none());

    mock_registry::terminate(registry).await;
}

/// A hostile bootstrap cannot grow every response of every node that contacted it
pub fn test_bootstrap_cache_cap() {
    let strings: Vec<String> = (0..MAX_BOOTSTRAP_RECORD_STRINGS * 2)
        .map(|i| format!("1|0|VLD0:k{}|example.com|T5150|1|sig", i))
        .collect();
    let cache = BootstrapCache::new(strings, vec![]);
    assert_eq!(cache.record_strings().len(), MAX_BOOTSTRAP_RECORD_STRINGS);
}

#[cfg(feature = "enable-protocol-webtransport")]
pub async fn test_webtransport_ip_literal_record_single_hostname() {
    let registry = mock_registry::init("").await;
    let network_manager = registry.network_manager();
    let dial_info_converter = MockDialInfoConverter::default();

    let addr = SocketAddress::new(Address::IPV4(Ipv4Addr::new(1, 2, 3, 4)), 5150);
    let dial_info_details = vec![
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::udp(addr),
        },
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_stream(
                addr,
                "https://1.2.3.4:5150/".to_owned(),
                vec![],
                None,
            )
            .expect("should make ip-literal webtransport dialinfo"),
        },
    ];
    let bsrec = BootstrapRecord::new(
        PublicKeyGroup::from(mock_public_keys()),
        VALID_ENVELOPE_VERSIONS.to_vec(),
        dial_info_details,
        None,
        vec![],
    );

    let v0str = bsrec
        .to_v0_string(&dial_info_converter)
        .await
        .expect("ip-literal webtransport must serialize into a single-hostname record");
    assert!(
        v0str.contains("example.com"),
        "record should use the PTR-derived hostname: {v0str}"
    );
    assert!(
        v0str.contains("B5150"),
        "record should include the WTS short form: {v0str}"
    );

    let bsrec2 =
        BootstrapRecord::try_new_from_v0_str(&network_manager, Some(&dial_info_converter), &v0str)
            .await
            .expect("should parse string")
            .expect("should be valid record");
    assert!(
        bsrec2.dial_info_details().iter().any(|did| {
            did.dial_info.protocol_type() == ProtocolType::WTS && did.dial_info.port() == 5150
        }),
        "parsed record should contain the WTS dial info"
    );

    mock_registry::terminate(registry).await;
}

#[cfg(feature = "enable-protocol-webtransport")]
pub async fn test_webtransport_short_form_slash_tolerant() {
    let dial_info_converter = MockDialInfoConverter::default();
    for short in ["B5150", "B5150/"] {
        let sdi = ShortDialInfo {
            short_url: short.to_string(),
            hostname: "example.com".to_string(),
        };
        let dis = dial_info_converter
            .try_vec_from_short(&sdi)
            .await
            .unwrap_or_else(|e| panic!("short form {short} should parse: {e}"));
        assert!(!dis.is_empty(), "short form {short} produced no dial info");
        for di in dis {
            assert_eq!(di.protocol_type(), ProtocolType::WTS, "short form {short}");
            assert_eq!(di.port(), 5150, "short form {short}");
        }
    }
}

fn current_bootstrap_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 180)), 5150)
}

fn expired_bootstrap_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 181)), 5150)
}

fn bootstrap_candidate_peer_info(
    routing_table: &RoutingTable,
    crypto_info_list: Vec<CryptoInfo>,
    socket_address: SocketAddress,
    expiration: Option<Timestamp>,
) -> Arc<PeerInfo> {
    let node_info = NodeInfo::new(
        Timestamp::new(0),
        vec![ENVELOPE_VERSION_ENV0],
        crypto_info_list,
        CONNECTIVITY_CAPABILITIES.to_vec(),
        ProtocolTypeSet::new(),
        AddressTypeSet::new(),
        vec![DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::tcp(socket_address),
        }],
        vec![],
        TransportMtus::default(),
        expiration,
    );

    Arc::new(
        PeerInfo::try_new_from_unsigned(routing_table, RoutingDomain::PublicInternet, node_info)
            .expect("should build unsigned peer info"),
    )
}

pub(super) fn register_current_and_expired(
    routing_table: &RoutingTable,
) -> (Arc<PeerInfo>, Arc<PeerInfo>) {
    let current = bootstrap_candidate_peer_info(
        routing_table,
        fix_crypto_info_list(true),
        current_bootstrap_socket_address(),
        None,
    );
    let expired = bootstrap_candidate_peer_info(
        routing_table,
        fix_crypto_info_list(false),
        expired_bootstrap_socket_address(),
        Some(Timestamp::new(1)),
    );
    routing_table
        .register_node_with_peer_info(Arc::new(UnverifiedPeerInfo::from_verified(&current)), true)
        .expect("should register the current node");
    routing_table
        .register_node_with_peer_info(Arc::new(UnverifiedPeerInfo::from_verified(&expired)), true)
        .expect("should register the expired node");
    (current, expired)
}

pub async fn test_bootstrap_v0_omits_expired_peer_info() {
    let registry = mock_registry::init("bootstrap_v0_expiration").await;
    {
        let routing_table = registry.routing_table();
        let network_manager = registry.network_manager();
        let (current, expired) = register_current_and_expired(&routing_table);

        let answers = network_manager.find_bootstrap_nodes_filtered(2);
        let answered_node_ids: Vec<NodeIdGroup> = answers.iter().map(|nr| nr.node_ids()).collect();

        assert!(
            answered_node_ids.contains(current.node_ids()),
            "a bootstrap candidate whose peer info has not expired must still be answered: \
             {answered_node_ids:?}"
        );
        assert!(
            !answered_node_ids.contains(expired.node_ids()),
            "a bootstrap must not hand out peer info that has expired: {answered_node_ids:?}"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_bootstrap_v1_omits_expired_peer_info() {
    let registry = mock_registry::init("bootstrap_v1_expiration").await;
    {
        let routing_table = registry.routing_table();
        let network_manager = registry.network_manager();
        let (current, expired) = register_current_and_expired(&routing_table);

        let bsrecs = [&current, &expired]
            .into_iter()
            .map(|peer_info| {
                BootstrapRecord::new(
                    peer_info.node_info().public_keys(),
                    VALID_ENVELOPE_VERSIONS.to_vec(),
                    peer_info.node_info().dial_info_detail_list().to_vec(),
                    None,
                    vec![],
                )
            })
            .collect::<Vec<_>>();

        let peers = network_manager.bootstrap_peer_info_for_records(&bsrecs);
        let peer_node_ids: Vec<NodeIdGroup> =
            peers.iter().map(|pi| pi.node_ids().clone()).collect();

        assert!(
            peer_node_ids.contains(current.node_ids()),
            "a record whose peer info has not expired must still carry it: {peer_node_ids:?}"
        );
        assert!(
            !peer_node_ids.contains(expired.node_ids()),
            "a record whose peer info has expired must be answered with records alone: \
             {peer_node_ids:?}"
        );
    }
    mock_registry::terminate(registry).await;
}

#[cfg(feature = "enable-protocol-webtransport")]
pub async fn test_webtransport_datagram_shares_the_stream_short_form() {
    let registry = mock_registry::init("").await;
    let network_manager = registry.network_manager();
    let dial_info_converter = MockDialInfoConverter::default();

    let addr = SocketAddress::new(Address::IPV4(Ipv4Addr::new(1, 2, 3, 4)), 5150);
    let url = "https://1.2.3.4:5150/wt".to_owned();
    let dial_info_details = vec![
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_stream(addr, url.clone(), vec![], None)
                .expect("should make wts dialinfo"),
        },
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_datagram(addr, url, vec![], None)
                .expect("should make wtd dialinfo"),
        },
    ];
    let bsrec = BootstrapRecord::new(
        PublicKeyGroup::from(mock_public_keys()),
        VALID_ENVELOPE_VERSIONS.to_vec(),
        dial_info_details,
        None,
        vec![],
    );

    let v0str = bsrec
        .to_v0_string(&dial_info_converter)
        .await
        .expect("a webtransport pair must serialize");
    let short_urls = v0str
        .split('|')
        .nth(4)
        .expect("record has a short url list");
    assert_eq!(
        short_urls, "B5150/wt",
        "the stream and datagram dial info must dedupe into the one stream short form, and the \
         datagram must never emit a short form of its own: {v0str}"
    );

    let bsrec2 =
        BootstrapRecord::try_new_from_v0_str(&network_manager, Some(&dial_info_converter), &v0str)
            .await
            .expect("should parse string")
            .expect("should be valid record");
    assert!(
        bsrec2
            .dial_info_details()
            .iter()
            .all(|did| did.dial_info.protocol_type() == ProtocolType::WTS),
        "the short form parses back to the stream dial info alone"
    );

    mock_registry::terminate(registry).await;
}
