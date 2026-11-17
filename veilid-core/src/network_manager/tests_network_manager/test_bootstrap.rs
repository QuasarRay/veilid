use super::*;
use crate::crypto::tests_crypto::*;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use crate::routing_table::tests_routing_table::make_public_internet_direct;
use crate::tests::*;

/// How long a test payload stays valid
const TEST_LIFETIME: TimestampDuration = TimestampDuration::new_secs(3600);

fn mock_signing_keys() -> Vec<PublicKey> {
    mock_keypairs()
        .iter()
        .map(|skp| PublicKey::new(skp.kind(), skp.ref_value().key()))
        .collect()
}

fn test_dial_info(last_octet: u8) -> DialInfo {
    DialInfo::tcp(SocketAddress::new(
        Address::IPV4(Ipv4Addr::new(18, 218, 0, last_octet)),
        5150,
    ))
}

/// A signed peer info for a fresh node, directly reachable at `dial_info`
fn fresh_peer_info(
    routing_table: &RoutingTable,
    crypto: &Crypto,
    dial_info: DialInfo,
    expiration: Option<Timestamp>,
) -> Arc<PeerInfo> {
    let kp = crypto.best().generate_keypair();
    let node_info = NodeInfo::new(
        Timestamp::now(),
        vec![ENVELOPE_VERSION_ENV0],
        vec![CryptoInfo::VLD0 {
            public_key: kp.ref_value().key(),
        }],
        CONNECTIVITY_CAPABILITIES.to_vec(),
        ProtocolTypeSet::new(),
        AddressTypeSet::new(),
        vec![DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info,
        }],
        vec![],
        TransportMtus::default(),
        expiration,
    );
    let secret_keys = SecretKeyGroup::from(vec![kp.secret()]);
    Arc::new(
        PeerInfo::try_new_from_node_info(
            routing_table,
            RoutingDomain::PublicInternet,
            &secret_keys,
            node_info,
        )
        .expect("should sign peer info"),
    )
}

/// A current and an expired directly reachable node, registered, for the native dial info
/// validator test
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn register_current_and_expired(
    routing_table: &RoutingTable,
) -> (Arc<PeerInfo>, Arc<PeerInfo>) {
    let crypto = routing_table.crypto();
    let current = fresh_peer_info(routing_table, &crypto, test_dial_info(180), None);
    let expired = fresh_peer_info(
        routing_table,
        &crypto,
        test_dial_info(181),
        Some(Timestamp::new(1)),
    );
    register(routing_table, &current);
    register(routing_table, &expired);
    (current, expired)
}

fn register(routing_table: &RoutingTable, peer_info: &Arc<PeerInfo>) {
    routing_table
        .register_node_with_peer_info(Arc::new(UnverifiedPeerInfo::from_verified(peer_info)), true)
        .expect("should register the node");
}

/// A payload naming `peers`, signed with `key_pairs` (none makes it unsigned)
fn payload_for(
    peers: &[Arc<PeerInfo>],
    crypto: &Crypto,
    key_pairs: &[KeyPair],
    timestamp: Timestamp,
    expiration: Option<Timestamp>,
) -> SignedBootstrapPayload {
    let bootstrap_nodes = peers
        .iter()
        .map(|pi| {
            BootstrapNode::new(
                pi.node_ids().clone(),
                pi.node_info()
                    .dial_info_detail_list()
                    .iter()
                    .map(|did| did.dial_info.clone())
                    .collect(),
            )
        })
        .collect();
    let payload = BootstrapPayload::new(timestamp, expiration, None, bootstrap_nodes);
    SignedBootstrapPayload::try_new_signed(crypto, payload, key_pairs).expect("should sign payload")
}

fn serve_payload(routing_table: &RoutingTable, payload: &SignedBootstrapPayload) {
    routing_table
        .get_routing_domain_controller(RoutingDomain::PublicInternet)
        .read_dyn()
        .set_config_bootstrap_cache(BootstrapCache::from_payload(payload, None));
}

pub async fn test_boot_v2_payload_round_trip() {
    let registry = mock_registry::init("boot_v2_payload").await;
    {
        let routing_table = registry.routing_table();
        let crypto = registry.crypto();
        let pi = fresh_peer_info(&routing_table, &crypto, test_dial_info(180), None);
        let now = Timestamp::now();
        let signed = payload_for(
            std::slice::from_ref(&pi),
            &crypto,
            &mock_keypairs()[..1],
            now,
            Some(now.later(TEST_LIFETIME)),
        );

        // The line form carries the exact bytes
        let line = signed.to_line();
        assert!(SignedBootstrapPayload::is_payload_line(&line));
        assert!(!SignedBootstrapPayload::is_payload_line(
            "1|0|VLD0:x|host|U5150"
        ));
        let parsed = SignedBootstrapPayload::try_new_from_line(&line).expect("should parse line");
        assert_eq!(parsed, signed);
        assert_eq!(parsed.payload().timestamp(), now);
        assert!(parsed.payload().names_node(pi.node_ids()));
        assert_eq!(parsed.payload().cache_ttl(), DEFAULT_BOOTSTRAP_CACHE_TTL);
        assert!(!parsed.payload().is_expired(now));
        assert!(parsed.payload().is_expired(now.later(TEST_LIFETIME)));

        // Trusted keys verify it, others do not
        parsed
            .verify(&crypto, &mock_signing_keys()[..1])
            .expect("should verify with the signing key");
        assert!(parsed.verify(&crypto, &mock_signing_keys()[1..2]).is_err());

        // An unsigned payload passes no key check
        let unsigned = payload_for(&[pi], &crypto, &[], now, None);
        assert!(unsigned.verify(&crypto, &mock_signing_keys()).is_err());
        assert_eq!(unsigned.payload().expiration(), None);

        // A node line round trips too
        let node = &signed.payload().bootstrap_nodes()[0];
        let node_line = node.to_line().expect("should make node line");
        assert!(node_line.starts_with(BOOTSTRAP_NODE_LINE_PREFIX));
        assert_eq!(
            &BootstrapNode::try_new_from_line(&node_line).expect("should parse node line"),
            node
        );
        assert!(BootstrapNode::try_new_from_line("node|not base64!").is_err());
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_boot_v2_request_forms() {
    assert!(NetworkManager::is_boot_v2_request(b"B02T"));
    assert!(NetworkManager::is_boot_v2_request(b"B01TB02T"));
    assert!(NetworkManager::is_boot_v2_request(b"BOOTB02Tand more"));
    assert!(!NetworkManager::is_boot_v2_request(b"B01T"));
    assert!(!NetworkManager::is_boot_v2_request(b"BOOT"));
    assert!(!NetworkManager::is_boot_v2_request(b"B01TBOOT"));
    assert!(!NetworkManager::is_boot_v2_request(b"B03T"));
    assert!(!NetworkManager::is_boot_v2_request(b"B0"));

    // A keyed client leads with the signed legacy tag while that version is still answered
    let registry = mock_registry::init("boot_v2_request_keyed").await;
    let keyed = registry.network_manager().boot_v2_request_bytes();
    #[cfg(feature = "enable-bootstrap-v1")]
    assert_eq!(&keyed[..], b"B01TB02T");
    #[cfg(not(feature = "enable-bootstrap-v1"))]
    assert_eq!(&keyed[..], b"B02T");
    assert!(NetworkManager::is_boot_v2_request(&keyed));
    mock_registry::terminate(registry).await;

    let registry = mock_registry::init_with_config("boot_v2_request_keyless", |cfg| {
        cfg.network.routing_table.bootstrap_keys.clear();
    })
    .await;
    let keyless = registry.network_manager().boot_v2_request_bytes();
    #[cfg(feature = "enable-bootstrap-v0")]
    assert_eq!(&keyless[..], b"BOOTB02T");
    #[cfg(not(feature = "enable-bootstrap-v0"))]
    assert_eq!(&keyless[..], b"B02T");
    assert!(NetworkManager::is_boot_v2_request(&keyless));
    mock_registry::terminate(registry).await;
}

/// A reply carries the held payload bytes unchanged and the peers it names
pub async fn test_boot_v2_response_round_trip() {
    let registry = mock_registry::init("boot_v2_response").await;
    {
        let routing_table = registry.routing_table();
        let network_manager = registry.network_manager();
        let crypto = registry.crypto();

        let named = fresh_peer_info(&routing_table, &crypto, test_dial_info(180), None);
        let expired = fresh_peer_info(
            &routing_table,
            &crypto,
            test_dial_info(181),
            Some(Timestamp::new(1)),
        );
        register(&routing_table, &named);
        register(&routing_table, &expired);
        let now = Timestamp::now();
        let signed = payload_for(
            &[named.clone(), expired.clone()],
            &crypto,
            &mock_keypairs()[..1],
            now,
            Some(now.later(TEST_LIFETIME)),
        );
        serve_payload(&routing_table, &signed);

        let reply = network_manager
            .boot_v2_response()
            .expect("should build reply");
        assert_eq!(&reply[..4], B02T_MAGIC);
        assert!(reply.len() <= MAX_MESSAGE_SIZE);
        let decoded = network_manager
            .decode_boot_v2_response(&reply[4..])
            .expect("should decode reply");
        assert_eq!(decoded.payload.as_ref(), Some(signed.bytes()));
        let ids: Vec<NodeIdGroup> = decoded
            .peers
            .iter()
            .map(|pi| pi.node_ids().clone())
            .collect();
        assert!(ids.contains(named.node_ids()), "{ids:?}");
        assert!(!ids.contains(expired.node_ids()), "{ids:?}");

        // With no payload held, the reply still offers direct peers for an unsigned client
        routing_table
            .get_routing_domain_controller(RoutingDomain::PublicInternet)
            .read_dyn()
            .set_config_bootstrap_cache(BootstrapCache::default());
        let reply = network_manager
            .boot_v2_response()
            .expect("should build reply");
        let decoded = network_manager
            .decode_boot_v2_response(&reply[4..])
            .expect("should decode reply");
        assert!(decoded.payload.is_none());
        let ids: Vec<NodeIdGroup> = decoded
            .peers
            .iter()
            .map(|pi| pi.node_ids().clone())
            .collect();
        assert!(ids.contains(named.node_ids()), "{ids:?}");
        assert!(!ids.contains(expired.node_ids()), "{ids:?}");
    }
    mock_registry::terminate(registry).await;
}

/// With keys, the payload must verify and every peer must be one of its nodes; without keys
/// everything offered is taken; a payload older than the one held is refused either way
pub async fn test_boot_v2_accept_rules() {
    let registry = mock_registry::init_with_config("boot_v2_accept", |cfg| {
        cfg.network.routing_table.bootstrap_keys = mock_signing_keys()[..1].to_vec();
    })
    .await;
    {
        let routing_table = registry.routing_table();
        let network_manager = registry.network_manager();
        let crypto = registry.crypto();
        let named = fresh_peer_info(&routing_table, &crypto, test_dial_info(180), None);
        let stranger = fresh_peer_info(&routing_table, &crypto, test_dial_info(182), None);
        let now = Timestamp::now();
        let expiration = Some(now.later(TEST_LIFETIME));
        let good = payload_for(
            std::slice::from_ref(&named),
            &crypto,
            &mock_keypairs()[..1],
            now,
            expiration,
        );
        let response = |payload: Option<&SignedBootstrapPayload>| BootV2Response {
            payload: payload.map(|p| p.bytes().clone()),
            peers: vec![
                UnverifiedPeerInfo::from_verified(&named),
                UnverifiedPeerInfo::from_verified(&stranger),
            ],
        };

        // A trusted payload: its node is kept, the stranger is not, and it is asked for nothing
        let accepted = network_manager.accept_boot_v2_response(response(Some(&good)));
        assert_eq!(accepted.payload.as_ref(), Some(&good));
        assert_eq!(accepted.peers.len(), 1);
        assert_eq!(accepted.peers[0].node_ids(), named.node_ids());
        assert!(accepted.unanswered.is_empty());

        // A payload naming a node the reply did not carry leaves it to be asked
        let absent = payload_for(
            &[named.clone(), stranger.clone()],
            &crypto,
            &mock_keypairs()[..1],
            now,
            expiration,
        );
        let accepted = network_manager.accept_boot_v2_response(BootV2Response {
            payload: Some(absent.bytes().clone()),
            peers: vec![UnverifiedPeerInfo::from_verified(&named)],
        });
        assert_eq!(accepted.unanswered.len(), 1);
        assert_eq!(accepted.unanswered[0].node_ids(), stranger.node_ids());

        // The wrong signing key, an unsigned payload, an expired one, or none: nothing is trusted
        let wrong_key = payload_for(
            std::slice::from_ref(&named),
            &crypto,
            &mock_keypairs()[1..2],
            now,
            expiration,
        );
        let unsigned = payload_for(std::slice::from_ref(&named), &crypto, &[], now, expiration);
        let expired = payload_for(
            std::slice::from_ref(&named),
            &crypto,
            &mock_keypairs()[..1],
            now,
            Some(Timestamp::new(1)),
        );
        for bad in [Some(&wrong_key), Some(&unsigned), Some(&expired), None] {
            let accepted = network_manager.accept_boot_v2_response(response(bad));
            assert!(accepted.payload.is_none());
            assert!(accepted.peers.is_empty());
        }

        // Holding a newer payload refuses an older one
        let newer = payload_for(
            std::slice::from_ref(&named),
            &crypto,
            &mock_keypairs()[..1],
            now.later(TimestampDuration::new_secs(1)),
            expiration,
        );
        serve_payload(&routing_table, &newer);
        assert_eq!(
            routing_table.bootstrap_payload_floor(),
            Some(newer.payload().timestamp())
        );
        let accepted = network_manager.accept_boot_v2_response(response(Some(&good)));
        assert!(accepted.payload.is_none());
        let accepted = network_manager.accept_boot_v2_response(response(Some(&newer)));
        assert_eq!(accepted.payload.as_ref(), Some(&newer));
    }
    mock_registry::terminate(registry).await;

    // Without keys, the payload and every verified peer are taken as offered
    let registry = mock_registry::init_with_config("boot_v2_accept_keyless", |cfg| {
        cfg.network.routing_table.bootstrap_keys.clear();
    })
    .await;
    {
        let routing_table = registry.routing_table();
        let network_manager = registry.network_manager();
        let crypto = registry.crypto();
        let named = fresh_peer_info(&routing_table, &crypto, test_dial_info(180), None);
        let stranger = fresh_peer_info(&routing_table, &crypto, test_dial_info(182), None);
        let now = Timestamp::now();
        let unsigned = payload_for(std::slice::from_ref(&named), &crypto, &[], now, None);
        let accepted = network_manager.accept_boot_v2_response(BootV2Response {
            payload: Some(unsigned.bytes().clone()),
            peers: vec![
                UnverifiedPeerInfo::from_verified(&named),
                UnverifiedPeerInfo::from_verified(&stranger),
            ],
        });
        assert_eq!(accepted.payload.as_ref(), Some(&unsigned));
        assert_eq!(accepted.peers.len(), 2);
        let accepted = network_manager.accept_boot_v2_response(BootV2Response {
            payload: None,
            peers: vec![UnverifiedPeerInfo::from_verified(&stranger)],
        });
        assert!(accepted.payload.is_none());
        assert_eq!(accepted.peers.len(), 1);
    }
    mock_registry::terminate(registry).await;
}

/// The newest payload wins a union, a config copy takes ties, and a re-check comes due once
/// per cache period for a learned copy and for having nothing to serve
pub async fn test_bootstrap_cache() {
    let registry = mock_registry::init("boot_v2_cache").await;
    {
        let routing_table = registry.routing_table();
        let crypto = registry.crypto();
        let pi = fresh_peer_info(&routing_table, &crypto, test_dial_info(180), None);
        let now = Timestamp::now();
        let older = payload_for(std::slice::from_ref(&pi), &crypto, &[], now, None);
        let newer = payload_for(
            std::slice::from_ref(&pi),
            &crypto,
            &[],
            now.later(TimestampDuration::new_secs(1)),
            Some(now.later(TEST_LIFETIME)),
        );

        // Nothing held comes due at once, then once per default cache period
        let mut empty = BootstrapCache::default();
        assert!(empty.is_empty());
        assert!(empty.served_payload(now).is_none());
        assert!(empty.recheck_due(now));
        empty.mark_rechecked(now);
        assert!(!empty.recheck_due(now));
        assert!(empty.recheck_due(now.later(DEFAULT_BOOTSTRAP_CACHE_TTL)));

        let mut learned = BootstrapCache::from_payload(&older, Some(now));
        assert!(!learned.is_empty());
        assert_eq!(learned.served_payload(now), Some(older.clone()));
        assert!(!learned.recheck_due(now));
        assert!(learned.recheck_due(now.later(DEFAULT_BOOTSTRAP_CACHE_TTL)));
        learned.mark_rechecked(now.later(DEFAULT_BOOTSTRAP_CACHE_TTL));
        assert!(!learned.recheck_due(now.later(DEFAULT_BOOTSTRAP_CACHE_TTL)));
        assert_eq!(learned.received_at(), Some(now));

        // The newer payload replaces the older, from either side
        learned.union(BootstrapCache::from_payload(&newer, Some(now)));
        assert_eq!(
            learned.payload_timestamp(),
            Some(newer.payload().timestamp())
        );
        learned.union(BootstrapCache::from_payload(&older, None));
        assert_eq!(
            learned.payload_timestamp(),
            Some(newer.payload().timestamp())
        );

        // A config copy never comes due while it is served, and takes a tie
        let unexpiring = BootstrapCache::from_payload(&older, None);
        assert!(!unexpiring.recheck_due(now.later(DEFAULT_BOOTSTRAP_CACHE_TTL)));
        let mut config = BootstrapCache::from_payload(&newer, None);
        config.union(BootstrapCache::from_payload(&newer, Some(now)));
        assert_eq!(config.received_at(), None);
        learned.union(BootstrapCache::from_payload(&newer, None));
        assert_eq!(learned.received_at(), None);

        // An expired payload is held for its floor but not served, and comes due like none
        let mut expired = BootstrapCache::from_payload(&newer, None);
        let later = now
            .later(TEST_LIFETIME)
            .later(TimestampDuration::new_secs(1));
        assert!(expired.served_payload(later).is_none());
        assert_eq!(
            expired.payload_timestamp(),
            Some(newer.payload().timestamp())
        );
        assert!(!expired.recheck_due(now));
        assert!(expired.recheck_due(later));
        expired.mark_rechecked(later);
        assert!(!expired.recheck_due(later));

        // The last re-check survives a union with the config copy
        let mut served = BootstrapCache::default();
        served.mark_rechecked(later);
        served.union(BootstrapCache::from_payload(&newer, None));
        assert!(!served.recheck_due(later));
    }
    mock_registry::terminate(registry).await;
}

/// A node asked for a payload it does not hold asks its bootstraps on the next tick
pub async fn test_bootstrap_recheck_with_nothing_to_serve() {
    let registry = mock_registry::init("boot_v2_recheck").await;
    {
        let routing_table = registry.routing_table();
        let network_manager = registry.network_manager();
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
        assert!(!controller.bootstrap_recheck_pending());
        network_manager
            .boot_v2_response()
            .expect("a reply with no payload still builds");
        assert!(controller.bootstrap_recheck_pending());
    }
    mock_registry::terminate(registry).await;
}

pub fn test_record_lifetime_parse() {
    const DAY: u64 = 86_400_000_000;
    assert_eq!(parse_record_lifetime("none"), Some(None));
    assert_eq!(parse_record_lifetime("0"), Some(None));
    assert_eq!(
        parse_record_lifetime("30d"),
        Some(Some(TimestampDuration::new(30 * DAY)))
    );
    assert_eq!(
        parse_record_lifetime("1y6mo"),
        Some(Some(TimestampDuration::new((365 + 180) * DAY)))
    );
    assert_eq!(
        parse_record_lifetime(" 2Y "),
        Some(Some(TimestampDuration::new(730 * DAY)))
    );
    for bad in ["", "5m", "1y2", "d", "1x", "-1d", "1h"] {
        assert_eq!(parse_record_lifetime(bad), None, "{bad:?}");
    }
}

/// The config's payload line is the newest trusted one; untrusted and malformed lines are skipped
pub async fn test_config_bootstrap_payload() {
    let registry = mock_registry::init("boot_v2_config_lines").await;
    let (older_line, newer_line, wrong_key_line) = {
        let routing_table = registry.routing_table();
        let crypto = registry.crypto();
        let pi = fresh_peer_info(&routing_table, &crypto, test_dial_info(180), None);
        let now = Timestamp::now();
        let expiration = Some(now.later(TEST_LIFETIME));
        (
            payload_for(
                std::slice::from_ref(&pi),
                &crypto,
                &mock_keypairs()[..1],
                now,
                expiration,
            )
            .to_line(),
            payload_for(
                std::slice::from_ref(&pi),
                &crypto,
                &mock_keypairs()[..1],
                now.later(TimestampDuration::new_secs(1)),
                expiration,
            )
            .to_line(),
            payload_for(
                std::slice::from_ref(&pi),
                &crypto,
                &mock_keypairs()[1..2],
                now.later(TimestampDuration::new_secs(2)),
                expiration,
            )
            .to_line(),
        )
    };
    mock_registry::terminate(registry).await;

    let registry = mock_registry::init_with_config("boot_v2_config_payload", |cfg| {
        cfg.network.routing_table.bootstrap_keys = mock_signing_keys()[..1].to_vec();
        cfg.network.routing_table.bootstrap_records = vec![
            older_line.clone(),
            "2|not base64!".to_owned(),
            wrong_key_line.clone(),
            newer_line.clone(),
        ];
    })
    .await;
    {
        let network_manager = registry.network_manager();
        let payload = network_manager
            .config_bootstrap_payload()
            .expect("should find the configured payload");
        assert_eq!(payload.to_line(), newer_line);

        // The configured payload's nodes are what this node asks directly
        let peers = network_manager.config_bootstrap();
        assert!(peers.peers.is_empty());
        assert_eq!(peers.unanswered.len(), 1);

        // And it is what this node serves before it ever bootstraps
        let cache = network_manager.config_bootstrap_cache();
        assert_eq!(
            cache.payload_timestamp(),
            Some(payload.payload().timestamp())
        );
        assert_eq!(cache.received_at(), None);
    }
    mock_registry::terminate(registry).await;
}

/// A node that serves bootstrap advertises BOOT only once it is directly reachable
pub async fn test_bootstrap_capability_needs_direct_dial_info() {
    let registry = mock_registry::init_with_config("boot_capability", |cfg| {
        cfg.network.routing_table.serve_direct_bootstrap = true;
    })
    .await;
    {
        let routing_table = registry.routing_table();
        let rdc = routing_table.get_routing_domain_controller(RoutingDomain::PublicInternet);
        assert!(!rdc
            .read_dyn()
            .capabilities()
            .contains(&VEILID_CAPABILITY_BOOTSTRAP));
        assert!(!routing_table.serves_direct_bootstrap());
    }
    mock_registry::terminate(registry).await;
}

/// A node told to serve bootstrap that is directly reachable on every transport and needs no
/// relay carries BOOT in the node info it makes, publishes it, and serves
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub async fn test_bootstrap_capability_reaches_published_node_info() {
    let registry = mock_registry::init_with_config("boot_capability_published", |cfg| {
        cfg.network.routing_table.serve_direct_bootstrap = true;
    })
    .await;
    {
        let routing_table = registry.routing_table();
        make_public_internet_direct(&routing_table);
        let controller = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
        let mut editor = controller.edit();
        editor.set_receive_mtus(Some(TransportMtus::default()));
        editor.commit();

        let current = routing_table.get_current_peer_info(RoutingDomain::PublicInternet);
        assert!(
            current
                .node_info()
                .has_capability(VEILID_CAPABILITY_BOOTSTRAP),
            "the node info this node makes must carry BOOT: {:?}",
            current.node_info().capabilities()
        );
        assert!(
            controller.publish_peer_info(),
            "precondition: a node that needs no relay publishes once its mtus are known"
        );
        assert!(routing_table.serves_direct_bootstrap());
    }
    mock_registry::terminate(registry).await;
}

/// A bootstrap never hands out peer info that has expired
pub async fn test_bootstrap_peers_omit_expired_peer_info() {
    let registry = mock_registry::init("bootstrap_peers_expiration").await;
    {
        let routing_table = registry.routing_table();
        let network_manager = registry.network_manager();
        let crypto = registry.crypto();
        let current = fresh_peer_info(&routing_table, &crypto, test_dial_info(180), None);
        let expired = fresh_peer_info(
            &routing_table,
            &crypto,
            test_dial_info(181),
            Some(Timestamp::new(1)),
        );
        register(&routing_table, &current);
        register(&routing_table, &expired);

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

#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
fn legacy_record(dial_info_details: Vec<DialInfoDetail>) -> BootstrapRecord {
    BootstrapRecord::new(
        PublicKeyGroup::from(mock_public_keys()),
        VALID_ENVELOPE_VERSIONS.to_vec(),
        dial_info_details,
        Some(Timestamp::now().as_u64() / 1_000_000u64),
        vec![],
    )
}

#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
fn legacy_dial_info_details() -> Vec<DialInfoDetail> {
    let addr = SocketAddress::new(Address::IPV4(Ipv4Addr::new(1, 2, 3, 4)), 5150);
    vec![
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::udp(addr),
        },
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_ws(addr, "ws://1.2.3.4:5150/ws".to_owned())
                .expect("should make ws dialinfo"),
        },
        #[cfg(feature = "enable-protocol-wss")]
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_wss(addr, "wss://1.2.3.4:5150/wss".to_owned())
                .expect("should make wss dialinfo"),
        },
        #[cfg(feature = "enable-protocol-webtransport")]
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_stream(
                addr,
                "https://1.2.3.4:5150/wt".to_owned(),
                vec![],
                None,
            )
            .expect("should make wts dialinfo"),
        },
        #[cfg(feature = "enable-protocol-webtransport")]
        DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::try_webtransport_datagram(
                addr,
                "https://1.2.3.4:5150/wt".to_owned(),
                vec![],
                None,
            )
            .expect("should make wtd dialinfo"),
        },
    ]
}

/// The legacy short forms carry the protocol letter, port and path; the hostname is the line's
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub fn test_legacy_short_dial_info() {
    let shorts: Vec<String> = legacy_dial_info_details()
        .iter()
        .map(|did| to_short_dial_info(&did.dial_info).short_url)
        .collect();
    assert!(shorts.contains(&"U5150".to_owned()), "{shorts:?}");
    assert!(shorts.contains(&"W5150/ws".to_owned()), "{shorts:?}");
    #[cfg(feature = "enable-protocol-wss")]
    assert!(shorts.contains(&"S5150/wss".to_owned()), "{shorts:?}");
    #[cfg(feature = "enable-protocol-webtransport")]
    assert_eq!(
        shorts.iter().filter(|s| *s == "B5150/wt").count(),
        2,
        "the datagram half shares the stream's short form: {shorts:?}"
    );
}

/// Legacy lines are written against the hostname the operator names, an IP literal included,
/// and parse back for serving; a signed line verifies only with its key
#[cfg(feature = "enable-bootstrap-v1")]
pub async fn test_legacy_record_lines() {
    let registry = mock_registry::init("legacy_record_lines").await;
    {
        let network_manager = registry.network_manager();
        let record = legacy_record(legacy_dial_info_details());

        let line = record
            .to_v1_string(&network_manager, "1.2.3.4", mock_keypairs()[0].clone())
            .expect("should make v1 line");
        assert!(line.starts_with("1|"));
        assert!(line.contains("|1.2.3.4|"));
        let parsed = BootstrapRecord::try_new_from_v1_str(
            &network_manager,
            &line,
            &mock_signing_keys()[..1],
        )
        .expect("should parse v1 line");
        assert_eq!(parsed.public_keys(), record.public_keys());
        assert!(parsed.dial_info_details().is_empty());
        assert!(BootstrapRecord::try_new_from_v1_str(
            &network_manager,
            &line,
            &mock_signing_keys()[1..2]
        )
        .is_err());
        assert!(record
            .to_v1_string(&network_manager, " ", mock_keypairs()[0].clone())
            .is_err());

        #[cfg(feature = "enable-bootstrap-v0")]
        {
            let line = record
                .to_v0_string("bootstrap.example.com")
                .expect("should make v0 line");
            assert!(line.starts_with("0|"));
            let parsed = BootstrapRecord::try_new_from_v0_str(&line).expect("should parse v0 line");
            assert_eq!(parsed.public_keys(), record.public_keys());
        }
    }
    mock_registry::terminate(registry).await;
}

/// The JSON a 0.5.x node is answered with has 0.5.8's fields and only the dial info kinds and
/// protocols of a 0.5.x build without its optional WSS
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub async fn test_legacy_json_shape() {
    let registry = mock_registry::init("legacy_json_shape").await;
    {
        let routing_table = registry.routing_table();
        let crypto = registry.crypto();
        let kp = crypto.best().generate_keypair();
        let node_info = NodeInfo::new(
            Timestamp::now(),
            vec![ENVELOPE_VERSION_ENV0],
            vec![CryptoInfo::VLD0 {
                public_key: kp.ref_value().key(),
            }],
            CONNECTIVITY_CAPABILITIES.to_vec(),
            ProtocolTypeSet::all(),
            AddressTypeSet::all(),
            legacy_dial_info_details(),
            vec![],
            TransportMtus::default(),
            None,
        );
        let pi = PeerInfo::try_new_from_node_info(
            &routing_table,
            RoutingDomain::PublicInternet,
            &SecretKeyGroup::from(vec![kp.secret()]),
            node_info,
        )
        .expect("should sign peer info");

        let json = serialize_json(LegacyPeerInfo::from_peer_info(&pi));
        let value: serde_json::Value = serde_json::from_str(&json).expect("should be json");
        let keys = |v: &serde_json::Value| -> Vec<String> {
            v.as_object().expect("object").keys().cloned().collect()
        };
        let mut top = keys(&value);
        top.sort();
        assert_eq!(
            top,
            [
                "node_ids",
                "node_info",
                "node_info_message",
                "routing_domain",
                "signatures"
            ]
        );
        let mut inner = keys(&value["node_info"]);
        inner.sort();
        assert_eq!(
            inner,
            [
                "address_types",
                "capabilities",
                "crypto_info_list",
                "dial_info_detail_list",
                "envelope_support",
                "outbound_protocols",
                "relay_info_list",
                "timestamp"
            ]
        );
        let mut kinds: Vec<&str> = value["node_info"]["dial_info_detail_list"]
            .as_array()
            .expect("array")
            .iter()
            .map(|did| did["dial_info"]["kind"].as_str().expect("kind"))
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            ["UDP", "WS"],
            "the fixture's other kinds are left out"
        );
        assert_eq!(
            value["node_info"]["outbound_protocols"].as_u64(),
            Some(0b111),
            "UDP, TCP and WS, the bits 0.5.8 gave them"
        );
        assert!(value["node_info_message"].is_array());
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_bootstrap_entry_forms() {
    for (entry, expected) in [
        (
            "bootstrap.test",
            Some(("bootstrap.test", BOOTSTRAP_DIRECT_PORT)),
        ),
        ("bootstrap.test:443", Some(("bootstrap.test", 443))),
        (
            "18.218.0.160",
            Some(("18.218.0.160", BOOTSTRAP_DIRECT_PORT)),
        ),
        ("18.218.0.160:443", Some(("18.218.0.160", 443))),
        (
            "2001:db8::1",
            Some(("[2001:db8::1]", BOOTSTRAP_DIRECT_PORT)),
        ),
        (
            "[2001:db8::1]",
            Some(("[2001:db8::1]", BOOTSTRAP_DIRECT_PORT)),
        ),
        ("[2001:db8::1]:443", Some(("[2001:db8::1]", 443))),
        ("bootstrap.test:port", None),
        ("boot strap.test", None),
        ("", None),
    ] {
        assert_eq!(
            split_bootstrap_entry(entry),
            expected.map(|(host, port)| (host.to_owned(), port)),
            "{entry:?}"
        );
    }

    // An address entry becomes a dial info without any lookup, in either family
    let converter = BootstrapDialInfoConverter::default();
    for (url, address) in [
        ("tcp://18.218.0.160:5150", "18.218.0.160"),
        ("tcp://[2001:db8::1]:5150", "2001:db8::1"),
        #[cfg(feature = "enable-protocol-wss")]
        ("wss://[2001:db8::1]:5150/ws", "2001:db8::1"),
    ] {
        let dial_infos = converter
            .try_vec_from_url(url)
            .await
            .expect("address url should convert");
        assert_eq!(dial_infos.len(), 1, "{url}");
        assert_eq!(
            dial_infos[0].to_socket_addr().ip(),
            IpAddr::from_str(address).expect("address"),
            "{url}"
        );
    }
}
