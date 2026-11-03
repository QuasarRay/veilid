use super::*;
use crate::tests::*;

fn current_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 170)), 5150)
}

fn expired_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 171)), 5150)
}

fn peer_info_expiring_at(
    routing_table: &RoutingTable,
    crypto_info_list: Vec<CryptoInfo>,
    socket_address: SocketAddress,
    expiration: Option<Timestamp>,
) -> Arc<PeerInfo> {
    let node_info = NodeInfo::new(
        Timestamp::new(0),
        vec![ENVELOPE_VERSION_ENV0],
        crypto_info_list,
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
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

pub async fn test_expired_peer_info_is_not_returned_to_askers() {
    let registry = mock_registry::init("peer_info_expiration").await;
    {
        let routing_table = registry.routing_table();

        let current = peer_info_expiring_at(
            &routing_table,
            fix_crypto_info_list(true),
            current_socket_address(),
            None,
        );
        let expired = peer_info_expiring_at(
            &routing_table,
            fix_crypto_info_list(false),
            expired_socket_address(),
            Some(Timestamp::new(1)),
        );

        let _current_nr = routing_table
            .register_node_with_peer_info(
                Arc::new(UnverifiedPeerInfo::from_verified(&current)),
                true,
            )
            .expect("should register the current node");
        let _expired_nr = routing_table
            .register_node_with_peer_info(
                Arc::new(UnverifiedPeerInfo::from_verified(&expired)),
                true,
            )
            .expect("should register the expired node");

        let crypto_kind = VALID_CRYPTO_KINDS[0];
        let hash_coordinate = routing_table.node_id(crypto_kind).to_hash_coordinate();
        let answers = routing_table.get_preferred_closest_nodes_peer_info(
            RoutingDomain::PublicInternet,
            hash_coordinate,
            &[],
        );

        let answered_node_ids: Vec<NodeIdGroup> =
            answers.iter().map(|pi| pi.node_ids().clone()).collect();
        assert!(
            answered_node_ids.contains(current.node_ids()),
            "a node whose peer info has not expired must still be answered: {answered_node_ids:?}"
        );
        assert!(
            !answered_node_ids.contains(expired.node_ids()),
            "a node whose peer info has expired must not be answered: {answered_node_ids:?}"
        );

        let expired_node_id = expired
            .node_ids()
            .get(crypto_kind)
            .expect("the expired peer info should have a node id of the crypto kind under test");
        assert!(
            routing_table
                .lookup_node_id(expired_node_id)
                .expect("lookup should succeed")
                .is_some(),
            "the expired node must still be in the routing table, just not answerable"
        );
    }
    mock_registry::terminate(registry).await;
}

fn peer_info_for_node_id(
    routing_table: &RoutingTable,
    node_id: &BareNodeId,
    socket_address: SocketAddress,
    expiration: Option<Timestamp>,
) -> Arc<PeerInfo> {
    peer_info_expiring_at(
        routing_table,
        vec![CryptoInfo::VLD0 {
            public_key: BarePublicKey::new(&node_id.to_vec()),
        }],
        socket_address,
        expiration,
    )
}

fn crowded_bucket_node_ids(routing_table: &RoutingTable) -> (BareNodeId, BareNodeId) {
    let mut first = routing_table.node_id(CRYPTO_KIND_VLD0).ref_value().to_vec();
    first[1] ^= 0x80;
    let mut second = first.clone();
    second[31] ^= 0x01;
    let (first, second) = (BareNodeId::new(&first), BareNodeId::new(&second));

    let index_of = |id: &BareNodeId| {
        routing_table
            .calculate_bucket_index(&NodeId::new(CRYPTO_KIND_VLD0, id.clone()))
            .expect("should calculate a bucket index")
    };
    let bucket_index = index_of(&first);
    assert_eq!(
        bucket_index,
        index_of(&second),
        "both node ids must land in the same bucket"
    );
    assert_eq!(
        RoutingTable::bucket_depth(bucket_index.1),
        1,
        "the bucket must hold one entry for two entries to overflow it"
    );

    (first, second)
}

fn make_dead(entry: &Arc<BucketEntry>) {
    entry.with_mut(|e| e.unreachable());
}

fn make_responsive(entry: &Arc<BucketEntry>) {
    let unreliable_answer = LivenessSpans::new(TimestampDuration::new_ms(
        VeilidConfigInternalRPC::default().timeout_ms.into(),
    ))
    .unreliable_answer;
    let answered_ts = Timestamp::new(Timestamp::now().as_u64() - 10 * unreliable_answer.as_u64());
    entry.with_mut(|e| {
        e.answer_rcvd(
            answered_ts,
            answered_ts,
            ByteCount::new(0),
            TransportType::new(ProtocolType::TCP, AddressType::IPV4),
            true,
        )
    });
}

fn bucket_entry(routing_table: &RoutingTable, node_id: &BareNodeId) -> Arc<BucketEntry> {
    let bucket_index = routing_table
        .calculate_bucket_index(&NodeId::new(CRYPTO_KIND_VLD0, node_id.clone()))
        .expect("should calculate a bucket index");
    let inner = routing_table.inner.read();
    inner
        .get_bucket(bucket_index)
        .entry(node_id)
        .expect("the entry should be registered")
}

pub async fn test_expired_responsive_entry_is_evicted_after_dead() {
    let registry = mock_registry::init("expired_eviction_order").await;
    {
        let routing_table = registry.routing_table();
        let mut bucket = Bucket::new(
            registry.clone(),
            Arc::new(ArcSwapOption::empty()),
            CRYPTO_KIND_VLD0,
        );

        let dead_id = BareNodeId::new(&[1u8; 32]);
        let expired_id = BareNodeId::new(&[2u8; 32]);
        let dead = bucket.add_new_entry(dead_id.clone());
        let expired = bucket.add_new_entry(expired_id.clone());

        dead.with_mut(|e| {
            e.update_peer_info(
                RoutingDomain::PublicInternet,
                peer_info_for_node_id(&routing_table, &dead_id, current_socket_address(), None),
            )
        });
        expired.with_mut(|e| {
            e.update_peer_info(
                RoutingDomain::PublicInternet,
                peer_info_for_node_id(
                    &routing_table,
                    &expired_id,
                    expired_socket_address(),
                    Some(Timestamp::new(1)),
                ),
            )
        });
        make_dead(&dead);
        make_responsive(&expired);

        let cur_ts = Timestamp::now();
        assert_eq!(
            dead.with(|e| e.state(cur_ts)),
            BucketEntryState::Dead,
            "precondition: the entry with a current record is dead"
        );
        assert!(
            expired.with(|e| e.state(cur_ts).is_responsive()),
            "precondition: the entry with an expired record still answers"
        );
        assert!(
            expired.with(|e| e.has_peer_info_and_all_expired(cur_ts)),
            "precondition: that entry's peer info has expired"
        );

        let kicked = bucket
            .kick(1, &BTreeSet::new())
            .expect("an over-capacity bucket must evict an entry");

        assert!(
            kicked.contains(&dead_id),
            "the dead entry must be evicted first: {kicked:?}"
        );
        assert!(
            !kicked.contains(&expired_id),
            "a responsive entry must not be evicted ahead of a dead one because its peer \
             info expired: {kicked:?}"
        );
    }
    mock_registry::terminate(registry).await;
}

pub async fn test_expired_responsive_entry_keeps_closest_exemption() {
    let registry = mock_registry::init("expired_closest_exemption").await;
    {
        let routing_table = registry.routing_table();
        let (current_id, expired_id) = crowded_bucket_node_ids(&routing_table);

        routing_table
            .register_node_with_peer_info(
                Arc::new(UnverifiedPeerInfo::from_verified(&peer_info_for_node_id(
                    &routing_table,
                    &current_id,
                    current_socket_address(),
                    None,
                ))),
                true,
            )
            .expect("should register the current node");
        routing_table
            .register_node_with_peer_info(
                Arc::new(UnverifiedPeerInfo::from_verified(&peer_info_for_node_id(
                    &routing_table,
                    &expired_id,
                    expired_socket_address(),
                    Some(Timestamp::new(1)),
                ))),
                true,
            )
            .expect("should register the expired node");

        let current = bucket_entry(&routing_table, &current_id);
        let expired = bucket_entry(&routing_table, &expired_id);
        make_responsive(&current);
        make_responsive(&expired);

        let cur_ts = Timestamp::now();
        assert!(
            expired.with(
                |e| e.state(cur_ts).is_responsive() && e.has_peer_info_and_all_expired(cur_ts)
            ),
            "precondition: the expired entry still answers"
        );

        routing_table
            .kick_buckets_task_routine(
                StopSource::new().token(),
                Timestamp::new(0),
                Timestamp::now(),
            )
            .expect("kicking buckets should succeed");

        for (name, node_id) in [("current", &current_id), ("expired", &expired_id)] {
            assert!(
                routing_table
                    .lookup_node_id(NodeId::new(CRYPTO_KIND_VLD0, node_id.clone()))
                    .expect("lookup should succeed")
                    .is_some(),
                "the {name} entry is among the closest peers and must survive the kick"
            );
        }
    }
    mock_registry::terminate(registry).await;
}
