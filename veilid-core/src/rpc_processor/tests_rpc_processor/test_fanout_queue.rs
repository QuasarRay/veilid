use super::*;
use crate::routing_table::tests_routing_table::mocks::*;
use crate::tests::*;

pub const CONSENSUS_COUNT: usize = 5;
const COLLECTION_COUNT: usize = 8;
pub const CONSENSUS_WIDTH: usize = 10;
pub const SEED_COUNT: usize = 20;

fn make_distinct_peer_info(routing_table: &RoutingTable) -> PeerInfo {
    let mut crypto_info_list: Vec<CryptoInfo> = vec![];
    let mut secret_keys = SecretKeyGroup::new();
    for ck in VALID_CRYPTO_KINDS {
        let (public_key, secret) = Crypto::generate_keypair(ck)
            .expect("should generate keypair")
            .value()
            .into_split();
        let ci = match ck {
            #[cfg(feature = "enable-crypto-none")]
            CRYPTO_KIND_NONE => CryptoInfo::NONE { public_key },
            #[cfg(feature = "enable-crypto-vld0")]
            CRYPTO_KIND_VLD0 => CryptoInfo::VLD0 { public_key },
            _ => {
                unreachable!("missing match arm");
            }
        };
        crypto_info_list.push(ci);
        secret_keys.add(SecretKey::new(ck, secret));
    }
    fix_peer_info(routing_table, crypto_info_list, secret_keys).expect("should be valid")
}

pub fn seed_nodes(routing_table: &RoutingTable, count: usize) -> Vec<NodeRef> {
    (0..count)
        .map(|_| {
            let pi = make_distinct_peer_info(routing_table);
            routing_table
                .register_node_with_peer_info(Arc::new(pi), false)
                .expect("should register")
                .unfiltered()
        })
        .collect()
}

fn make_queue<'a>(
    registry: &VeilidComponentRegistry,
    collection_count: usize,
    opt_throttle_duration: Option<TimestampDuration>,
) -> FanoutQueue<'a> {
    let target = fix_typed_node_id(CRYPTO_KIND_VLD0, 0).to_hash_coordinate();
    FanoutQueue::new(
        "test".to_string(),
        registry.clone(),
        CRYPTO_KIND_VLD0,
        Box::new(RoutingTable::make_closest_node_id_sort(target)),
        CONSENSUS_COUNT,
        collection_count,
        CONSENSUS_WIDTH,
        opt_throttle_duration,
    )
}

fn count_stage(queue: &FanoutQueue, stage: FanoutNodeStage) -> usize {
    queue.with_nodes(|nodes, sorted_nodes| {
        sorted_nodes
            .iter()
            .filter(|x| {
                core::mem::discriminant(&nodes.get(*x).unwrap_or_log().status.stage())
                    == core::mem::discriminant(&stage)
            })
            .count()
    })
}

fn take_work(queue: &mut FanoutQueue) -> FanoutWorkItem {
    try_take_work(queue).expect("should have work")
}

fn try_take_work(queue: &mut FanoutQueue) -> Option<FanoutWorkItem> {
    let work_receiver = queue
        .request_work("test-lane".to_string())
        .expect("should request work");
    work_receiver.try_recv().ok()
}

/// A full seed must survive `update()` untouched: with no answers yet, no node may be
/// width-disqualified before a single RPC is attempted
pub async fn test_seed_keeps_full_reserve() {
    let registry = mock_registry::init("fanout_queue").await;
    {
        let routing_table = registry.routing_table();
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);

        let mut queue = make_queue(&registry, CONSENSUS_COUNT, None);
        queue.update(&node_refs, Timestamp::now_non_decreasing());

        assert_eq!(count_stage(&queue, FanoutNodeStage::Queued), SEED_COUNT);
        assert_eq!(count_stage(&queue, FanoutNodeStage::Disqualified), 0);
    }
    mock_registry::terminate(registry).await;
}

/// Once `consensus_width` closer nodes hold terminal answers, the reserve can never
/// matter and is culled
pub async fn test_answered_window_culls_reserve() {
    let registry = mock_registry::init("fanout_queue").await;
    {
        let routing_table = registry.routing_table();
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);

        let mut queue = make_queue(&registry, CONSENSUS_COUNT, None);
        queue.update(&node_refs, Timestamp::now_non_decreasing());

        // Accept the closest CONSENSUS_WIDTH nodes; dispatch order is closest-first
        for _ in 0..CONSENSUS_WIDTH {
            let work_item = take_work(&mut queue);
            queue.accepted(work_item.node_ref, Timestamp::now_non_decreasing());
        }
        queue.update(&[], Timestamp::now_non_decreasing());

        assert_eq!(
            count_stage(&queue, FanoutNodeStage::Accepted),
            CONSENSUS_WIDTH
        );
        assert_eq!(
            count_stage(&queue, FanoutNodeStage::Disqualified),
            SEED_COUNT - CONSENSUS_WIDTH
        );
    }
    mock_registry::terminate(registry).await;
}

/// Timeouts hold no window slot, so a failing closest set leaves the reserve alive
/// and dispatchable
pub async fn test_timeouts_promote_reserve() {
    let registry = mock_registry::init("fanout_queue").await;
    {
        let routing_table = registry.routing_table();
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);

        let mut queue = make_queue(&registry, CONSENSUS_COUNT, None);
        queue.update(&node_refs, Timestamp::now_non_decreasing());

        // Closest ten: four accept, six time out
        for n in 0..CONSENSUS_WIDTH {
            let work_item = take_work(&mut queue);
            if n < 4 {
                queue.accepted(work_item.node_ref, Timestamp::now_non_decreasing());
            } else {
                queue.timeout(work_item.node_ref, Timestamp::now_non_decreasing());
            }
        }
        queue.update(&[], Timestamp::now_non_decreasing());

        assert_eq!(count_stage(&queue, FanoutNodeStage::Accepted), 4);
        assert_eq!(count_stage(&queue, FanoutNodeStage::Timeout), 6);
        assert_eq!(
            count_stage(&queue, FanoutNodeStage::Queued),
            SEED_COUNT - CONSENSUS_WIDTH
        );
        assert_eq!(count_stage(&queue, FanoutNodeStage::Disqualified), 0);

        // The reserve is dispatchable
        let work_item = take_work(&mut queue);
        queue.accepted(work_item.node_ref, Timestamp::now_non_decreasing());
        assert_eq!(count_stage(&queue, FanoutNodeStage::Accepted), 5);
    }
    mock_registry::terminate(registry).await;
}

/// A throttled queue keeps dispatching reserve candidates after consensus until the
/// collection target, then stops; with no collection target it stops at consensus
pub async fn test_collection_dispatches_reserve_after_consensus() {
    let registry = mock_registry::init("fanout_queue").await;
    {
        let routing_table = registry.routing_table();
        let throttle = Some(TimestampDuration::new_secs(10));

        // Collection target 8: dispatch continues from accept 5 through 8, then stops
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);
        let mut queue = make_queue(&registry, COLLECTION_COUNT, throttle);
        queue.update(&node_refs, Timestamp::now_non_decreasing());
        for _ in 0..COLLECTION_COUNT {
            let work_item = take_work(&mut queue);
            queue.accepted(work_item.node_ref, Timestamp::now_non_decreasing());
        }
        assert!(try_take_work(&mut queue).is_none());
        assert_eq!(
            count_stage(&queue, FanoutNodeStage::Accepted),
            COLLECTION_COUNT
        );
        assert_eq!(count_stage(&queue, FanoutNodeStage::Disqualified), 0);

        // No collection target: dispatch stops at consensus
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);
        let mut queue = make_queue(&registry, CONSENSUS_COUNT, throttle);
        queue.update(&node_refs, Timestamp::now_non_decreasing());
        for _ in 0..CONSENSUS_COUNT {
            let work_item = take_work(&mut queue);
            queue.accepted(work_item.node_ref, Timestamp::now_non_decreasing());
        }
        assert!(try_take_work(&mut queue).is_none());
        assert_eq!(
            count_stage(&queue, FanoutNodeStage::Accepted),
            CONSENSUS_COUNT
        );
    }
    mock_registry::terminate(registry).await;
}

/// Rejection consensus still ends the fanout: `consensus_count` consecutive rejections
/// disqualify everything unfinished (transaction mutual exclusion depends on this)
pub async fn test_rejection_consensus_culls_everything() {
    let registry = mock_registry::init("fanout_queue").await;
    {
        let routing_table = registry.routing_table();
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);

        let mut queue = make_queue(&registry, CONSENSUS_COUNT, None);
        queue.update(&node_refs, Timestamp::now_non_decreasing());

        for _ in 0..CONSENSUS_COUNT {
            let work_item = take_work(&mut queue);
            queue.rejected(work_item.node_ref, Timestamp::now_non_decreasing());
        }

        assert_eq!(
            count_stage(&queue, FanoutNodeStage::Rejected),
            CONSENSUS_COUNT
        );
        assert_eq!(
            count_stage(&queue, FanoutNodeStage::Disqualified),
            SEED_COUNT - CONSENSUS_COUNT
        );
    }
    mock_registry::terminate(registry).await;
}
