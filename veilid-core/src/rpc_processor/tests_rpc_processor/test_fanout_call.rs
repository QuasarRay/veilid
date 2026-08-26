use super::test_fanout_queue::{seed_nodes, CONSENSUS_COUNT, CONSENSUS_WIDTH, SEED_COUNT};
use super::*;
use crate::routing_table::tests_routing_table::mocks::*;
use crate::tests::*;

const COLLECTION_COUNT: usize = 8;

fn rank_map(node_refs: &[NodeRef], target: &HashCoordinate) -> HashMap<NodeId, usize> {
    let mut ids: Vec<NodeId> = node_refs
        .iter()
        .map(|nr| nr.node_ids().get(CRYPTO_KIND_VLD0).unwrap_or_log())
        .collect();
    ids.sort_unstable_by(RoutingTable::make_closest_node_id_sort(target.clone()));
    ids.into_iter().enumerate().map(|(n, id)| (id, n)).collect()
}

/// Scripted network: closest CONSENSUS_COUNT accept, next CONSENSUS_COUNT time out,
/// the reserve accepts or times out
fn make_call_routine(ranks: HashMap<NodeId, usize>, reserve_accepts: bool) -> FanoutCallRoutine {
    Arc::new(move |node_ref: NodeRef| {
        let rank = node_ref
            .node_ids()
            .get(CRYPTO_KIND_VLD0)
            .and_then(|id| ranks.get(&id).copied())
            .unwrap_or_log();
        Box::pin(async move {
            let disposition =
                if rank < CONSENSUS_COUNT || (reserve_accepts && rank >= CONSENSUS_COUNT * 2) {
                    FanoutCallDisposition::Accepted
                } else {
                    FanoutCallDisposition::Timeout
                };
            Ok(FanoutCallOutput {
                peer_info_list: vec![],
                disposition,
            })
        }) as PinBoxFutureStatic<FanoutCallResult>
    })
}

fn make_begin_style_check_done() -> FanoutCheckDone {
    Arc::new(|fanout_result: &FanoutResult| match fanout_result.kind {
        FanoutResultKind::Incomplete => FanoutDoneDisposition::NotDone,
        FanoutResultKind::Timeout | FanoutResultKind::Exhausted => FanoutDoneDisposition::DoneEarly,
        FanoutResultKind::Consensus => {
            if fanout_result.consensus_nodes.len() >= COLLECTION_COUNT {
                FanoutDoneDisposition::DoneEarly
            } else {
                FanoutDoneDisposition::Done
            }
        }
    })
}

/// Returns (result kind, consensus node count); NodeRefs must drop before terminate
async fn run_scripted_fanout(collect: bool, reserve_accepts: bool) -> (FanoutResultKind, usize) {
    let registry = mock_registry::init("fanout_call").await;
    let (kind, consensus_len) = {
        let routing_table = registry.routing_table();
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);
        let target = fix_typed_node_id(CRYPTO_KIND_VLD0, 0).to_hash_coordinate();
        let ranks = rank_map(&node_refs, &target);

        let mut fanout_call = FanoutCall::new(
            &routing_table,
            FanoutCallParams {
                name: "test_fanout_call".to_string(),
                hash_coordinate: target,
                node_count: SEED_COUNT,
                fanout_tasks: 6,
                consensus_count: CONSENSUS_COUNT,
                consensus_width: CONSENSUS_WIDTH,
                timeout: TimestampDuration::new_secs(10),
            },
            empty_fanout_peer_info_filter(),
            make_call_routine(ranks, reserve_accepts),
            make_begin_style_check_done(),
        )
        .with_post_consensus_timeout_callback(Arc::new(|_| TimestampDuration::new_ms(500)));
        if collect {
            fanout_call.set_collection_count(COLLECTION_COUNT);
        }

        let stop_source = StopSource::new();
        let result = fanout_call
            .run(
                node_refs,
                FanoutQueueMode::ThrottleAtConsensus,
                stop_source.token(),
            )
            .await
            .expect("fanout should run");
        (result.kind, result.consensus_nodes.len())
    };
    mock_registry::terminate(registry).await;
    (kind, consensus_len)
}

/// With a collection target, a consensus met among a failing closest set keeps
/// dispatching the reserve until the full headroom is collected
pub async fn test_collection_converges_thin_consensus() {
    let (kind, consensus_len) = run_scripted_fanout(true, true).await;
    assert!(matches!(kind, FanoutResultKind::Consensus));
    assert_eq!(consensus_len, COLLECTION_COUNT);
}

/// Without a collection target, dispatch stops at consensus and only in-flight
/// lanes can add accepts
pub async fn test_no_collection_stops_at_consensus() {
    let (kind, consensus_len) = run_scripted_fanout(false, true).await;
    assert!(matches!(kind, FanoutResultKind::Consensus));
    assert!(consensus_len < COLLECTION_COUNT);
}

/// A collecting run whose queue exhausts below the target still returns the thin
/// consensus, exiting via the post-consensus window rather than the full timeout
pub async fn test_collection_exhausted_below_target_bounded_exit() {
    let start_ts = Timestamp::now_non_decreasing();
    let (kind, consensus_len) = run_scripted_fanout(true, false).await;
    assert!(matches!(kind, FanoutResultKind::Consensus));
    assert_eq!(consensus_len, CONSENSUS_COUNT);
    // Well under the 10s fanout timeout; the 500ms rolling window is the exit
    let elapsed = Timestamp::now_non_decreasing().duration_since(start_ts);
    assert!(elapsed < TimestampDuration::new_secs(5), "took {}", elapsed);
}
