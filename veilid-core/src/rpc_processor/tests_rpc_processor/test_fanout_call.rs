use super::test_fanout_queue::{CONSENSUS_COUNT, CONSENSUS_WIDTH, SEED_COUNT};
use super::*;
use crate::routing_table::tests_routing_table::mocks::*;
use crate::tests::*;

const COLLECTION_COUNT: usize = 8;

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

/// Returns (result kind, consensus node count, fanout run time); NodeRefs must drop before
/// terminate. The run time excludes registry startup and shutdown, which dominate under load
async fn run_scripted_fanout(
    collect: bool,
    reserve_accepts: bool,
) -> (FanoutResultKind, usize, TimestampDuration) {
    let registry = mock_registry::init("fanout_call").await;
    let (kind, consensus_len, elapsed) = {
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
        let start_ts = Timestamp::now_non_decreasing();
        let result = fanout_call
            .run(
                node_refs,
                FanoutQueueMode::ThrottleAtConsensus,
                stop_source.token(),
            )
            .await
            .expect("fanout should run");
        let elapsed = Timestamp::now_non_decreasing().duration_since(start_ts);
        (result.kind, result.consensus_nodes.len(), elapsed)
    };
    mock_registry::terminate(registry).await;
    (kind, consensus_len, elapsed)
}

/// With a collection target, a consensus met among a failing closest set keeps
/// dispatching the reserve until the full headroom is collected
pub async fn test_collection_converges_thin_consensus() {
    let (kind, consensus_len, _) = run_scripted_fanout(true, true).await;
    assert!(matches!(kind, FanoutResultKind::Consensus));
    assert_eq!(consensus_len, COLLECTION_COUNT);
}

/// Without a collection target, dispatch stops at consensus and only in-flight
/// lanes can add accepts
pub async fn test_no_collection_stops_at_consensus() {
    let (kind, consensus_len, _) = run_scripted_fanout(false, true).await;
    assert!(matches!(kind, FanoutResultKind::Consensus));
    assert!(consensus_len < COLLECTION_COUNT);
}

/// A collecting run whose queue exhausts below the target still returns the thin
/// consensus, exiting via the post-consensus window rather than the full timeout
pub async fn test_collection_exhausted_below_target_bounded_exit() {
    let (kind, consensus_len, elapsed) = run_scripted_fanout(true, false).await;
    assert!(matches!(kind, FanoutResultKind::Consensus));
    assert_eq!(consensus_len, CONSENSUS_COUNT);
    // Well under the 10s fanout timeout; the 500ms rolling window is the exit
    assert!(elapsed < TimestampDuration::new_secs(5), "took {}", elapsed);
}

/// Get-shaped: consensus 3 over five lanes
const GET_CONSENSUS_COUNT: usize = 3;
const GET_FANOUT_TASKS: usize = 5;
/// A run that ends this fast never waited out its 1s timeout
const QUICK: TimestampDuration = TimestampDuration::new_ms(500);

/// A get-shaped fanout where each rank answers `script(rank)`, a delay in ms and a disposition;
/// returns (result kind, consensus node count, fanout run time)
async fn run_get_fanout(
    timeout: TimestampDuration,
    script: impl Fn(usize) -> (u32, FanoutCallDisposition) + Send + Sync + 'static,
) -> (FanoutResultKind, usize, TimestampDuration) {
    let registry = mock_registry::init("fanout_get").await;
    let out = {
        let routing_table = registry.routing_table();
        let node_refs = seed_nodes(&routing_table, SEED_COUNT);
        let target = fix_typed_node_id(CRYPTO_KIND_VLD0, 0).to_hash_coordinate();
        let ranks = rank_map(&node_refs, &target);
        let script = Arc::new(script);
        let call_routine: FanoutCallRoutine = Arc::new(move |node_ref: NodeRef| {
            let rank = node_ref
                .node_ids()
                .get(CRYPTO_KIND_VLD0)
                .and_then(|id| ranks.get(&id).copied())
                .unwrap_or_log();
            let (delay_ms, disposition) = script(rank);
            Box::pin(async move {
                sleep(delay_ms).await;
                Ok(FanoutCallOutput {
                    peer_info_list: vec![],
                    disposition,
                })
            }) as PinBoxFutureStatic<FanoutCallResult>
        });
        let check_done: FanoutCheckDone =
            Arc::new(|fanout_result: &FanoutResult| match fanout_result.kind {
                FanoutResultKind::Incomplete => FanoutDoneDisposition::NotDone,
                FanoutResultKind::Timeout
                | FanoutResultKind::Exhausted
                | FanoutResultKind::Consensus => FanoutDoneDisposition::DoneEarly,
            });
        let fanout_call = FanoutCall::new(
            &routing_table,
            FanoutCallParams {
                name: "test_fanout_get".to_string(),
                hash_coordinate: target,
                node_count: SEED_COUNT,
                fanout_tasks: GET_FANOUT_TASKS,
                consensus_count: GET_CONSENSUS_COUNT,
                consensus_width: CONSENSUS_WIDTH,
                timeout,
            },
            empty_fanout_peer_info_filter(),
            call_routine,
            check_done,
        );

        let stop_source = StopSource::new();
        let start_ts = Timestamp::now_non_decreasing();
        let result = fanout_call
            .run(
                node_refs,
                FanoutQueueMode::ThrottleAtConsensus,
                stop_source.token(),
            )
            .await
            .expect("fanout should run");
        let elapsed = Timestamp::now_non_decreasing().duration_since(start_ts);
        (result.kind, result.consensus_nodes.len(), elapsed)
    };
    mock_registry::terminate(registry).await;
    out
}

/// A get-shaped fanout with a 1s timeout where the ranks `stale` picks answer Stale and the rest
/// accept, each after 10ms
async fn run_stale_fanout(
    stale: impl Fn(usize) -> bool + Send + Sync + 'static,
) -> (FanoutResultKind, usize, TimestampDuration) {
    run_get_fanout(TimestampDuration::new_secs(1), move |rank| {
        let disposition = if stale(rank) {
            FanoutCallDisposition::Stale
        } else {
            FanoutCallDisposition::Accepted
        };
        (10, disposition)
    })
    .await
}

/// Stale answers fill no quota, so a fanout where every node is stale asks the whole window and
/// ends long before its timeout
pub async fn test_all_stale_exhausts_quickly() {
    let (kind, consensus_len, elapsed) = run_stale_fanout(|_| true).await;
    assert!(matches!(kind, FanoutResultKind::Exhausted), "{:?}", kind);
    assert_eq!(consensus_len, 0);
    assert!(elapsed < QUICK, "took {:#}", elapsed);
}

/// Holders behind seven stale nodes are still in the window, so they are asked
pub async fn test_holders_behind_stale_nodes_are_asked() {
    let (kind, consensus_len, elapsed) = run_stale_fanout(|rank| rank < 7).await;
    assert!(matches!(kind, FanoutResultKind::Consensus), "{:?}", kind);
    assert_eq!(consensus_len, GET_CONSENSUS_COUNT);
    assert!(elapsed < QUICK, "took {:#}", elapsed);
}

/// Two stale nodes ahead of the holders leave consensus within reach of the first wave
pub async fn test_few_stale_nodes_reach_consensus() {
    let (kind, consensus_len, elapsed) = run_stale_fanout(|rank| rank < 2).await;
    assert!(matches!(kind, FanoutResultKind::Consensus), "{:?}", kind);
    assert!(consensus_len >= GET_CONSENSUS_COUNT);
    assert!(elapsed < QUICK, "took {:#}", elapsed);
}

/// How long a straggler takes to answer; the mock's 3s rpc timeout makes its slow-node
/// threshold 990ms
const STRAGGLER_MS: u32 = 2500;
/// Long enough that only the nodes' answers can end a straggler run
const STRAGGLER_FANOUT_TIMEOUT: TimestampDuration = TimestampDuration::new_secs(10);

/// A node still in flight once the rest of the window has answered and consensus is out of
/// reach is cut off at the slow-node threshold rather than waited out
pub async fn test_straggler_cut_when_consensus_unreachable() {
    let (kind, consensus_len, elapsed) = run_get_fanout(STRAGGLER_FANOUT_TIMEOUT, |rank| {
        if rank == 0 {
            (STRAGGLER_MS, FanoutCallDisposition::Timeout)
        } else {
            (10, FanoutCallDisposition::Stale)
        }
    })
    .await;
    assert!(matches!(kind, FanoutResultKind::Exhausted), "{:?}", kind);
    assert_eq!(consensus_len, 0);
    assert!(
        elapsed < TimestampDuration::new_ms(2000),
        "took {:#}",
        elapsed
    );
}

/// A lone holder that answers inside the grace still counts
pub async fn test_late_holder_inside_grace_counts() {
    let (kind, consensus_len, _) = run_get_fanout(STRAGGLER_FANOUT_TIMEOUT, |rank| {
        if rank == 0 {
            (300, FanoutCallDisposition::Accepted)
        } else {
            (10, FanoutCallDisposition::Stale)
        }
    })
    .await;
    assert!(matches!(kind, FanoutResultKind::Exhausted), "{:?}", kind);
    assert_eq!(consensus_len, 1);
}

/// A node in flight that can still complete consensus is waited for
pub async fn test_straggler_waited_for_while_consensus_reachable() {
    let (kind, consensus_len, elapsed) =
        run_get_fanout(STRAGGLER_FANOUT_TIMEOUT, |rank| match rank {
            0 | 1 => (10, FanoutCallDisposition::Accepted),
            2 => (STRAGGLER_MS, FanoutCallDisposition::Accepted),
            _ => (10, FanoutCallDisposition::Stale),
        })
        .await;
    assert!(matches!(kind, FanoutResultKind::Consensus), "{:?}", kind);
    assert_eq!(consensus_len, GET_CONSENSUS_COUNT);
    assert!(
        elapsed >= TimestampDuration::new_ms(STRAGGLER_MS.into()),
        "took {:#}",
        elapsed
    );
}
