use super::*;
mod test_dial_info;
mod test_fanout_call;
mod test_fanout_queue;
mod test_signed_value_data;

pub async fn test_all() {
    test_fanout_queue::test_seed_keeps_full_reserve().await;
    test_fanout_queue::test_answered_window_culls_reserve().await;
    test_fanout_queue::test_timeouts_promote_reserve().await;
    test_fanout_queue::test_collection_dispatches_reserve_after_consensus().await;
    test_fanout_call::test_collection_converges_thin_consensus().await;
    test_fanout_call::test_no_collection_stops_at_consensus().await;
    test_fanout_call::test_collection_exhausted_below_target_bounded_exit().await;
    test_fanout_call::test_all_stale_exhausts_quickly().await;
    test_fanout_call::test_holders_behind_stale_nodes_are_asked().await;
    test_fanout_call::test_few_stale_nodes_reach_consensus().await;
    test_fanout_call::test_straggler_cut_when_consensus_unreachable().await;
    test_fanout_call::test_late_holder_inside_grace_counts().await;
    test_fanout_call::test_straggler_waited_for_while_consensus_reachable().await;
    test_fanout_queue::test_rejection_consensus_culls_everything().await;
    test_fanout_queue::test_preferred_nodes_lead_the_sort().await;
    test_fanout_queue::test_no_preference_leaves_order_untouched().await;
    test_fanout_queue::test_routed_unresponsive_nodes_trail_the_sort().await;
    test_fanout_queue::test_next_straggler_cut_matches_the_cut().await;
    test_signed_value_data::test_encode_and_decode_signed_value_data();
    test_dial_info::test_encode_and_decode_dial_info_udp();
    test_dial_info::test_encode_and_decode_dial_info_tcp();
    test_dial_info::test_encode_and_decode_dial_info_ws();
    #[cfg(feature = "enable-protocol-wss")]
    test_dial_info::test_encode_and_decode_dial_info_wss();
    test_dial_info::test_decode_dial_info_rejects_unspecified_ipv4();
    test_dial_info::test_decode_dial_info_rejects_unspecified_ipv6();
}
