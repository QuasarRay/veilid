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
    test_fanout_queue::test_rejection_consensus_culls_everything().await;
    test_signed_value_data::test_encode_and_decode_signed_value_data();
    test_dial_info::test_encode_and_decode_dial_info_udp();
    test_dial_info::test_encode_and_decode_dial_info_tcp();
    test_dial_info::test_encode_and_decode_dial_info_ws();
    #[cfg(feature = "enable-protocol-wss")]
    test_dial_info::test_encode_and_decode_dial_info_wss();
    test_dial_info::test_decode_dial_info_rejects_unspecified_ipv4();
    test_dial_info::test_decode_dial_info_rejects_unspecified_ipv6();
}
