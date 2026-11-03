use super::*;
mod test_destination;
mod test_dial_info;
mod test_fanout_call;
mod test_fanout_config;
mod test_fanout_queue;
mod test_invalid_answer;
mod test_node_info;
mod test_peer_info;
mod test_signed_value_data;
mod test_transport_mtus;

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
    test_fanout_queue::test_routed_unresponsive_nodes_dispatch_after_their_window().await;
    test_fanout_queue::test_demoted_straggler_does_not_hold_the_cut().await;
    test_fanout_call::test_demoted_closest_node_still_counts().await;
    test_fanout_call::test_demoted_straggler_is_cut_at_the_grace().await;
    test_fanout_queue::test_next_straggler_cut_matches_the_cut().await;
    test_invalid_answer::test_invalid_answer_fails_its_question_at_once().await;
    test_peer_info::test_ignored_node_info_drops_only_its_peer().await;
    test_signed_value_data::test_encode_and_decode_signed_value_data();
    test_destination::test_same_target_ignores_how_it_is_reached();
    test_dial_info::test_encode_and_decode_dial_info_udp();
    test_dial_info::test_encode_and_decode_dial_info_tcp();
    test_dial_info::test_encode_and_decode_dial_info_ws();
    #[cfg(feature = "enable-protocol-wss")]
    test_dial_info::test_encode_and_decode_dial_info_wss();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_dial_info::test_encode_and_decode_dial_info_wts();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_dial_info::test_encode_and_decode_dial_info_wtd();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_dial_info::test_webtransport_protocol_type_properties();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_dial_info::test_webtransport_url_validation();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_dial_info::test_decode_dial_info_caps_cert_hashes();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_dial_info::test_decode_dial_info_rejects_wrong_length_cert_hash();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_dial_info::test_decode_dial_info_absent_webtransport_expiration_is_none();
    test_dial_info::test_dial_info_expiration_is_webtransport_only();
    test_node_info::test_encode_and_decode_node_info_expiration();
    test_node_info::test_decode_node_info_absent_expiration_is_none();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_node_info::test_min_dial_info_expiration();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_node_info::test_decode_node_info_keeps_stated_expiration_independent_of_dial_info();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_node_info::test_decode_node_info_ignores_relay_dial_info_expiration();
    #[cfg(feature = "enable-protocol-webtransport")]
    test_node_info::test_decode_node_info_skips_dial_info_with_wrong_length_cert_hash();
    test_dial_info::test_decode_dial_info_skips_unknown_protocol();
    test_dial_info::test_decode_dial_info_rejects_unspecified_ipv4();
    test_dial_info::test_decode_dial_info_rejects_unspecified_ipv6();
    test_fanout_config::test_absent_fanout_config_is_the_default();
    test_fanout_config::test_fanout_config_round_trip_and_cap();
    test_transport_mtus::test_transport_mtus_skip_what_they_cannot_use();
    test_transport_mtus::test_transport_mtus_reject_bad_lists();
    test_transport_mtus::test_transport_mtus_bound_the_list();
    test_transport_mtus::test_transport_mtus_absent_from_older_node_info();
    test_transport_mtus::test_mtu_probe_bounds();
}
