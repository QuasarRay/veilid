mod mocks;
mod test_address_family_confirm;
mod test_bootstrap;
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
mod test_cert_manager;
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
mod test_cert_renewal;
#[cfg(feature = "debug-api")]
mod test_chaos;
mod test_connection_table;
#[cfg(not(target_arch = "wasm32"))]
mod test_dial_info_validators;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod test_egress_change;
mod test_envelope_timestamps;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod test_family_mtu;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod test_hole_punch_ttl;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod test_hop_mtu;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod test_inbound_relay_dial_info;
mod test_loss_estimator;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod test_mtu_probe_processor;
mod test_online_detector;
mod test_protected_reconnect;
mod test_protocol_type;
#[cfg(all(
    feature = "enable-protocol-webtransport",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        windows
    )
))]
mod test_shared_socket_fragmentation;
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
mod test_tracked_flush;
mod test_transport_stats;
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
mod test_udp_demux;
#[cfg(not(target_arch = "wasm32"))]
mod test_udp_protocol;
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
mod test_webtransport;
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
mod test_webtransport_listener;
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
pub mod test_webtransport_native;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod test_ws_mixed_content;

use super::*;
pub use mocks::*;

pub async fn test_all() {
    test_bootstrap::test_bootstrap_v0().await;
    test_bootstrap::test_bootstrap_v1().await;
    test_bootstrap::test_boot_v1_response().await;
    test_bootstrap::test_bootstrap_record_unresolved().await;
    test_bootstrap::test_short_dial_info_multibyte().await;
    test_bootstrap::test_bootstrap_peer_json_binding().await;
    test_bootstrap::test_config_bootstrap_records().await;
    test_bootstrap::test_bootstrap_cache_cap();
    test_bootstrap::test_bootstrap_v0_omits_expired_peer_info().await;
    test_bootstrap::test_bootstrap_v1_omits_expired_peer_info().await;
    #[cfg(feature = "enable-protocol-webtransport")]
    test_bootstrap::test_webtransport_short_form_slash_tolerant().await;
    #[cfg(feature = "enable-protocol-webtransport")]
    test_bootstrap::test_webtransport_ip_literal_record_single_hostname().await;
    #[cfg(feature = "enable-protocol-webtransport")]
    test_bootstrap::test_webtransport_datagram_shares_the_stream_short_form().await;
    #[cfg(feature = "debug-api")]
    test_chaos::test_all().await;
    test_connection_table::test_add_get_remove().await;
    test_connection_table::test_eviction().await;
    test_connection_table::test_dead_connection_skip().await;
    #[cfg(feature = "enable-protocol-webtransport")]
    test_connection_table::test_webtransport_stream_and_datagram_coexist().await;
    test_envelope_timestamps::test_all().await;
    test_loss_estimator::test_all();
    #[cfg(not(target_arch = "wasm32"))]
    test_dial_info_validators::test_expired_peer_info_is_not_a_dial_info_validator().await;
    test_online_detector::test_all();
    test_protected_reconnect::test_all();
    test_protocol_type::test_protocol_type_set_persisted_width();
    test_protocol_type::test_webtransport_and_udp_are_low_level_udp();
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    test_egress_change::test_all();
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    test_family_mtu::test_all();
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    test_hop_mtu::test_hop_mtu_sizes_by_the_next_hop().await;
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    Box::pin(test_inbound_relay_dial_info::test_all()).await;
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    test_mtu_probe_processor::test_all().await;
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    test_hole_punch_ttl::test_all();
    test_transport_stats::test_all();
    test_transport_stats::test_ordering_availability_follows_outbound_protocols().await;
    test_address_family_confirm::test_all();
    #[cfg(not(target_arch = "wasm32"))]
    test_udp_protocol::test_demuxed_recv_reassembles_from_channel().await;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    test_ws_mixed_content::test_ws_target_is_local();
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    test_ws_mixed_content::test_ws_allowed_from_a_secure_http_page();
    #[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
    Box::pin(test_all_webtransport()).await;
}

/// Boxed by its caller, so these futures do not grow `test_all`'s stack frame
#[cfg(all(feature = "enable-protocol-webtransport", not(target_arch = "wasm32")))]
async fn test_all_webtransport() {
    test_cert_manager::test_generate_certificate().await;
    test_cert_manager::test_rotation_timeline().await;
    test_cert_manager::test_maintain_served_changed_on_promotion().await;
    test_cert_manager::test_persist_reload().await;
    test_cert_manager::test_restart_preserves_certs_mid_window().await;
    test_cert_manager::test_restart_across_switch_point().await;
    test_cert_manager::test_restart_after_current_expiry().await;
    test_cert_manager::test_restart_after_total_outage().await;
    test_cert_manager::test_backwards_clock_does_not_regenerate().await;
    test_cert_manager::test_current_hashes_continuity_property().await;
    test_cert_manager::test_continuity_property_with_restarts().await;
    test_cert_manager::test_rotation_boundary_instants().await;
    test_cert_manager::test_validity_clamp_strictly_under_browser_max().await;
    test_cert_manager::test_max_validity_under_browser_reject_threshold();
    test_cert_manager::test_handoff_overlap_is_a_slice_of_the_validity();
    test_cert_manager::test_forward_skew_within_backdate_is_valid().await;
    test_cert_manager::test_forward_skew_beyond_backdate_residual().await;
    test_cert_manager::test_corrupted_slot_dropped_and_healed().await;
    test_cert_manager::test_inconsistent_windows_dropped_and_healed().await;
    test_cert_manager::test_transient_load_error_preserves_pinned_certs().await;
    test_cert_renewal::test_all().await;
    test_webtransport::test_contact_method_prefers_udp_tcp_over_webtransport();
    test_webtransport::test_wire3_hole_punch_webtransport_requires_webtransport_dial_info().await;
    test_udp_demux::test_routes_quic_long_header_to_webtransport();
    test_udp_demux::test_routes_quic_short_header_to_webtransport();
    test_udp_demux::test_routes_assembly_buffer_frame_to_raw_udp().await;
    test_udp_demux::test_routes_empty_and_unclaimed_datagrams_to_raw_udp();
    test_udp_demux::test_no_first_byte_is_accepted_by_both_protocols();
    test_udp_demux::test_demux_slot_probe_bytes_route_as_expected();
    test_udp_demux::test_demux_slot_keeps_a_single_quic_datagram();
    test_udp_demux::test_demux_slot_forwards_a_single_raw_datagram();
    test_udp_demux::test_demux_slot_treats_zero_stride_as_one_datagram();
    test_udp_demux::test_demux_slot_handles_stride_larger_than_len();
    test_udp_demux::test_demux_slot_keeps_an_all_quic_train();
    test_udp_demux::test_demux_slot_forwards_an_all_raw_train();
    test_udp_demux::test_demux_slot_splits_an_alternating_train();
    test_udp_demux::test_demux_slot_keeps_a_short_final_quic_datagram();
    test_udp_demux::test_demux_slot_forwards_a_short_final_raw_datagram();
    test_udp_demux::test_retained_prefix_reframes_into_the_original_quic_datagrams();
    test_udp_demux::test_raw_demux_channel_is_bounded();
    test_udp_demux::test_poll_recv_yields_under_raw_flood().await;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    test_udp_demux::test_coalesced_slot_is_split_per_datagram().await;
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        windows
    ))]
    test_shared_socket_fragmentation::test_shared_socket_keeps_fragmentation_policy();
    test_tracked_flush::test_tracked_flush_is_cancelled_and_joined_at_shutdown().await;
    test_tracked_flush::test_tracked_flush_dropped_when_not_started();
    test_webtransport_listener::test_sibling_ip_path();
    test_webtransport_listener::test_same_bind_target_equal_port_and_addrs();
    test_webtransport_listener::test_same_bind_target_ignores_search_flag();
    test_webtransport_listener::test_same_bind_target_order_insensitive();
    test_webtransport_listener::test_same_bind_target_port_differs();
    test_webtransport_listener::test_same_bind_target_addr_sets_differ();
    test_webtransport_listener::test_same_bind_target_partial_overlap();
    test_webtransport_listener::test_same_bind_target_subset();
    test_webtransport_listener::test_webtransport_path_matches_table();
    test_webtransport_listener::test_webtransport_path_matches_rejects_oversize_path();
    test_webtransport_listener::test_webtransport_request_url_injects_port_and_path();
    test_webtransport_listener::test_webtransport_request_url_keeps_url_crate_encoding();
    test_webtransport_listener::test_webtransport_request_url_dials_its_own_accept_route();
    test_webtransport_listener::test_webtransport_socket_request_url_brackets_and_paths();
    test_webtransport_listener::test_webtransport_udp_delivery_conflict_same_port();
    test_webtransport_listener::test_webtransport_udp_delivery_conflict_wildcard_ip();
    test_webtransport_listener::test_webtransport_udp_delivery_conflict_family_mismatch();
    test_webtransport_listener::test_webtransport_udp_delivery_conflict_different_port();
    Box::pin(test_webtransport_listener::test_webtransport_bind_plan_explicit_listen_address())
        .await;
    Box::pin(test_webtransport_listener::test_webtransport_bind_plan_default_listen_address())
        .await;
    Box::pin(test_webtransport_native::test_all()).await;
}
