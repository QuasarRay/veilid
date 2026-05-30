pub mod mocks;
pub mod test_network_estimator;
pub mod test_routing_metrics;
pub mod test_serialize_routing_table;
pub mod test_signed_node_info;

pub use mocks::*;

use super::*;

pub async fn test_all() {
    test_serialize_routing_table::test_routingtable_buckets_round_trip().await;
    test_serialize_routing_table::test_round_trip_peerinfo().await;
    test_signed_node_info::test_signed_node_info().await;
    test_routing_metrics::test_bucket_depth();
    test_routing_metrics::test_practical_max_size_zero();
    test_routing_metrics::test_practical_max_size_small_network_holds_most_nodes();
    test_routing_metrics::test_practical_max_size_known_values();
    test_routing_metrics::test_practical_max_size_monotonic();
    test_network_estimator::test_network_estimator_empty();
    test_network_estimator::test_network_estimator_lowest_unsaturated_bucket();
    test_network_estimator::test_network_estimator_skips_saturated_bucket_0();
    test_network_estimator::test_network_estimator_high_water_across_slots();
    test_network_estimator::test_network_estimator_only_zeroes_entered_slot();
    test_network_estimator::test_network_estimator_entered_slot_zeros_old_data();
    test_network_estimator::test_network_estimator_combined_single_kind();
    test_network_estimator::test_network_estimator_clock_backward_ignored();
}
