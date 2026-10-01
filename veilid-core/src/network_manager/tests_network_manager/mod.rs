mod mocks;
mod test_address_family_confirm;
mod test_bootstrap;
mod test_connection_table;
mod test_envelope_timestamps;
mod test_online_detector;
mod test_protected_reconnect;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod test_routable_interface_addresses;
mod test_transport_stats;

use super::*;
pub use mocks::*;

pub async fn test_all() {
    test_bootstrap::test_bootstrap_v0().await;
    test_bootstrap::test_bootstrap_v1().await;
    test_bootstrap::test_boot_v1_response().await;
    test_bootstrap::test_bootstrap_record_unresolved().await;
    test_bootstrap::test_config_bootstrap_records().await;
    test_bootstrap::test_bootstrap_cache_cap();
    test_connection_table::test_add_get_remove().await;
    test_connection_table::test_eviction().await;
    test_connection_table::test_dead_connection_skip().await;
    test_envelope_timestamps::test_all().await;
    test_online_detector::test_all();
    test_protected_reconnect::test_all();
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    test_routable_interface_addresses::test_all();
    test_transport_stats::test_all();
    test_address_family_confirm::test_all();
}
