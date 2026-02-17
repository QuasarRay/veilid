mod mocks;
mod test_bootstrap;
mod test_connection_table;
mod test_dial_info;

use super::*;
pub use mocks::*;

pub async fn test_all() {
    test_bootstrap::test_bootstrap_v0().await;
    test_bootstrap::test_bootstrap_v1().await;
    test_connection_table::test_add_get_remove().await;
    test_dial_info::test_all().await;
}
