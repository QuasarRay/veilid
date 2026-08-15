pub mod mocks;
pub mod test_config;
pub mod test_serialize_json;
pub mod test_value_data;
pub mod test_value_seq_num;

pub use mocks::*;

use super::*;

#[expect(clippy::unused_async)]
pub async fn test_all() {
    test_serialize_json::test_serialize_json();
    test_value_data::value_data_ok();
    test_value_data::value_data_too_long();
    test_value_seq_num::value_seq_num_next();
    test_value_seq_num::value_seq_num_saturating_next();
    test_value_seq_num::value_seq_num_ordering();
    #[cfg(feature = "debug-api")]
    test_value_seq_num::value_seq_num_parse();
    test_config::test_internal_footgun_gate();
}
