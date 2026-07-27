use super::*;

mod test_encrypted_value_data;
#[cfg(feature = "aimd-dht")]
mod test_gated_operation;
mod test_inbound_set_value_signature;

pub async fn test_all() {
    test_encrypted_value_data::test_all().await;
    #[cfg(feature = "aimd-dht")]
    test_gated_operation::test_all();
    test_inbound_set_value_signature::test_all().await;
    record_store::tests::test_record_store().await;
}
