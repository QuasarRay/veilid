use super::*;

impl StorageManager {
    // Check if client-side transactions on opened records have expired
    //#[cfg_attr(feature = "instrument", instrument(level = "trace", target = "stor", skip_all, err))]
    pub(super) fn check_outbound_transactions_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        cur_ts: Timestamp,
    ) -> EyreResult<()> {
        let registry = self.registry();

        let inner = &mut *self.inner.lock();
        let otm = &mut inner.outbound_transaction_manager;

        let mut expired_transactions = vec![];

        for (transaction_handle, outbound_transaction_state) in otm.transactions() {
            let transaction_handle = transaction_handle.clone();

            let expired = outbound_transaction_state
                .opt_expiration()
                .map(|expiration| expiration < cur_ts)
                .unwrap_or(false);
            if expired {
                if let Some(records_lock) = self.record_lock_table.try_lock_records(
                    transaction_handle.keys().to_vec(),
                    StorageManagerRecordLockPurpose::TransactDrop,
                ) {
                    veilid_log!(registry debug "Dropping expired transaction: {}", transaction_handle);

                    expired_transactions.push((transaction_handle, records_lock));
                }
            }
        }

        for (transaction_handle, records_lock) in expired_transactions {
            if let Some(state) = otm.drop_transaction(transaction_handle.clone()) {
                let cleanup = state.into_transaction_cleanup(transaction_handle);
                let drop_fut = async move {
                    cleanup.await;
                    drop(records_lock);
                };
                self.background_operation_processor.add_future(drop_fut);
            }
        }

        Ok(())
    }
}
