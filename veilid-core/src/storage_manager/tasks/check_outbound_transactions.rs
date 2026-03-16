use super::*;

impl StorageManager {
    // Check if client-side transactions on opened records have expired
    //#[cfg_attr(feature = "instrument", instrument(level = "trace", target = "stor", skip_all, err))]
    // Check if client-side transactions on opened records have expired
    pub(super) fn check_outbound_transactions_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        _cur_ts: Timestamp,
    ) -> EyreResult<()> {
        let expired_transaction_handles = {
            let inner = &*self.inner.lock();
            let cur_ts = Timestamp::now_non_decreasing();
            let otm = &inner.outbound_transaction_manager;

            otm.transactions()
                .filter_map(|(transaction_handle, outbound_transaction_state)| {
                    let expired = outbound_transaction_state
                        .opt_expiration()
                        .map(|expiration| expiration < cur_ts)
                        .unwrap_or(false);
                    if expired {
                        Some(transaction_handle.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };

        for expired_transaction_handle in expired_transaction_handles {
            // Don't drop expired records that are currently being worked on
            if let Some(records_lock) = self.record_lock_table.try_lock_records(
                expired_transaction_handle.keys().to_vec(),
                StorageManagerRecordLockPurpose::TransactDrop,
            ) {
                let registry = self.registry();
                let drop_fut = async move {
                    let this = registry.storage_manager();

                    veilid_log!(this debug "Dropping expired transaction: {}", expired_transaction_handle);

                    let opt_cleanup = {
                        let inner = &mut *this.inner.lock();
                        let otm = &mut inner.outbound_transaction_manager;
                        otm.drop_transaction(expired_transaction_handle.clone())
                            .map(|x| x.into_transaction_cleanup(expired_transaction_handle))
                    };

                    if let Some(cleanup) = opt_cleanup {
                        this.process_transaction_cleanup(cleanup).await;
                    }

                    drop(records_lock);
                };

                self.background_operation_processor.add_future(drop_fut);
            }
        }

        Ok(())
    }
}
