use super::*;

impl StorageManager {
    // Flush record stores to disk, remove dead records and apply the storage budget
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "stor", skip_all, err)
    )]
    pub(super) async fn flush_record_stores_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        _cur_ts: Timestamp,
    ) -> EyreResult<()> {
        if let Ok(local_record_store) = self.get_local_record_store() {
            if let Err(e) = local_record_store.flush().await {
                veilid_log!(self error "Error flushing local record store during flush task: {}", e);
            }
        }
        if let Ok(remote_record_store) = self.get_remote_record_store() {
            if let Err(e) = remote_record_store.flush().await {
                veilid_log!(self error "Error flushing remote record store during flush task: {}", e);
            }
        }
        match self.update_storage_limits().await {
            Ok(_) => self.storage_limits_stale.store(false, Ordering::Release),
            Err(e) => {
                if self.storage_limits_stale.swap(true, Ordering::AcqRel) {
                    veilid_log!(self debug "Unable to update the remote record store's limit: {}", e);
                } else {
                    veilid_log!(self warn "Unable to update the remote record store's limit, which stays as it was: {}", e);
                }
            }
        }
        Ok(())
    }
}
