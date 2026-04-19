use super::*;

impl StorageManager {
    /// Check active watches for missing ValueChanged notifications.
    /// If no ValueChanged has arrived within WATCH_FALLBACK_INSPECT_INTERVAL,
    /// enqueue a change inspection. If that inspection finds changes,
    /// it will set needs_forced_reconcile to re-establish the watch.
    fn check_fallback_inspections(&self, inner: &mut StorageManagerInner, cur_ts: Timestamp) {
        // Collect watches needing fallback inspection
        let inspections: Vec<_> = inner
            .outbound_watch_manager
            .outbound_watches
            .values()
            .filter_map(|ow| {
                let state = ow.state()?;
                if state.needs_fallback_inspect(cur_ts) {
                    Some((ow.record_key(), state.params().subkeys.clone()))
                } else {
                    None
                }
            })
            .collect();

        if inspections.is_empty() {
            return;
        }

        // Enqueue inspections and update timestamps
        for (record_key, subkeys) in inspections {
            veilid_log!(self debug target: "watch",
                "Fallback inspection triggered for watch: {}",
                record_key
            );
            inner
                .outbound_watch_manager
                .enqueue_change_inspect(self, record_key.clone(), subkeys);

            let owm = &mut inner.outbound_watch_manager;
            if let Some(ow) = owm.outbound_watches.get_mut(&record_key.opaque()) {
                if let Some(state) = ow.state_mut() {
                    state.edit(&owm.per_node_states, |editor| {
                        editor.touch_fallback_inspect(cur_ts);
                    });
                }
            }
        }
    }

    // Check if client-side watches on opened records either have dead nodes or if the watch has expired
    pub(super) fn check_outbound_watches_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        cur_ts: Timestamp,
    ) -> EyreResult<()> {
        let mut inner = self.inner.lock();

        // Update per-node watch states
        // Desired state updates are performed by get_next_outbound_watch_operation
        inner.outbound_watch_manager.update_per_node_states(cur_ts);

        // Check for watches that need fallback inspection
        self.check_fallback_inspections(&mut inner, cur_ts);

        // Iterate all outbound watches and determine what work needs doing if any
        for outbound_watch in inner.outbound_watch_manager.outbound_watches.values_mut() {
            // Get next work on watch and queue it if we have something to do
            if let Some(op_fut) = self.get_next_outbound_watch_operation(
                outbound_watch.record_key(),
                cur_ts,
                outbound_watch,
            ) {
                self.background_operation_processor.add_future(op_fut);
            };
        }

        // Iterate all queued change inspections and do them
        for (k, v) in inner.outbound_watch_manager.needs_change_inspection.drain() {
            // Get next work on watch and queue it if we have something to do
            let op_fut = self.get_change_inspection_operation(k, v);
            self.background_operation_processor.add_future(op_fut);
        }

        Ok(())
    }
}
