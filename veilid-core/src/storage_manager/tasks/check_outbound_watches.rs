use super::*;

impl StorageManager {
    /// Check active watches for missing ValueChanged notifications.
    /// If no ValueChanged has arrived within the watch's current fallback interval,
    /// enqueue a change inspection. If that inspection finds changes,
    /// it will set needs_forced_reconcile to re-establish the watch.
    fn check_fallback_inspections_inner(
        registry: VeilidComponentRegistry,
        owm: &mut OutboundWatchManager,
        cur_ts: Timestamp,
        renew_window: TimestampDuration,
    ) {
        // A stalled or unreachable node cannot complete these, and either answer the
        // detector gives means wait
        if registry
            .network_manager()
            .online_detector()
            .blame_suppressed(RoutingDomain::PublicInternet)
        {
            return;
        }

        // Collect watches needing fallback inspection
        let consensus_count = registry.config().internal().network.dht.get_value_count as usize;
        let max_interval = registry
            .storage_manager()
            .timings()
            .watch_inspect_max_interval;
        let inspections: Vec<_> = owm
            .outbound_watches
            .values()
            .filter_map(|ow| {
                Some((
                    ow.record_key(),
                    ow.needs_fallback_inspect(cur_ts, consensus_count, renew_window, max_interval)?,
                ))
            })
            .collect();

        if inspections.is_empty() {
            return;
        }

        // Enqueue inspections and update timestamps
        for (record_key, subkeys) in inspections {
            veilid_log!(registry debug target: "watch",
                "Fallback inspection triggered for watch: {}",
                record_key
            );
            owm.enqueue_change_inspect(record_key.clone(), subkeys);

            if let Some(ow) = owm.outbound_watches.get_mut(&record_key.opaque()) {
                ow.touch_fallback_inspect(&owm.per_node_states, cur_ts);
            }
        }
    }

    // Check if client-side watches on opened records either have dead nodes or if the watch has expired
    pub(in crate::storage_manager) fn check_outbound_watches_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        cur_ts: Timestamp,
    ) -> EyreResult<()> {
        let Some(local_record_store) = self.inner.lock().local_record_store.as_ref().cloned()
        else {
            // No local record store, so no watches to check
            return Ok(());
        };
        // Per-tick progress rides the periodic save, not a background save every second
        let owm = &mut *self.outbound_watch_manager.lock();

        // Update per-node watch states
        // Desired state updates are performed by get_next_outbound_watch_operation
        owm.update_per_node_states(cur_ts);

        // Check for watches that need fallback inspection
        Self::check_fallback_inspections_inner(
            self.registry(),
            owm,
            cur_ts,
            self.timings().renew_outbound_watches,
        );

        // Send any repeat hints owed from reads that raced suppressed reports
        if !owm.pending_rehints.is_empty() {
            let registry = self.registry();
            self.background_operation_processor.add_future(async move {
                registry.storage_manager().send_pending_rehints().await;
            });
        }

        let hold_network_work = Self::holds_watch_network_work(
            self.network_manager()
                .online_detector()
                .online_state(RoutingDomain::PublicInternet),
        );

        // Iterate all outbound watches and determine what work needs doing if any
        for outbound_watch in owm.outbound_watches.values_mut() {
            // Operate on this watch only if it isn't already being operated on.
            // Watch mode (lifetime.read + watch_lock) is concurrent with reads/sets/transactions.
            if let Some(record_lock) = self.record_lock_table.try_lock_record(
                outbound_watch.record_key().opaque(),
                StorageManagerRecordLockPurpose::Watch,
            ) {
                // Get next work on watch and queue it if we have something to do
                if let Some(op_fut) = Self::get_next_outbound_watch_operation_inner(
                    self.registry(),
                    record_lock,
                    cur_ts,
                    outbound_watch,
                    hold_network_work,
                ) {
                    self.background_operation_processor.add_future(op_fut);
                };
            }
        }

        if hold_network_work {
            return Ok(());
        }

        // Run queued change inspections that are due, leaving backed-off retries and
        // records whose inspection is still running queued
        let due_keys = owm
            .needs_change_inspection
            .iter()
            .filter(|(k, (_, not_before))| {
                *not_before <= cur_ts && !owm.change_inspects_in_flight.contains(&k.opaque())
            })
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        for k in due_keys {
            let Some((subkeys, _)) = owm.needs_change_inspection.remove(&k) else {
                continue;
            };
            let opaque_record_key = k.opaque();
            owm.change_inspects_in_flight
                .insert(opaque_record_key.clone());

            let op_fut = Self::get_change_inspection_operation_inner(
                self.registry(),
                local_record_store.clone(),
                k,
                subkeys,
            );
            // Cleared in a wrapper so both inspection variants release it
            let registry = self.registry();
            self.background_operation_processor.add_future(async move {
                op_fut.await;
                registry
                    .storage_manager()
                    .outbound_watch_manager
                    .lock()
                    .change_inspects_in_flight
                    .remove(&opaque_record_key);
            });
        }

        Ok(())
    }
}
