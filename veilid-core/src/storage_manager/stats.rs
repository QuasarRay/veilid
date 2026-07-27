use super::*;

#[derive(Debug, Serialize)]
pub(super) struct StorageManagerStats {
    online: bool,
    gated_operations_active: u32,
    opened_records: u32,
    offline_write_records: u32,
    offline_write_subkeys: u64,
    rehydration_requests: u32,
    transactions: TransactionStats,
    gated_operations: Vec<GatedOperationKindStats>,
    locks: Vec<LockStatsEntry>,
    #[cfg(feature = "aimd-dht")]
    aimd: AimdStats,
}

#[derive(Debug, Serialize)]
struct LockStatsEntry {
    name: String,
    count: u64,
    wait: LatencyStats,
    held: LatencyStats,
}

#[derive(Debug, Serialize)]
struct TransactionStats {
    total: u32,
    foreground: u32,
}

#[derive(Debug, Serialize)]
struct GatedOperationKindStats {
    kind: String,
    count: u64,
    retryable: u64,
    gate_wait: LatencyStats,
    held: LatencyStats,
}

#[cfg(feature = "aimd-dht")]
#[derive(Debug, Serialize)]
struct AimdStats {
    upload: AimdDirectionStats,
    download: AimdDirectionStats,
}

#[cfg(feature = "aimd-dht")]
#[derive(Debug, Serialize)]
struct AimdDirectionStats {
    limit: u64,
    holds: u64,
    lowers: u64,
    clamps: u64,
    raises: u64,
    completed: u64,
    congested: u64,
    demand_events: u64,
}

#[cfg(feature = "aimd-dht")]
impl From<AimdCounters> for AimdDirectionStats {
    fn from(c: AimdCounters) -> Self {
        Self {
            limit: c.limit,
            holds: c.holds,
            lowers: c.lowers,
            clamps: c.clamps,
            raises: c.raises,
            completed: c.completed,
            congested: c.congested,
            demand_events: c.demand_events,
        }
    }
}

impl StorageManager {
    pub(super) fn stats_impl(&self) -> Option<Box<dyn VeilidComponentStats>> {
        let (
            opened_records,
            offline_write_records,
            offline_write_subkeys,
            rehydration_requests,
            transactions,
        ) = {
            let inner = self.inner.lock();
            let (total, foreground) = inner.outbound_transaction_manager.transaction_counts();
            let offline_write_subkeys = inner
                .offline_subkey_writes
                .values()
                .map(|osw| osw.subkeys.len() + osw.subkeys_in_flight.len())
                .sum();
            (
                inner.opened_records.len() as u32,
                inner.offline_subkey_writes.len() as u32,
                offline_write_subkeys,
                inner.rehydration_requests.len() as u32,
                TransactionStats { total, foreground },
            )
        };

        let gated_operations = self
            .gate_accounting
            .lock()
            .per_kind()
            .into_iter()
            .map(|s| GatedOperationKindStats {
                kind: s.kind.to_string(),
                count: s.count,
                retryable: s.retryable,
                gate_wait: s.gate_wait,
                held: s.held,
            })
            .collect();

        let lock = self.inner.lock_stats();
        let locks = vec![LockStatsEntry {
            name: lock.name.to_string(),
            count: lock.count,
            wait: lock.wait,
            held: lock.held,
        }];

        Some(Box::new(StorageManagerStats {
            online: self.is_online.load(Ordering::Acquire),
            gated_operations_active: self.gate_active.load(Ordering::Acquire) as u32,
            opened_records,
            offline_write_records,
            offline_write_subkeys,
            rehydration_requests,
            transactions,
            gated_operations,
            locks,
            #[cfg(feature = "aimd-dht")]
            aimd: AimdStats {
                upload: self.upload_budget.aimd_counters().into(),
                download: self.download_budget.aimd_counters().into(),
            },
        }))
    }
}
