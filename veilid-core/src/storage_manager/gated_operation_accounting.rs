//! Rolling accounting for the DHT operation gate: per-kind wait/hold
//! latencies and, with `aimd-dht`, per-direction AIMD decision tallies.
//! Compiled only with `stats`; the serializable snapshot lives in `stats.rs`.
use super::gated_operation::GatedOperationKind;
use super::*;

/// Per-kind rolling wait/hold accounting
#[derive(Debug, Default)]
struct GatedKindAccounting {
    count: u64,
    // Completions that ended in a retryable outcome (no consensus / congestion);
    // the client defers or retries these, so the ratio to `count` is retry pressure.
    retryable: u64,
    gate_wait: LatencyStats,
    gate_wait_accounting: LatencyStatsAccounting,
    held: LatencyStats,
    held_accounting: LatencyStatsAccounting,
}

/// One kind's gate telemetry, read by the storage manager stats snapshot
#[derive(Clone)]
pub(super) struct GatedKindSnapshot {
    pub kind: &'static str,
    pub count: u64,
    pub retryable: u64,
    pub gate_wait: LatencyStats,
    pub held: LatencyStats,
}

/// Gate wait (admission delay) and hold (round-trip proxy) latencies plus a
/// completion count, per operation kind
#[derive(Debug, Default)]
pub(super) struct GatedOperationAccounting {
    set: GatedKindAccounting,
    get: GatedKindAccounting,
    transact_set: GatedKindAccounting,
    transact_get: GatedKindAccounting,
}

impl GatedOperationAccounting {
    fn kind_mut(&mut self, kind: GatedOperationKind) -> &mut GatedKindAccounting {
        match kind {
            GatedOperationKind::Set => &mut self.set,
            GatedOperationKind::Get => &mut self.get,
            GatedOperationKind::TransactSet => &mut self.transact_set,
            GatedOperationKind::TransactGet => &mut self.transact_get,
        }
    }
    pub(super) fn record_wait(&mut self, kind: GatedOperationKind, wait: TimestampDuration) {
        let k = self.kind_mut(kind);
        k.gate_wait = k.gate_wait_accounting.record_latency(wait);
    }
    pub(super) fn record_completion(&mut self, kind: GatedOperationKind, held: TimestampDuration) {
        let k = self.kind_mut(kind);
        k.count += 1;
        k.held = k.held_accounting.record_latency(held);
    }
    pub(super) fn record_retryable(&mut self, kind: GatedOperationKind) {
        self.kind_mut(kind).retryable += 1;
    }
    pub(super) fn per_kind(&self) -> [GatedKindSnapshot; 4] {
        let snap = |kind, k: &GatedKindAccounting| GatedKindSnapshot {
            kind,
            count: k.count,
            retryable: k.retryable,
            gate_wait: k.gate_wait.clone(),
            held: k.held.clone(),
        };
        [
            snap("set", &self.set),
            snap("get", &self.get),
            snap("tx_set", &self.transact_set),
            snap("tx_get", &self.transact_get),
        ]
    }
}

/// Cumulative AIMD decision tallies for one direction
#[cfg(feature = "aimd-dht")]
#[derive(Debug, Default)]
pub(super) struct AimdAccounting {
    holds: u64,
    lowers: u64,
    clamps: u64,
    raises: u64,
    completed: u64,
    congested: u64,
    demand_events: u64,
}

#[cfg(feature = "aimd-dht")]
impl AimdAccounting {
    pub(super) fn record(&mut self, step: &AimdStepResult) {
        match step.decision {
            AimdDecision::Hold => self.holds += 1,
            AimdDecision::Lower(_) => self.lowers += 1,
            AimdDecision::Clamp(_) => self.clamps += 1,
            AimdDecision::Raise(_) => self.raises += 1,
        }
        self.completed += step.completed;
        self.congested += step.congested;
        self.demand_events += step.demand_events;
    }
    pub(super) fn counters(&self, limit: u64) -> AimdCounters {
        AimdCounters {
            limit,
            holds: self.holds,
            lowers: self.lowers,
            clamps: self.clamps,
            raises: self.raises,
            completed: self.completed,
            congested: self.congested,
            demand_events: self.demand_events,
        }
    }
}

/// One direction's AIMD telemetry, read by the storage manager stats snapshot
#[cfg(feature = "aimd-dht")]
#[derive(Clone, Copy)]
pub(super) struct AimdCounters {
    pub limit: u64,
    pub holds: u64,
    pub lowers: u64,
    pub clamps: u64,
    pub raises: u64,
    pub completed: u64,
    pub congested: u64,
    pub demand_events: u64,
}
