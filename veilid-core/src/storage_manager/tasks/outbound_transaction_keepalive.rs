use futures_util::future::select_all;
use futures_util::stream::{FuturesUnordered, StreamExt};
use stop_token::future::FutureExt as _;

use super::*;

/// Fixed interval between keepalive Gets per node.
/// Multiple keepalives can be in-flight simultaneously for the same node.
/// This must be shorter than the server-side transaction TTL so that at least
/// one keepalive arrives before expiry even under worst-case RPC latency.
const OUTBOUND_TRANSACTION_KEEPALIVE_INTERVAL: TimestampDuration = TimestampDuration::new_ms(1_000);

impl_veilid_log_facility!("stor");

/// Immediate keepalive request sent to the processor via channel
#[derive(Debug, Clone)]
struct OutboundTransactionKeepalive {
    /// The transaction handle
    transaction_handle: OutboundTransactionHandle,
    /// The record key being transacted
    opaque_record_key: OpaqueRecordKey,
    /// Nodes transaction id to use
    node_xid: NodeTransactionId,
    /// Destination to send keepalive to
    dest: Destination,
    /// Descriptor of the record being transacted
    descriptor: Arc<SignedValueDescriptor>,
}

/// Keepalive processor commands
#[derive(Debug, Clone)]
enum OutboundTransactionKeepaliveCommand {
    AddKeepalive {
        deadline_ts: Timestamp,
        keepalive: OutboundTransactionKeepalive,
    },
}

/// Result returned from a keepalive processor future
#[derive(Debug, Clone)]
enum ProcessorResult {
    CommandReceived {
        command: OutboundTransactionKeepaliveCommand,
    },
    DeadlineReached,
    KeepaliveResult {
        keepalive: OutboundTransactionKeepalive,
        opt_expiration: Option<Timestamp>,
    },
    Failed {
        error: String,
    },
}

/// Shared deadline state protected by sync mutex
struct OutboundTransactionKeepaliveDeadlines {
    /// Scheduled deadlines sorted by timestamp. Each deadline maps to one or more OutboundTransactionKeepalive items
    deadlines: BTreeMap<Timestamp, Vec<OutboundTransactionKeepalive>>,
    /// Transactions that have been unregistered. handle_keepalive_result will not reschedule these.
    cancelled: HashSet<OutboundTransactionHandle>,
}

impl OutboundTransactionKeepaliveDeadlines {
    fn new() -> Self {
        Self {
            deadlines: BTreeMap::new(),
            cancelled: HashSet::new(),
        }
    }

    /// Timestamp of the earliest scheduled keepalive, if any.
    fn next_deadline(&self) -> Option<Timestamp> {
        self.deadlines.keys().next().copied()
    }

    /// Schedule a keepalive for OutboundTransactionKeepalive at time `ts`.
    fn add_deadline(&mut self, ts: Timestamp, keepalive: OutboundTransactionKeepalive) {
        self.deadlines.entry(ts).or_default().push(keepalive);
    }

    /// Cancel all scheduled deadlines for a transaction and mark it cancelled so
    /// completing in-flight RPCs will not reschedule new ones.
    fn cancel_deadlines(&mut self, transaction_handle: &OutboundTransactionHandle) {
        // Remove deadlines associated with this transaction handle
        self.deadlines.retain(|_ts, entries| {
            entries.retain(|keepalive| &keepalive.transaction_handle != transaction_handle);
            !entries.is_empty()
        });

        // Mark the transaction as cancelled so new deadlines are not scheduled
        self.cancelled.insert(transaction_handle.clone());
    }

    /// Returns true if the transaction has been cancelled via `remove_transaction`.
    fn is_cancelled(&self, transaction_handle: &OutboundTransactionHandle) -> bool {
        self.cancelled.contains(transaction_handle)
    }

    /// Remove all tracking state for a fully-completed transaction (cleanup after commit/rollback).
    fn cleanup_transaction(&mut self, transaction_handle: &OutboundTransactionHandle) {
        self.cancelled.remove(transaction_handle);
    }

    /// Remove and return all (transaction, record, node) triples whose deadline has passed.
    fn take_due_entries(&mut self) -> Vec<OutboundTransactionKeepalive> {
        let cur_ts = Timestamp::now();
        // split_off returns [cur_ts+1ms..), leaving [..=cur_ts] in self.deadlines
        let future = self
            .deadlines
            .split_off(&cur_ts.later(TimestampDuration::new_ms(1)));
        let due = std::mem::replace(&mut self.deadlines, future);
        due.into_values().flatten().collect()
    }

    /// Total number of scheduled deadline entries across all timestamps.
    fn len(&self) -> usize {
        self.deadlines.values().map(|v| v.len()).sum()
    }
}

/// Processor object with shared state for synchronous register/unregister
/// and async keepalive processing
pub(in crate::storage_manager) struct OutboundTransactionKeepaliveProcessor {
    registry: VeilidComponentRegistry,
    deadlines: Arc<Mutex<OutboundTransactionKeepaliveDeadlines>>,
    sender: flume::Sender<OutboundTransactionKeepaliveCommand>,
    receiver: flume::Receiver<OutboundTransactionKeepaliveCommand>,
    jh: Mutex<Option<MustJoinHandle<()>>>,
    stop_source: Mutex<Option<StopSource>>,
}

impl VeilidComponentRegistryAccessor for OutboundTransactionKeepaliveProcessor {
    fn registry(&self) -> VeilidComponentRegistry {
        self.registry.clone()
    }
}

impl OutboundTransactionKeepaliveProcessor {
    /// Create a new processor. Call `init` to start the background loop.
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        let (sender, receiver) = flume::unbounded();
        Self {
            registry,
            deadlines: Arc::new(Mutex::new(OutboundTransactionKeepaliveDeadlines::new())),
            sender,
            receiver,
            jh: Mutex::new(None),
            stop_source: Mutex::new(None),
        }
    }

    /// Schedule recurring keepalives for one node transaction in one record within a transaction
    /// Each node's first keepalive is scheduled at OUTBOUND_TRANSACTION_KEEPALIVE_INTERVAL
    /// from now. Subsequent keepalives fire at the same fixed interval regardless of how many
    /// are simultaneously in-flight.
    pub fn register(
        &self,
        transaction_handle: OutboundTransactionHandle,
        opaque_record_key: OpaqueRecordKey,
        node_xid: NodeTransactionId,
        dest: Destination,
        expiration_ts: Timestamp,
        descriptor: Arc<SignedValueDescriptor>,
    ) {
        let cur_ts = Timestamp::now();

        if expiration_ts <= cur_ts {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug target:"dht", "Keepalive register: node already expired: handle={} record={} node={}",
                transaction_handle, opaque_record_key, node_xid);
            return;
        }
        // Schedule first keepalive at fixed interval from now
        let next_ts = cur_ts.later(OUTBOUND_TRANSACTION_KEEPALIVE_INTERVAL);

        let keepalive = OutboundTransactionKeepalive {
            transaction_handle,
            opaque_record_key,
            node_xid,
            dest,
            descriptor,
        };

        #[cfg(feature = "verbose-tracing")]
        veilid_log!(self debug target:"dht", "Keepalive node registered: expiry={} first_keepalive={}, keepalive={:?}",
            expiration_ts.duration_since(cur_ts), OUTBOUND_TRANSACTION_KEEPALIVE_INTERVAL, keepalive);

        let _ = self
            .sender
            .send(OutboundTransactionKeepaliveCommand::AddKeepalive {
                deadline_ts: next_ts,
                keepalive,
            });
    }

    /// Cancel all scheduled keepalives for a transaction. Marks it cancelled so
    /// any in-flight keepalive that completes will not reschedule a successor.
    /// Call this before sending End RPCs.
    ///
    /// Must always be paired with a later call to `cleanup_transaction` to free
    /// the handle from the cancelled set; this is done by `process_transaction_cleanup`.
    pub fn unregister(&self, transaction_handle: OutboundTransactionHandle) {
        self.deadlines.lock().cancel_deadlines(&transaction_handle);
    }

    /// Release all tracking state for a transaction after commit or rollback.
    /// Frees memory from the cancelled set.
    pub fn cleanup_transaction(&self, transaction_handle: OutboundTransactionHandle) {
        self.deadlines
            .lock()
            .cleanup_transaction(&transaction_handle);
    }

    /// Spawn the background processor loop. Must be called before register.
    pub fn init(&self) {
        let rx = self.receiver.clone();
        let stop_source = StopSource::new();
        let stop_token = stop_source.token();
        let jh = spawn(
            "outbound transaction keepalive processor",
            Self::processor_loop(self.registry(), stop_token, rx, self.deadlines.clone()),
        );
        *self.jh.lock() = Some(jh);
        *self.stop_source.lock() = Some(stop_source);
    }

    /// Signal the background loop to stop and wait for it to exit.
    pub async fn terminate(&self) {
        drop(self.stop_source.lock().take());
        let opt_jh = self.jh.lock().take();
        if let Some(jh) = opt_jh {
            jh.await;
        }
        self.receiver.drain();
    }

    /// Long-lived background processor loop
    async fn processor_loop(
        registry: VeilidComponentRegistry,
        stop_token: StopToken,
        rx: flume::Receiver<OutboundTransactionKeepaliveCommand>,
        deadlines: Arc<Mutex<OutboundTransactionKeepaliveDeadlines>>,
    ) {
        let mut unord = FuturesUnordered::<PinBoxFutureStatic<ProcessorResult>>::new();

        loop {
            let mut futs = vec![];

            // Start any due keepalives
            Self::start_due_keepalives(&registry, &deadlines, &mut unord);

            // Wait for the next keepalive result if we have any in-flight
            if !unord.is_empty() {
                futs.push(pin_dyn_future!(async {
                    unord
                        .next()
                        .await
                        .unwrap_or_else(|| ProcessorResult::Failed {
                            error: "No keepalive result".to_string(),
                        })
                }));
            }

            // See if we have a next deadline, if so, add a delay to the unord to wait for it
            let opt_next_deadline = deadlines.lock().next_deadline();
            if let Some(next_deadline) = opt_next_deadline {
                let cur_ts = Timestamp::now();
                let delay_ms = next_deadline
                    .duration_since(cur_ts)
                    .millis_u32()
                    .unwrap_or(0);
                futs.push(pin_dyn_future!(async move {
                    sleep(delay_ms).await;
                    ProcessorResult::DeadlineReached
                }));
            }

            // Always wait on the channel
            futs.push(pin_dyn_future!(async {
                rx.recv_async()
                    .await
                    .map(|command| ProcessorResult::CommandReceived { command })
                    .unwrap_or_else(|e| ProcessorResult::Failed {
                        error: e.to_string(),
                    })
            }));

            // Race these futures and handle the first result
            let Ok((res, _idx, _other_futs)) =
                select_all(futs).timeout_at(stop_token.clone()).await
            else {
                // Stop token fired, shut down immediately
                break;
            };

            match res {
                ProcessorResult::CommandReceived { command } => match command {
                    OutboundTransactionKeepaliveCommand::AddKeepalive {
                        deadline_ts,
                        keepalive,
                    } => {
                        deadlines.lock().add_deadline(deadline_ts, keepalive);
                    }
                },
                ProcessorResult::DeadlineReached => {
                    // Fall through to start_due_keepalives
                }
                ProcessorResult::KeepaliveResult {
                    keepalive,
                    opt_expiration,
                } => {
                    // Some node keepalive finished with a new expiration
                    Self::handle_keepalive_expiration(
                        keepalive,
                        opt_expiration,
                        &registry,
                        &deadlines,
                    );
                }
                ProcessorResult::Failed { error } => {
                    // Log the error and continue
                    veilid_log!(registry error "Keepalive processor error: error={}", error);
                }
            }

            // Loop to construct the next race
        }

        veilid_log!(registry debug "Transaction keepalive processor stopped. {} deadlines remaining.",
            deadlines.lock().len());
    }

    /// Start keepalive RPCs for all per-node entries at or past their deadline.
    /// Multiple keepalives can be in-flight simultaneously for the same node.
    fn start_due_keepalives(
        registry: &VeilidComponentRegistry,
        deadlines: &Mutex<OutboundTransactionKeepaliveDeadlines>,
        unord: &mut FuturesUnordered<PinBoxFutureStatic<ProcessorResult>>,
    ) {
        let due_entries = deadlines.lock().take_due_entries();
        if due_entries.is_empty() {
            return;
        }

        for due_entry in due_entries {
            Self::start_keepalive(registry, unord, due_entry);
        }
    }

    /// Start a single per-node keepalive RPC
    fn start_keepalive(
        registry: &VeilidComponentRegistry,
        unord: &mut FuturesUnordered<PinBoxFutureStatic<ProcessorResult>>,
        keepalive: OutboundTransactionKeepalive,
    ) {
        let registry = registry.clone();

        #[cfg(feature = "verbose-tracing")]
        veilid_log!(registry debug target: "dht", "Keepalive sending: keepalive={:?}", keepalive);

        unord.push(Box::pin(async move {
            let rpc_processor = registry.rpc_processor();

            let result = rpc_processor.rpc_call_transact_command(keepalive.dest.clone(), keepalive.opaque_record_key.clone(), keepalive.descriptor.clone(), keepalive.node_xid.xid(), TransactCommand::Get, None, None, None).await;

            match result {
                Ok(NetworkResult::Value(answer)) => {
                    ProcessorResult::KeepaliveResult { keepalive, opt_expiration: answer.answer.opt_expiration }
                }
                #[allow(unused_variables)]
                Ok(v) => {
                    // Any other network result gets ignored but logged
                    #[cfg(feature = "verbose-tracing")]
                    veilid_log!(registry debug target: "dht", "Keepalive RPC failed: keepalive={:?}: {:?}", keepalive, v);
                    ProcessorResult::KeepaliveResult { keepalive, opt_expiration: None }
                }
                Err(e) => {
                    ProcessorResult::Failed { error: e.to_string() }
                }
            }
        }));
    }

    /// Handle a completed keepalive RPC — update node state and reschedule at fixed interval
    fn handle_keepalive_expiration(
        keepalive: OutboundTransactionKeepalive,
        opt_expiration: Option<Timestamp>,
        registry: &VeilidComponentRegistry,
        deadlines: &Mutex<OutboundTransactionKeepaliveDeadlines>,
    ) {
        let storage_manager = registry.storage_manager();

        let Some(expiration) = opt_expiration else {
            // No new expiration, just log end of keepalive
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(registry debug target: "dht", "Keepalive finished: keepalive={:?}", keepalive);
            return;
        };

        // Record results via existing OTM method (command_result moved, no clone needed)
        let reschedule = {
            let mut inner = storage_manager.inner.lock();
            match inner
                .outbound_transaction_manager
                .record_transact_keepalive_result(
                    keepalive.transaction_handle.clone(),
                    keepalive.opaque_record_key.clone(),
                    keepalive.node_xid.clone(),
                    expiration,
                ) {
                Ok(v) => v,
                Err(e) => {
                    veilid_log!(registry debug "Keepalive result recording failed: keepalive={:?} expiration={}: {}",
                        keepalive, expiration, e);
                    // Do not reschedule on recording failure
                    false
                }
            }
        };

        if reschedule {
            let mut dl = deadlines.lock();
            if !dl.is_cancelled(&keepalive.transaction_handle) {
                let cur_ts = Timestamp::now();
                let next_ts = cur_ts.later(OUTBOUND_TRANSACTION_KEEPALIVE_INTERVAL);
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(registry debug target: "dht", "Keepalive rescheduled: next_ts={} keepalive={:?}", next_ts, keepalive);

                dl.add_deadline(next_ts, keepalive);
            }
        }
    }
}
