use futures_util::future::MaybeDone;

use super::*;

/// Collection of node xids per record
pub(in crate::storage_manager) type PerRecordNodeTransactionIds =
    Vec<(OpaqueRecordKey, Vec<NodeTransactionId>)>;

/// Stage consensus for transaction state across all records
#[derive(Clone, Debug)]
pub(in crate::storage_manager) struct OutboundTransactionStageConsensus {
    /// The best consensus stage we could come up with for this transaction
    pub stage: OutboundTransactionStage,
    /// The list of node transactions that should be rolled back at this point per record
    pub per_record_node_xids_to_rollback: PerRecordNodeTransactionIds,
    /// The list of node transactions that should be dropped at this point
    pub per_record_node_xids_to_drop: PerRecordNodeTransactionIds,
}

/// State of a single transaction across multiple records
#[derive(Debug, Serialize, Deserialize)]
pub(in crate::storage_manager) struct OutboundTransactionState {
    /// Registry for logging
    #[serde(skip)]
    opt_registry: Option<VeilidComponentRegistry>,
    /// The timestamp of when the transaction was created
    created_ts: Timestamp,
    /// State per record
    record_states: Vec<OutboundTransactionRecordState>,
    /// Background operations to join at drop
    #[serde(skip)]
    background_tokens: Vec<MaybeDone<StopToken>>,
    /// Operations in-flight semaphore
    #[serde(skip)]
    #[serde(default = "default_operation_concurrency")]
    operation_concurrency: Arc<AsyncSemaphore>,
    /// Safety routes locked during this transaction
    #[serde(skip)]
    locked_safety_routes: LockedSafetyRoutes,
}

fn default_operation_concurrency() -> Arc<AsyncSemaphore> {
    Arc::new(AsyncSemaphore::new(PER_TRANSACTION_OPERATION_CONCURRENCY))
}

impl fmt::Display for OutboundTransactionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"created@{} {}@{}
record_infos:
{}
"#,
            self.created_ts,
            self.stage_consensus()
                .map(|x| x.stage.to_string())
                .unwrap_or_else(|| "INIT".to_string()),
            self.stage_ts(),
            self.record_states
                .iter()
                .enumerate()
                .map(|x| indent_all_string(&format!("{}: {}", x.0, x.1)))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

impl VeilidComponentRegistryAccessor for OutboundTransactionState {
    fn registry(&self) -> VeilidComponentRegistry {
        self.opt_registry.clone().unwrap_or_log()
    }
}

impl Drop for OutboundTransactionState {
    fn drop(&mut self) {
        if self.opt_registry.is_none() {
            eprintln!("BUG: OutboundTransactionState dropped without registry");
            return;
        }
        if !self.locked_safety_routes.is_empty() {
            veilid_log!(self error "OutboundTransactionState dropped with {} locked safety routes still held", self.locked_safety_routes.len());
        }
        let active_bg = self
            .background_tokens
            .iter()
            .filter(|x| matches!(x, MaybeDone::Future(_)))
            .count();
        if active_bg > 0 {
            veilid_log!(self error "OutboundTransactionState dropped with {} active background tokens", active_bg);
        }
    }
}

impl OutboundTransactionState {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        Self {
            opt_registry: Some(registry),
            created_ts: Timestamp::now(),
            record_states: vec![],
            background_tokens: vec![],
            operation_concurrency: Arc::new(AsyncSemaphore::new(
                PER_TRANSACTION_OPERATION_CONCURRENCY,
            )),
            locked_safety_routes: LockedSafetyRoutes::new(),
        }
    }

    pub fn prepare(&mut self, routing_table: &RoutingTable, cur_ts: Timestamp) {
        self.opt_registry = Some(routing_table.registry());
        for record_info in &mut self.record_states {
            record_info.prepare(routing_table, cur_ts);
        }
    }

    #[expect(dead_code)]
    pub fn created_ts(&self) -> Timestamp {
        self.created_ts
    }

    pub fn opt_expiration(&self) -> Option<Timestamp> {
        self.record_states
            .iter()
            .map(|x| x.opt_expiration())
            .reduce(|a, b| match (a, b) {
                (None, None) => None,
                (None, Some(b)) => Some(b),
                (Some(a), None) => Some(a),
                (Some(a), Some(b)) => Some(a.min(b)),
            })
            .flatten()
    }

    pub fn stage_consensus(&self) -> Option<OutboundTransactionStageConsensus> {
        // All record stages must be the same or this is a failed state
        let mut opt_best_opt_stage: Option<Option<OutboundTransactionStage>> = None;
        let mut per_record_node_xids_to_rollback: Vec<(OpaqueRecordKey, Vec<NodeTransactionId>)> =
            vec![];
        let mut per_record_node_xids_to_drop: Vec<(OpaqueRecordKey, Vec<NodeTransactionId>)> =
            vec![];
        let mut force_fail = false;

        for record_state in &self.record_states {
            let Some(record_stage_consensus) = record_state.stage_consensus() else {
                // If some record has no stage consensus yet (INIT), all records must be INIT
                if let Some(best_opt_stage) = opt_best_opt_stage {
                    // Other record found that was not INIT
                    if best_opt_stage.is_some() {
                        force_fail = true;
                        break;
                    }
                } else {
                    opt_best_opt_stage = Some(None);
                }
                continue;
            };

            // If we have a record stage consensus, it must match all the other records
            let record_stage = record_stage_consensus.stage;
            if let Some(best_opt_stage) = opt_best_opt_stage {
                if best_opt_stage != Some(record_stage) {
                    force_fail = true;
                    break;
                }
            } else {
                opt_best_opt_stage = Some(Some(record_stage));
            }
            per_record_node_xids_to_rollback.push((
                record_state.record_key().opaque(),
                record_stage_consensus.node_xids_to_rollback,
            ));
            per_record_node_xids_to_drop.push((
                record_state.record_key().opaque(),
                record_stage_consensus.node_xids_to_drop,
            ));
        }

        // If we are forcing a failed state, sum up the rollbacks instead
        if force_fail {
            let per_record_node_xids_to_rollback = self.get_all_rollbacks();
            return Some(OutboundTransactionStageConsensus {
                stage: OutboundTransactionStage::Failed,
                per_record_node_xids_to_rollback,
                per_record_node_xids_to_drop: vec![],
            });
        }

        let Some(best_opt_stage) = opt_best_opt_stage else {
            // No records means INIT stage
            return None;
        };
        let Some(stage) = best_opt_stage else {
            // All INIT means INIT stage
            return None;
        };

        // Return the summed up transaction stage consensus
        // and all of the actions to perform for reconciliation
        Some(OutboundTransactionStageConsensus {
            stage,
            per_record_node_xids_to_rollback,
            per_record_node_xids_to_drop,
        })
    }

    pub fn get_all_rollbacks(&self) -> PerRecordNodeTransactionIds {
        let mut per_record_node_xids_to_rollback = PerRecordNodeTransactionIds::new();

        for record_state in &self.record_states {
            let node_xids_to_rollback = record_state.get_all_rollbacks();
            per_record_node_xids_to_rollback
                .push((record_state.record_key().opaque(), node_xids_to_rollback));
        }
        per_record_node_xids_to_rollback
    }

    pub fn stage_ts(&self) -> Timestamp {
        self.record_states
            .iter()
            .map(|x| x.stage_ts())
            .reduce(|a, b| a.max(b))
            .unwrap_or(self.created_ts)
    }

    pub fn new_record_state(
        &mut self,
        params: OutboundTransactionRecordParams,
    ) -> VeilidAPIResult<&mut OutboundTransactionRecordState> {
        let opaque_record_key = params.record_key.opaque();
        if self.get_record_state(&opaque_record_key).is_some() {
            apibail_internal!("record info already exists");
        }

        self.record_states
            .push(OutboundTransactionRecordState::new(self.registry(), params));

        Ok(self.record_states.last_mut().unwrap_or_log())
    }

    pub fn get_record_states(&self) -> &[OutboundTransactionRecordState] {
        &self.record_states
    }

    pub fn get_record_states_mut(&mut self) -> &mut [OutboundTransactionRecordState] {
        &mut self.record_states
    }

    pub fn get_record_state(
        &self,
        opaque_record_key: &OpaqueRecordKey,
    ) -> Option<&OutboundTransactionRecordState> {
        self.record_states
            .iter()
            .find(|ri| &ri.record_key().opaque() == opaque_record_key)
    }

    pub fn get_record_state_mut(
        &mut self,
        opaque_record_key: &OpaqueRecordKey,
    ) -> Option<&mut OutboundTransactionRecordState> {
        self.record_states
            .iter_mut()
            .find(|ri| &ri.record_key().opaque() == opaque_record_key)
    }

    pub fn add_background_token(&mut self, background_token: StopToken) {
        self.background_tokens
            .push(futures_util::future::maybe_done(background_token));
    }

    pub fn remove_completed_background_tokens(&mut self) {
        self.background_tokens.retain(|x| match x {
            MaybeDone::Future(_) => true,
            MaybeDone::Done(_) | MaybeDone::Gone => false,
        });
    }

    pub fn into_transaction_cleanup(
        mut self,
        transaction_handle: OutboundTransactionHandle,
    ) -> TransactionCleanup {
        let background_tokens = std::mem::take(&mut self.background_tokens)
            .into_iter()
            .filter_map(|x| match x {
                MaybeDone::Future(fut) => Some(fut),
                MaybeDone::Done(_) | MaybeDone::Gone => None,
            })
            .collect();
        let locked_safety_routes = std::mem::take(&mut self.locked_safety_routes);
        TransactionCleanup {
            transaction_handle,
            background_tokens,
            locked_safety_routes,
        }
    }

    pub fn get_operation_concurrency_semaphore(&self) -> Arc<AsyncSemaphore> {
        self.operation_concurrency.clone()
    }

    pub fn add_locked_safety_routes(&mut self, locked_safety_routes: LockedSafetyRoutes) {
        self.locked_safety_routes.merge(locked_safety_routes);
    }
}
