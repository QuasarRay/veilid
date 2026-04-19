mod node_transaction;
mod node_transaction_id;
mod outbound_transaction_record_state;
mod outbound_transaction_stage;
mod outbound_transaction_state;
mod subkey_consensus;
mod transaction_cleanup;

use super::transaction::OutboundTransactionHandle;
use super::transaction_begin::{OutboundTransactBeginParams, OutboundTransactBeginResult};
use super::transaction_command::{
    OutboundTransactCommandNodes, OutboundTransactCommandParams,
    OutboundTransactCommandPerNodeResult, OutboundTransactCommandResult,
    TransactCommandDisposition,
};
use super::*;

use serde_with::serde_as;

pub(in crate::storage_manager) use node_transaction::*;
pub(in crate::storage_manager) use node_transaction_id::*;
pub(in crate::storage_manager) use outbound_transaction_record_state::*;
pub(in crate::storage_manager) use outbound_transaction_stage::*;
pub(in crate::storage_manager) use outbound_transaction_state::*;
pub(in crate::storage_manager) use subkey_consensus::*;
pub(in crate::storage_manager) use transaction_cleanup::*;

impl_veilid_log_facility!("stor");

/// The percentage of nodes to allow past the consensus count on a transaction begin to account for network errors, rounded up
const CONSENSUS_TRIM_PERCENT: usize = 50;

/// Number of concurrent network operations per transaction
/// excluding keepalives. Applies only to get/set operations inside a begin state.
const PER_TRANSACTION_OPERATION_CONCURRENCY: usize = 32;

/// Outbound Transaction Manager is not currently serialized, so
/// transactions do not survive across app restarts
/// If it is to be serialized it has to be done more intelligently than
/// the `save_metadata` task default json dump that writes the whole thing
/// every 30 seconds.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub(in crate::storage_manager) struct OutboundTransactionManager {
    /// Registry used for logging
    #[serde(skip)]
    opt_registry: Option<VeilidComponentRegistry>,
    /// Record key to handle map
    handles_by_key: HashMap<OpaqueRecordKey, OutboundTransactionHandle>,
    /// Each transaction per record key
    #[serde_as(as = "Vec<(_, _)>")]
    transactions: HashMap<OutboundTransactionHandle, OutboundTransactionState>,
}

impl fmt::Display for OutboundTransactionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = format!("transactions({}): [\n", self.transactions.len());
        {
            let mut keys = self.transactions.keys().cloned().collect::<Vec<_>>();
            keys.sort();

            for k in keys {
                let v = self.transactions.get(&k).unwrap_or_log();
                out += &format!("  {}:\n{}\n", k, indent_all_by(4, f.to_string(v)));
            }
        }
        out += "]\n";

        write!(f, "{}", out)
    }
}
impl Default for OutboundTransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VeilidComponentRegistryAccessor for OutboundTransactionManager {
    fn registry(&self) -> VeilidComponentRegistry {
        self.opt_registry.clone().unwrap_or_log()
    }
}

type OutboundTransactionPerNodeResultHandler<'a> = Box<
    dyn FnMut(&mut NodeTransaction, OutboundTransactCommandPerNodeResult) -> VeilidAPIResult<()>
        + 'a,
>;

impl OutboundTransactionManager {
    pub fn new() -> Self {
        Self {
            opt_registry: None,
            handles_by_key: HashMap::new(),
            transactions: HashMap::new(),
        }
    }

    pub fn prepare(&mut self, routing_table: &RoutingTable) {
        self.opt_registry = Some(routing_table.registry());

        let cur_ts = Timestamp::now();
        for transaction in self.transactions.values_mut() {
            transaction.prepare(routing_table, cur_ts);
        }
    }

    pub fn new_transaction(
        &mut self,
        record_params: Vec<OutboundTransactionRecordParams>,
    ) -> VeilidAPIResult<OutboundTransactionHandle> {
        // Ensure no other transactions are using any of these record keys and make handle
        let mut opaque_record_keys = vec![];
        for rp in &record_params {
            let opaque_record_key = rp.record_key.opaque();
            if self.handles_by_key.contains_key(&opaque_record_key) {
                apibail_generic!(
                    "Record {} already has a a transaction open",
                    opaque_record_key
                );
            }
            opaque_record_keys.push(opaque_record_key);
        }
        let transaction_handle = OutboundTransactionHandle::new(opaque_record_keys.clone());

        // Create a new outbound transaction state
        let mut outbound_transaction_state = OutboundTransactionState::new(self.registry());

        // Add all records
        for rp in record_params {
            outbound_transaction_state.new_record_state(rp)?;
        }

        // Add to transaction list
        for opaque_record_key in opaque_record_keys {
            self.handles_by_key
                .insert(opaque_record_key, transaction_handle.clone());
        }
        self.transactions
            .insert(transaction_handle.clone(), outbound_transaction_state);

        // Success, return the transaction handle
        Ok(transaction_handle)
    }

    /// Drop a transaction completely. Does not error.
    /// If the transaction does not exist, this does nothing and returns None.
    /// If the transaction does exist, it is returned as Some(transaction) after being removed.
    #[must_use]
    pub fn drop_transaction(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
    ) -> Option<OutboundTransactionState> {
        let outbound_transaction_state = match self.transactions.remove(&transaction_handle) {
            Some(x) => x,
            None => {
                veilid_log!(self debugwarn "Dropping non-existent transaction: {:?}", transaction_handle);
                return None;
            }
        };

        veilid_log!(self debug target: "network_result", "Dropping transaction: {:?}", transaction_handle);

        for record_state in outbound_transaction_state.get_record_states() {
            let opaque_record_key = record_state.record_key().opaque();
            self.handles_by_key.remove(&opaque_record_key);
        }
        Some(outbound_transaction_state)
    }

    /// Get transaction handle for record
    pub fn get_transaction_by_record(
        &self,
        opaque_record_key: &OpaqueRecordKey,
    ) -> Option<OutboundTransactionHandle> {
        self.handles_by_key.get(opaque_record_key).cloned()
    }

    /// Check if a transaction exists
    pub fn transaction_exists(&self, transaction_handle: &OutboundTransactionHandle) -> bool {
        self.transactions.contains_key(transaction_handle)
    }

    /// Get a transaction state
    pub fn get_transaction_state(
        &self,
        transaction_handle: &OutboundTransactionHandle,
    ) -> VeilidAPIResult<&OutboundTransactionState> {
        self.transactions
            .get(transaction_handle)
            .ok_or_else(|| VeilidAPIError::transaction_not_found("missing transaction"))
    }

    /// Modify a transaction state
    pub fn get_transaction_state_mut(
        &mut self,
        transaction_handle: &OutboundTransactionHandle,
    ) -> VeilidAPIResult<&mut OutboundTransactionState> {
        self.transactions
            .get_mut(transaction_handle)
            .ok_or_else(|| VeilidAPIError::transaction_not_found("missing transaction"))
    }

    /// Iterate transaction handles and states
    pub fn transactions(
        &self,
    ) -> impl Iterator<Item = (&OutboundTransactionHandle, &OutboundTransactionState)> {
        self.transactions.iter()
    }

    /// Prepare to begin a transaction
    pub fn prepare_transact_begin_params(
        &self,
        transaction_handle: OutboundTransactionHandle,
    ) -> VeilidAPIResult<Vec<OutboundTransactBeginParams>> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state(&transaction_handle)?;

        // Assert stage
        if let Some(stage_consensus) = outbound_transaction_state.stage_consensus() {
            apibail_transaction_not_found!("stage was {:?}, wanted Init", stage_consensus.stage,);
        }

        let mut out = vec![];
        for record_state in outbound_transaction_state.get_record_states() {
            out.push(OutboundTransactBeginParams {
                transaction_handle: transaction_handle.clone(),
                opaque_record_key: record_state.record_key().opaque(),
                safety_selection: record_state.safety_selection().clone(),
                signing_keypair: record_state.signing_keypair().clone(),
            });
        }

        Ok(out)
    }

    /// Record begin transaction
    pub fn record_transact_begin_results(
        &mut self,
        results: Vec<OutboundTransactBeginResult>,
    ) -> VeilidAPIResult<()> {
        #[cfg(feature = "verbose-tracing")]
        let registry = self.registry();

        // Get the required strict consensus count
        let required_strict_consensus_count = self.config().network.dht.set_value_count as usize;

        // Add all node transaction ids
        // Each record must still be in Init state (no node_transactions yet) when being recorded
        for result in results {
            let transaction_handle = result.params.transaction_handle.clone();

            // Get transaction
            let outbound_transaction_state = self.get_transaction_state_mut(&transaction_handle)?;

            // Add locked routes to transaction state
            outbound_transaction_state.add_locked_routes(result.locked_routes);

            // Get record state
            let Some(record_state) =
                outbound_transaction_state.get_record_state_mut(&result.params.opaque_record_key)
            else {
                apibail_internal!(
                    "missing record during begin results recording: {}",
                    result.params.opaque_record_key
                );
            };

            // Ensure results came in with enough consensus
            let node_transaction_count = record_state.get_node_transactions().len();
            if node_transaction_count < required_strict_consensus_count {
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(registry debug target: "dht", "Did not get a consensus of transaction ids for begin for handle={} record={}: merged_seqs={} with state: {}",
                    transaction_handle,
                    result.params.opaque_record_key,
                    result.seqs.to_table_string(),
                    record_state
                );

                apibail_try_again!("did not get consensus of transaction ids in begin (rec={}, count={}, required_consensus={})",
                    result.params.opaque_record_key,
                    node_transaction_count,
                    required_strict_consensus_count
                );
            }

            // Update record state with results
            record_state.update_descriptor(result.descriptor)?;
            record_state.update_begin_network_seqs(result.seqs)?;

            // Assert this record is now in the Begin state
            let Some(stage_consensus) = record_state.stage_consensus() else {
                apibail_generic!(
                    "record {} has no stage consensus during begin results recording",
                    result.params.opaque_record_key
                );
            };

            if stage_consensus.stage != OutboundTransactionStage::Begin {
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(registry debug target: "dht", "record {} did not get Begin consensus with state: {}", result.params.opaque_record_key, record_state);

                apibail_generic!(
                    "record {} has stage consensus {:?} during begin results recording, wanted Begin",
                    result.params.opaque_record_key,
                    stage_consensus.stage
                );
            }

            // Trim the number of node transactions down to a multiplier of the strict consensus count
            let max_node_transaction_params_count = required_strict_consensus_count
                + (required_strict_consensus_count * CONSENSUS_TRIM_PERCENT).div_ceil(100);

            record_state.trim_node_transactions(max_node_transaction_params_count);

            #[cfg(feature = "verbose-tracing")]
            veilid_log!(registry debug target: "dht", "Begin results for record {}: {}", result.params.opaque_record_key, record_state);
        }

        Ok(())
    }

    /// Generic transact command result recording boilerplate common to all results
    fn record_transact_command_results(
        outbound_transaction_state: &mut OutboundTransactionState,
        results: Vec<OutboundTransactCommandResult>,
        mut callback: OutboundTransactionPerNodeResultHandler<'_>,
    ) -> VeilidAPIResult<()> {
        // Record results
        for result in results {
            let opaque_record_key = &result.params.opaque_record_key;

            let Some(record_state) =
                outbound_transaction_state.get_record_state_mut(opaque_record_key)
            else {
                apibail_internal!("missing record: {}", opaque_record_key);
            };

            callback =
                Self::record_transact_command_per_record_results(record_state, result, callback)?
        }
        Ok(())
    }

    /// Generic transact command per-record result recording boilerplate common to all record results
    fn record_transact_command_per_record_results<'a>(
        record_state: &mut OutboundTransactionRecordState,
        result: OutboundTransactCommandResult,
        mut callback: OutboundTransactionPerNodeResultHandler<'a>,
    ) -> VeilidAPIResult<OutboundTransactionPerNodeResultHandler<'a>> {
        let mut command_node_xids = result.get_command_node_xids();
        for pnr in result.per_node_results {
            if !command_node_xids.remove(&pnr.node_transaction_id) {
                apibail_internal!(
                    "node transaction has multiple results: {} pnr={:?}",
                    result.params.opaque_record_key,
                    pnr
                );
            }

            let node_transaction = record_state
                .get_node_transaction_mut(&pnr.node_transaction_id)
                .ok_or_else(|| VeilidAPIError::internal("missing node transaction"))?;

            match pnr.disposition {
                TransactCommandDisposition::Invalid => {
                    // If not valid, the server already rolled it back
                    #[cfg(feature = "verbose-tracing")]
                    veilid_log!(node_transaction debug target: "dht", "transact_command_result: node={} INVALID (server rolled back) record={}",
                        pnr.node_transaction_id, result.params.opaque_record_key);
                    node_transaction.set_stage(OutboundTransactionStage::Rollback, None);
                    continue;
                }
                TransactCommandDisposition::Skipped => {
                    // Node was not waited for due to early consensus exit, leave its stage unchanged
                    #[cfg(feature = "verbose-tracing")]
                    veilid_log!(node_transaction debug target: "dht", "transact_command_result: node={} SKIPPED (no response/early exit) record={} stage={:?}",
                        pnr.node_transaction_id, result.params.opaque_record_key, node_transaction.stage());
                    continue;
                }
                TransactCommandDisposition::Valid => {
                    // If transaction is still valid, then call the processing callback
                    callback(node_transaction, pnr)?;
                }
            }
        }

        // Any commands that did not return a result have their node transactions marked as failed
        for missing_node_xid in &command_node_xids {
            let Some(node_transaction) = record_state.get_node_transaction_mut(missing_node_xid)
            else {
                apibail_internal!(
                    "missing node transaction in record state: {}",
                    missing_node_xid,
                );
            };
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(node_transaction debug target: "dht", "transact_command_result: node={} MISSING result → Failed",
                missing_node_xid);
            node_transaction.set_stage(OutboundTransactionStage::Failed, None);
        }
        Ok(callback)
    }

    /// Prepare to rollback a transaction.
    ///
    /// Best-effort: if Begin never reached consensus (or got zero accepts), this returns
    /// rollback params only for nodes that actually did accept Begin. If no nodes ever
    /// accepted, returns an empty list (nothing to roll back). The caller still gets the
    /// original begin error (TryAgain / etc.) propagated through rollback_guard_locked.
    pub fn prepare_rollback_transact_value_params(
        &self,
        transaction_handle: OutboundTransactionHandle,
        opt_rollback_ids: Option<PerRecordNodeTransactionIds>,
    ) -> VeilidAPIResult<Vec<OutboundTransactCommandParams>> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state(&transaction_handle)?;

        // If rollback ids are specified, just go with it
        // Otherwise get the full set of fail rollback ids (empty if no nodes accepted)
        let rollback_ids = match opt_rollback_ids {
            Some(rbids) => rbids,
            None => outbound_transaction_state.get_all_rollbacks(),
        };

        let mut out = vec![];

        for (opaque_record_key, node_xids) in rollback_ids {
            // Skip records with no nodes to roll back (Begin never got any accepts for this record)
            if node_xids.is_empty() {
                continue;
            }

            let record_state = outbound_transaction_state
                .get_record_state(&opaque_record_key)
                .ok_or_else(|| {
                    VeilidAPIError::internal(format!(
                        "tried to rollback record not in transaction: {}",
                        opaque_record_key
                    ))
                })?;

            let safety_selection = record_state.safety_selection().clone();
            let nodes = record_state.get_transact_command_nodes(Some(&node_xids), None)?;
            let required_strict_consensus_count = record_state.required_strict_consensus_count();

            out.push(OutboundTransactCommandParams {
                opaque_record_key,
                safety_selection,
                nodes,
                command: TransactCommand::Rollback,
                opt_seqs: None,
                opt_subkey: None,
                opt_value: None,
                required_strict_consensus_count,
            });
        }

        Ok(out)
    }

    /// Record rollback transaction
    pub fn record_transact_rollback_results(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
        results: Vec<OutboundTransactCommandResult>,
    ) -> VeilidAPIResult<()> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state_mut(&transaction_handle)?;

        // If there are no results, nothing to record. This happens when a rollback was
        // issued for a transaction that never reached Begin consensus (zero nodes accepted).
        if results.is_empty() {
            return Ok(());
        }

        // Record results
        Self::record_transact_command_results(
            outbound_transaction_state,
            results,
            Box::new(
                |node_transaction: &mut NodeTransaction,
                 _: OutboundTransactCommandPerNodeResult| {
                    // Transition to rollback stage
                    node_transaction.set_stage(OutboundTransactionStage::Rollback, None);
                    Ok(())
                },
            ) as OutboundTransactionPerNodeResultHandler,
        )?;

        Ok(())
    }

    /// Prepare to end a transaction
    pub fn prepare_transact_end_params(
        &self,
        transaction_handle: OutboundTransactionHandle,
    ) -> VeilidAPIResult<Vec<OutboundTransactCommandParams>> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::Begin => {}
            OutboundTransactionStage::End
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted Begin", stage);
            }
        }

        let mut out = vec![];

        for record_state in outbound_transaction_state.get_record_states() {
            let opaque_record_key = record_state.record_key().opaque();
            let safety_selection = record_state.safety_selection().clone();
            let nodes = record_state.get_transact_command_nodes(None, None)?;
            let required_strict_consensus_count = record_state.required_strict_consensus_count();

            out.push(OutboundTransactCommandParams {
                opaque_record_key,
                safety_selection,
                nodes,
                command: TransactCommand::End,
                opt_seqs: None,
                opt_subkey: None,
                opt_value: None,
                required_strict_consensus_count,
            });
        }

        Ok(out)
    }

    /// Record end transaction
    pub fn record_transact_end_results(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
        results: Vec<OutboundTransactCommandResult>,
    ) -> VeilidAPIResult<()> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state_mut(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::Begin => {}
            OutboundTransactionStage::End
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted Begin", stage);
            }
        }

        // Record results
        Self::record_transact_command_results(
            outbound_transaction_state,
            results,
            Box::new(
                |node_transaction: &mut NodeTransaction,
                 pnr: OutboundTransactCommandPerNodeResult| {
                    // Transition to end stage
                    node_transaction.set_stage(OutboundTransactionStage::End, pnr.opt_expiration);
                    Ok(())
                },
            ) as OutboundTransactionPerNodeResultHandler,
        )?;

        Ok(())
    }

    /// Prepare to commit a transaction
    pub fn prepare_transact_commit_params(
        &self,
        transaction_handle: OutboundTransactionHandle,
    ) -> VeilidAPIResult<Vec<OutboundTransactCommandParams>> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::End => {}
            OutboundTransactionStage::Begin
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted End", stage);
            }
        }

        let mut out = vec![];

        for record_state in outbound_transaction_state.get_record_states() {
            let opaque_record_key = record_state.record_key().opaque();
            let safety_selection = record_state.safety_selection().clone();
            // commit_will_change_remote() logs internally when returning false
            let nodes = record_state.get_transact_command_nodes(
                None,
                Some(Box::new(|nt: &NodeTransaction| {
                    nt.commit_will_change_remote()
                })),
            )?;
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug target: "dht", "prepare_commit: record={} nodes_requiring_commit_rpc={} total_nodes={}",
                opaque_record_key,
                nodes.len(),
                record_state.get_node_transactions().len());
            let required_strict_consensus_count = record_state.required_strict_consensus_count();

            out.push(OutboundTransactCommandParams {
                opaque_record_key,
                safety_selection,
                nodes,
                command: TransactCommand::Commit,
                opt_seqs: None,
                opt_subkey: None,
                opt_value: None,
                required_strict_consensus_count,
            });
        }

        Ok(out)
    }

    /// Record commit transaction
    pub fn record_transact_commit_results(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
        results: Vec<OutboundTransactCommandResult>,
    ) -> VeilidAPIResult<()> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state_mut(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::End => {}
            OutboundTransactionStage::Begin
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted End", stage);
            }
        }

        // For all node transactions where commit commands were not required,
        // transition them directly to the commit state.
        for record_state in outbound_transaction_state.get_record_states_mut() {
            for node_transaction in record_state.get_node_transactions_mut() {
                // commit_will_change_remote() logs internally when returning false
                if !node_transaction.commit_will_change_remote() {
                    node_transaction.set_stage(OutboundTransactionStage::Commit, None);
                }
            }
        }

        // Record results
        Self::record_transact_command_results(
            outbound_transaction_state,
            results,
            Box::new(
                |node_transaction: &mut NodeTransaction,
                 _: OutboundTransactCommandPerNodeResult| {
                    // Transition to end stage
                    node_transaction.set_stage(OutboundTransactionStage::Commit, None);
                    Ok(())
                },
            ) as OutboundTransactionPerNodeResultHandler,
        )?;

        Ok(())
    }

    /// Prepare to set a value in a transaction
    pub fn prepare_transact_set_params(
        &self,
        transaction_handle: OutboundTransactionHandle,
        opaque_record_key: &OpaqueRecordKey,
        subkey: ValueSubkey,
        signed_value_data: Arc<SignedValueData>,
    ) -> VeilidAPIResult<OutboundTransactCommandParams> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::Begin => {}
            OutboundTransactionStage::End
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted Begin", stage);
            }
        }

        let Some(record_state) = outbound_transaction_state.get_record_state(opaque_record_key)
        else {
            apibail_invalid_argument!(
                "record not in transaction",
                "opaque_record_key",
                opaque_record_key
            );
        };

        // Check if the subkey is in range
        if subkey
            > record_state
                .schema()
                .ok_or_else(|| VeilidAPIError::internal("missing descriptor"))?
                .max_subkey()
        {
            apibail_invalid_argument!("subkey out of range", "subkey", subkey);
        }

        let safety_selection = record_state.safety_selection().clone();
        // Only send Set to Begin-stage nodes; Rollback nodes reject unconditionally.
        let nodes = record_state.get_transact_command_nodes(
            None,
            Some(Box::new(|nt: &NodeTransaction| {
                nt.stage() == OutboundTransactionStage::Begin
            })),
        )?;
        let required_strict_consensus_count = record_state.required_strict_consensus_count();

        Ok(OutboundTransactCommandParams {
            opaque_record_key: opaque_record_key.clone(),
            safety_selection,
            nodes,
            command: TransactCommand::Set,
            opt_seqs: None,
            opt_subkey: Some(subkey),
            opt_value: Some(signed_value_data),
            required_strict_consensus_count,
        })
    }

    /// Record set value in transaction
    pub fn record_transact_set_result(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
        result: OutboundTransactCommandResult,
    ) -> VeilidAPIResult<()> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state_mut(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::Begin => {}
            OutboundTransactionStage::End
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted Begin", stage);
            }
        }

        // Get the record state we're working on
        let Some(record_state) =
            outbound_transaction_state.get_record_state_mut(&result.params.opaque_record_key)
        else {
            apibail_internal!("missing record in set: {}", result.params.opaque_record_key);
        };

        // Set desired subkey to track goal state
        let subkey = result.params.opt_subkey.unwrap_or_log();
        let value = result.params.opt_value.clone().unwrap_or_log();
        record_state.set_desired_subkey(subkey, value.clone());

        // Record set results and calculate the result state consensus
        let mut opt_set_subkey_consensus: Option<SubkeyConsensus> = None;
        let mut found_newer = false;
        let required_strict_consensus_count = record_state.required_strict_consensus_count();

        let set_result_handler = Box::new(
            |node_transaction: &mut NodeTransaction, pnr: OutboundTransactCommandPerNodeResult| {
                // Check if node id transactions reached consensus

                node_transaction.update_expiration(pnr.opt_expiration);

                // Record subkey write
                let opt_value = if let Some(newer_value) = pnr.opt_value {
                    // Something newer was found

                    // (Asserted in decode/validate) Subkey should be present if value is
                    let Some(newer_value_subkey) = pnr.opt_subkey else {
                        apibail_internal!("missing subkey for value");
                    };
                    // (Asserted in decode/validate) Ensure newer subkey matches params
                    if subkey != newer_value_subkey {
                        apibail_internal!("returned subkey does not match parameter");
                    }
                    // (Asserted in decode/validate) Ensure newer value was actually newer or equal
                    if newer_value.value_data().seq() < value.value_data().seq() {
                        apibail_internal!("returned newer value is older than current value");
                    }

                    // Newer value found online
                    #[cfg(feature = "verbose-tracing")]
                    veilid_log!(node_transaction debug target: "dht", "transact_set: node={} subkey={} NEWER value found online seq={} (our seq={}), write cancelled",
                        node_transaction.node_xid(), subkey,
                        newer_value.value_data().seq(), value.value_data().seq());
                    node_transaction.record_current_subkey_value(subkey, Some(newer_value.clone()));
                    node_transaction.record_updated_subkey_value(subkey, None);

                    let opt_value = Some(newer_value);
                    found_newer = true;
                    opt_value
                } else {
                    // Successful write
                    #[cfg(feature = "verbose-tracing")]
                    veilid_log!(node_transaction debug target: "dht", "transact_set: node={} subkey={} write accepted seq={}",
                        node_transaction.node_xid(), subkey, value.value_data().seq());
                    node_transaction.record_updated_subkey_value(subkey, Some(value.clone()));

                    Some(value.clone())
                };

                if let Some(set_subkey_state) = &mut opt_set_subkey_consensus {
                    set_subkey_state.add_value(opt_value, required_strict_consensus_count);
                } else {
                    opt_set_subkey_consensus = Some(SubkeyConsensus::new(opt_value));
                }

                Ok(())
            },
        ) as OutboundTransactionPerNodeResultHandler;

        let _ = Self::record_transact_command_per_record_results(
            record_state,
            result,
            set_result_handler,
        )?;

        // Record the subkey consensus results
        if let Some(set_subkey_consensus) = opt_set_subkey_consensus {
            if found_newer {
                // Add found newer value to current subkey consensus
                record_state
                    .current_consensus_mut()
                    .record(subkey, Some(set_subkey_consensus));
                // Remove updated subkey consensus
                record_state.updated_consensus_mut().record(subkey, None);
            } else {
                // Add set value to updated subkey consensus
                record_state
                    .updated_consensus_mut()
                    .record(subkey, Some(set_subkey_consensus));
            }
        } else {
            // If no consensus was reached, we eliminate the consensus records for this subkey
            // and return a try again error
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(record_state debug target: "dht", "transact_set: subkey={}:{} NO CONSENSUS reached (found_newer={}) → TryAgain",
                record_state.record_key().opaque(), subkey, found_newer);
            record_state.updated_consensus_mut().record(subkey, None);
            record_state.current_consensus_mut().record(subkey, None);
            apibail_try_again!(
                "set did not reach consensus for subkey: {}:{}",
                record_state.record_key().opaque(),
                subkey
            );
        }

        Ok(())
    }

    /// Prepare to get a value in a transaction
    pub fn prepare_transact_get_params(
        &self,
        transaction_handle: OutboundTransactionHandle,
        opaque_record_key: &OpaqueRecordKey,
        subkey: ValueSubkey,
    ) -> VeilidAPIResult<OutboundTransactCommandParams> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::Begin => {}
            OutboundTransactionStage::End
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted Begin", stage);
            }
        }

        let Some(record_state) = outbound_transaction_state.get_record_state(opaque_record_key)
        else {
            apibail_invalid_argument!(
                "record not in transaction",
                "opaque_record_key",
                opaque_record_key
            );
        };

        // Check if the subkey is in range
        if subkey
            > record_state
                .schema()
                .ok_or_else(|| VeilidAPIError::internal("missing descriptor"))?
                .max_subkey()
        {
            apibail_invalid_argument!("subkey out of range", "subkey", subkey);
        }

        let safety_selection = record_state.safety_selection().clone();
        let nodes = record_state.get_transact_command_nodes(None, None)?;
        // Use get_value_count as GET consensus threshold so a single non-responding node
        // won't force a costly retry that exceeds the outer timeout. (get_value_count <= set_value_count by config.)
        let required_strict_consensus_count = self.config().network.dht.get_value_count as usize;

        Ok(OutboundTransactCommandParams {
            opaque_record_key: opaque_record_key.clone(),
            safety_selection,
            nodes,
            command: TransactCommand::Get,
            opt_seqs: None,
            opt_subkey: Some(subkey),
            opt_value: None,
            required_strict_consensus_count,
        })
    }

    /// Record get value in transaction
    pub fn record_transact_get_result(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
        result: OutboundTransactCommandResult,
    ) -> VeilidAPIResult<()> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state_mut(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::Begin => {}
            OutboundTransactionStage::End
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted Begin", stage);
            }
        }

        // Check if node id transactions reached consensus
        let Some(record_state) =
            outbound_transaction_state.get_record_state_mut(&result.params.opaque_record_key)
        else {
            apibail_internal!("missing record in get: {}", result.params.opaque_record_key);
        };

        // Record get results and calculate the result state consensus
        let subkey = result.params.opt_subkey.unwrap_or_log();

        // Calculate the result state consensus
        let mut opt_get_subkey_consensus: Option<SubkeyConsensus> = None;
        let required_strict_consensus_count = record_state.required_strict_consensus_count();

        let get_result_handler = Box::new(
            |node_transaction: &mut NodeTransaction, pnr: OutboundTransactCommandPerNodeResult| {
                // Record subkey get for this node transaction
                let opt_value = pnr.opt_value;
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(node_transaction debug target: "dht", "transact_get: node={} subkey={} returned seq={}",
                    node_transaction.node_xid(), subkey,
                    opt_value.as_ref().map(|v| v.value_data().seq().to_string()).unwrap_or_else(|| "None".to_string()));
                node_transaction.record_current_subkey_value(subkey, opt_value.clone());
                node_transaction.update_expiration(pnr.opt_expiration);

                if let Some(get_subkey_state) = &mut opt_get_subkey_consensus {
                    get_subkey_state.add_value(opt_value, required_strict_consensus_count);
                } else {
                    opt_get_subkey_consensus = Some(SubkeyConsensus::new(opt_value));
                }
                Ok(())
            },
        ) as OutboundTransactionPerNodeResultHandler;

        let _ = Self::record_transact_command_per_record_results(
            record_state,
            result,
            get_result_handler,
        )?;

        // Record the subkey consensus results
        record_state
            .current_consensus_mut()
            .record(subkey, opt_get_subkey_consensus);

        Ok(())
    }

    /// Record keepalive results
    pub fn record_transact_keepalive_result(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
        opaque_record_key: OpaqueRecordKey,
        node_xid: NodeTransactionId,
        expiration: Timestamp,
    ) -> VeilidAPIResult<bool> {
        #[cfg(feature = "verbose-tracing")]
        let registry = self.registry();

        let outbound_transaction_state = self.get_transaction_state_mut(&transaction_handle)?;
        let Some(record_state) =
            outbound_transaction_state.get_record_state_mut(&opaque_record_key)
        else {
            // Record was removed from transaction
            return Ok(false);
        };
        let Some(nt) = record_state.get_node_transaction_mut(&node_xid) else {
            // Node transaction was dropped from transaction
            return Ok(false);
        };

        // Update expiration only if we're still in Begin or End stage
        if matches!(
            nt.stage(),
            OutboundTransactionStage::Begin | OutboundTransactionStage::End
        ) {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(registry debug target: "dht", "Keepalive updated expiration: transaction_handle={} record={} node_xid={} expiration={:#}", transaction_handle, opaque_record_key, node_xid, expiration);

            nt.update_expiration(Some(expiration));
        } else {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(registry debug target: "dht", "Keepalive update ignored: stage={} transaction_handle={} record={} node_xid={} expiration={:#}", nt.stage(), transaction_handle, opaque_record_key, node_xid, expiration);
        }

        Ok(matches!(nt.stage(), OutboundTransactionStage::Begin))
    }

    /// Get an inspection report for a transaction
    pub fn get_record_report(
        &mut self,
        transaction_handle: OutboundTransactionHandle,
        opaque_record_key: &OpaqueRecordKey,
        subkeys: Option<ValueSubkeyRangeSet>,
        scope: DHTReportScope,
    ) -> VeilidAPIResult<DHTRecordReport> {
        // Get transaction
        let outbound_transaction_state = self.get_transaction_state(&transaction_handle)?;

        // Assert stage
        let stage = outbound_transaction_state
            .stage_consensus()
            .ok_or_else(|| VeilidAPIError::generic("transaction not started"))?
            .stage;
        match stage {
            OutboundTransactionStage::Begin => {}
            OutboundTransactionStage::End
            | OutboundTransactionStage::Failed
            | OutboundTransactionStage::Rollback
            | OutboundTransactionStage::Commit => {
                apibail_transaction_not_found!("stage was {:?}, wanted Begin", stage);
            }
        }

        let Some(record_state) = outbound_transaction_state.get_record_state(opaque_record_key)
        else {
            apibail_invalid_argument!(
                "record not in transaction",
                "opaque_record_key",
                opaque_record_key
            );
        };

        let Some(schema) = record_state.schema() else {
            apibail_internal!("no schema for transaction");
        };

        let subkeys = ValueSubkeyRangeSet::single_range(0, schema.max_subkey())
            .intersect(&subkeys.unwrap_or_else(ValueSubkeyRangeSet::full));

        let opt_local_snapshot = record_state.local_snapshot();
        let mut local_seqs = Vec::with_capacity(subkeys.len() as usize);
        let mut network_seqs = Vec::with_capacity(subkeys.len() as usize);
        for subkey in subkeys.iter() {
            let Some(local_snapshot) = &opt_local_snapshot else {
                local_seqs.push(ValueSeqNum::NONE);
                continue;
            };

            let mut local_seq = local_snapshot.seq(subkey)?;

            match scope {
                DHTReportScope::Local => {
                    local_seqs.push(local_seq);
                    network_seqs.push(ValueSeqNum::NONE);
                }
                DHTReportScope::SyncGet | DHTReportScope::SyncSet => {
                    local_seqs.push(local_seq);
                    network_seqs.push(record_state.begin_network_seq(subkey)?);
                }
                DHTReportScope::UpdateGet => {
                    let network_seq = record_state.begin_network_seq(subkey)?;
                    local_seqs.push(ValueSeqNum::max(local_seq, network_seq));
                    network_seqs.push(network_seq);
                }
                DHTReportScope::UpdateSet => {
                    let network_seq = record_state.begin_network_seq(subkey)?;
                    local_seq = local_seq.next()?;
                    local_seqs.push(local_seq);
                    network_seqs.push(ValueSeqNum::max(local_seq, network_seq));
                }
            }
        }

        DHTRecordReport::new(
            subkeys,
            // Transactions never have offline subkeys
            ValueSubkeyRangeSet::new(),
            local_seqs,
            network_seqs,
        )
    }
}
