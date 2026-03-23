use super::*;

impl_veilid_log_facility!("stor");

pub(in crate::storage_manager) type OutboundTransactCommandNodes =
    Vec<(NodeTransactionId, NodeRef)>;

/// parameters required to perform a command on a transaction
#[derive(Debug, Clone)]
pub(in crate::storage_manager) struct OutboundTransactCommandParams {
    /// The record key being transacted
    pub opaque_record_key: OpaqueRecordKey,
    /// The safety selection used with the transaction
    pub safety_selection: SafetySelection,
    /// Nodes and transaction ids to use
    pub nodes: OutboundTransactCommandNodes,
    /// The command to execute on each node
    pub command: TransactCommand,
    /// Parameter for the command (sequence numbers)
    pub opt_seqs: Option<Vec<ValueSeqNum>>,
    /// Parameter for the command (subkey number)
    pub opt_subkey: Option<ValueSubkey>,
    /// Parameter for the command (value)
    pub opt_value: Option<Arc<SignedValueData>>,
    /// The number of valid responses required for strict consensus
    pub required_strict_consensus_count: usize,
}

/// Disposition of a per-node transaction command result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::storage_manager) enum TransactCommandDisposition {
    /// The node responded and the transaction is still valid
    Valid,
    /// The node responded but the transaction is no longer valid
    Invalid,
    /// The node was not waited for due to early consensus exit
    Skipped,
}

/// The result of the outbound_transact_command operation
#[derive(Debug)]
pub(in crate::storage_manager) struct OutboundTransactCommandPerNodeResult {
    /// The node transaction id this is for
    pub node_transaction_id: NodeTransactionId,
    /// The disposition of this node's result
    pub disposition: TransactCommandDisposition,
    /// Return from the command (sequence numbers)
    #[expect(dead_code)]
    pub opt_seqs: Option<Vec<ValueSeqNum>>,
    /// Return from the command (subkey number)
    pub opt_subkey: Option<ValueSubkey>,
    /// Return from the command (value)
    pub opt_value: Option<Arc<SignedValueData>>,
    /// Updated expiration to apply
    pub opt_expiration: Option<Timestamp>,
}

/// The result of the outbound_transact_command operation
#[derive(Debug)]
pub(in crate::storage_manager) struct OutboundTransactCommandResult {
    /// Copy of the params used to produce these results
    pub params: OutboundTransactCommandParams,
    /// The results per node, in closest-to-the-record-key sorted order
    pub per_node_results: Vec<OutboundTransactCommandPerNodeResult>,
}

impl OutboundTransactCommandResult {
    pub fn get_command_node_xids(&self) -> HashSet<NodeTransactionId> {
        self.params
            .nodes
            .iter()
            .map(|x| x.0.clone())
            .collect::<HashSet<_>>()
    }
}

/// The result of the inbound_transact_command operation
#[derive(Clone, Debug)]
pub(crate) enum InboundTransactCommandResult {
    /// Value transacted successfully
    Success(TransactCommandSuccess),
    /// Transaction not valid
    InvalidTransaction,
    /// Invalid arguments
    InvalidArguments,
}

/// The result of a single successful transaction command
#[derive(Default, Debug, Clone)]
pub(crate) struct TransactCommandSuccess {
    /// Expiration timestamp
    pub expiration: Timestamp,
    /// Sequence numbers
    pub opt_seqs: Option<Vec<ValueSeqNum>>,
    /// Subkey
    pub opt_subkey: Option<ValueSubkey>,
    /// Value
    pub opt_value: Option<Arc<SignedValueData>>,
}

impl StorageManager {
    ////////////////////////////////////////////////////////////////////////

    /// Perform transact command queries on the network for a single record.
    ///
    /// Fans out transact commands to all nodes concurrently via FuturesUnordered.
    /// Results are collected as they complete. Early exit once strict consensus is reached.
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "dht", skip_all, err)
    )]
    pub(in crate::storage_manager) async fn outbound_transact_command(
        &self,
        params: OutboundTransactCommandParams,
    ) -> VeilidAPIResult<OutboundTransactCommandResult> {
        let OutboundTransactCommandParams {
            opaque_record_key,
            safety_selection,
            nodes,
            command,
            opt_seqs,
            opt_subkey,
            opt_value,
            required_strict_consensus_count,
        } = params.clone();

        let routing_domain = RoutingDomain::PublicInternet;

        // Pull the descriptor for this record
        let descriptor = {
            let local_record_store = self.get_local_record_store()?;
            local_record_store
                .with_record(&opaque_record_key, |record| record.descriptor())?
                .ok_or_else(|| VeilidAPIError::internal("record does not exist in transaction"))?
        };

        let total_nodes = nodes.len();

        #[cfg(feature = "verbose-tracing")]
        let diag_start = {
            veilid_log!(self debug "TransactCmd start: cmd={} key={}{} nodes={} required_consensus={}",
                command,
                opaque_record_key,
                if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                total_nodes,
                required_strict_consensus_count,
            );
            Timestamp::now()
        };

        // Retry loop: send commands, and if consensus isn't reached but progress
        // was made (some nodes responded), retry with only non-responding nodes.
        // Each retry uses a new randomly-selected safety route, which may succeed
        // where the previous route timed out. The keepalive processor keeps the
        // server-side transaction alive during retries.
        let mut per_node_results: Vec<OutboundTransactCommandPerNodeResult> = Vec::new();
        let mut valid_response_count = 0usize;
        let mut nodes_to_send = nodes.clone();
        #[cfg(feature = "verbose-tracing")]
        let mut attempt = 0usize;

        loop {
            if nodes_to_send.is_empty() {
                break;
            }

            #[cfg(feature = "verbose-tracing")]
            {
                attempt += 1;
                if attempt > 1 {
                    veilid_log!(self debug "TransactCmd retry: cmd={} key={}{} attempt={} retrying_nodes={} valid_so_far={}/{}",
                        command,
                        opaque_record_key,
                        if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                        attempt,
                        nodes_to_send.len(),
                        valid_response_count,
                        required_strict_consensus_count,
                    );
                }
            }

            let prev_valid_count = valid_response_count;
            #[cfg(feature = "verbose-tracing")]
            let attempt_node_count = nodes_to_send.len();

            let mut unord = FuturesUnordered::new();

            for (node_transaction_id, node_ref) in &nodes_to_send {
                let registry = self.registry();
                let node_transaction_id = node_transaction_id.clone();
                let node_ref = node_ref.clone();
                let descriptor = descriptor.clone();
                let opaque_record_key = opaque_record_key.clone();
                let safety_selection = safety_selection.clone();
                let opt_seqs = opt_seqs.clone();
                let opt_value = opt_value.clone();
                #[cfg(feature = "verbose-tracing")]
                let node_start = Timestamp::now();

                let node_xid_key = node_transaction_id.clone();

                unord.push(Box::pin(async move {
                    let rpc_processor = registry.rpc_processor();

                    let rpc_result = rpc_processor
                        .rpc_call_transact_command(
                            Destination::direct(
                                node_ref.routing_domain_filtered(routing_domain),
                                Some(safety_selection),
                            ),
                            opaque_record_key.clone(),
                            descriptor,
                            node_transaction_id.xid(),
                            command,
                            opt_seqs,
                            opt_subkey,
                            opt_value,
                        )
                        .await
                        .map_err(VeilidAPIError::from);

                    #[cfg(feature = "verbose-tracing")]
                    let node_elapsed = Timestamp::now().duration_since(node_start);

                    let mapped = rpc_result.map(|result| match result {
                        NetworkResult::Timeout | NetworkResult::NoConnection(_) => {
                            #[cfg(feature = "verbose-tracing")]
                            {
                                let dial_info_str = node_ref
                                    .node_info(routing_domain)
                                    .map(|ni| {
                                        let dids = ni.dial_info_detail_list();
                                        if dids.is_empty() {
                                            "no_dialinfo".to_string()
                                        } else {
                                            dids.iter()
                                                .map(|d| format!("{}", d))
                                                .collect::<Vec<_>>()
                                                .join(",")
                                        }
                                    })
                                    .unwrap_or_else(|| "no_nodeinfo".to_string());
                                let caps = node_ref
                                    .node_info(routing_domain)
                                    .map(|ni| format!("{:?}", ni.capabilities()))
                                    .unwrap_or_default();
                                veilid_log!(registry debug "TransactCmd node NO_RESPONSE: cmd={} key={}{} node={} elapsed={} dial_info=[{}] caps={}",
                                    command, opaque_record_key,
                                    if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                                    node_ref, node_elapsed,
                                    dial_info_str, caps);
                            }
                            None
                        }
                        NetworkResult::ServiceUnavailable(_)
                        | NetworkResult::AlreadyExists(_)
                        | NetworkResult::InvalidMessage(_) => {
                            #[cfg(feature = "verbose-tracing")]
                            veilid_log!(registry debug "TransactCmd node result: cmd={} key={}{} node={} result=SERVICE_ERROR elapsed={}",
                                command, opaque_record_key,
                                if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                                node_ref, node_elapsed,
                            );
                            None
                        }
                        NetworkResult::Value(tva) => {
                            let disposition = if tva.answer.transaction_valid {
                                #[cfg(feature = "verbose-tracing")]
                                veilid_log!(registry debug "TransactCmd node result: cmd={} key={}{} node={} result=VALID elapsed={}",
                                    command, opaque_record_key,
                                    if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                                    node_ref, node_elapsed,
                                );
                                TransactCommandDisposition::Valid
                            } else {
                                #[cfg(feature = "verbose-tracing")]
                                veilid_log!(registry debug "TransactCmd node INVALID (no longer valid): cmd={} key={}{} node={} elapsed={}",
                                    command, opaque_record_key,
                                    if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                                    node_ref, node_elapsed,
                                );
                                TransactCommandDisposition::Invalid
                            };

                            Some(OutboundTransactCommandPerNodeResult {
                                node_transaction_id,
                                disposition,
                                opt_seqs: tva.answer.opt_seqs,
                                opt_subkey: tva.answer.opt_subkey,
                                opt_value: tva.answer.opt_value,
                                opt_expiration: tva.answer.opt_expiration,
                            })
                        }
                    });

                    (node_xid_key, mapped)
                }));
            }

            // Collect results; exit early on consensus (remaining futures dropped).
            #[cfg(feature = "verbose-tracing")]
            let attempt_node_count_diag = attempt_node_count;
            let mut attempt_responded_xids = HashSet::new();
            let mut consensus_reached = false;

            while let Some((_node_xid, result)) = unord.next().await {
                let opt_pnr = result.inspect_err(|e| {
                    veilid_log!(self error target:"network_result",
                        "Error performing transaction command: {}", e);
                })?;

                if let Some(pnr) = opt_pnr {
                    if pnr.disposition == TransactCommandDisposition::Valid {
                        valid_response_count += 1;
                    }
                    attempt_responded_xids.insert(pnr.node_transaction_id.clone());
                    per_node_results.push(pnr);

                    // Early exit: once we have enough valid responses for consensus,
                    // stop waiting for remaining nodes that may be timing out.
                    if valid_response_count >= required_strict_consensus_count {
                        #[cfg(feature = "verbose-tracing")]
                        {
                            let responded = attempt_responded_xids.len();
                            if responded < attempt_node_count_diag {
                                veilid_log!(self debug "TransactCmd early exit: cmd={} key={}{} valid={}/{} responded={}/{}",
                                    command,
                                    opaque_record_key,
                                    if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                                    valid_response_count,
                                    required_strict_consensus_count,
                                    responded,
                                    attempt_node_count_diag,
                                );
                            }
                        }
                        consensus_reached = true;
                        break;
                    }
                }
                // None (timeout/no-response): excluded from responded set, eligible for retry.
            }

            // If consensus reached, we're done
            if consensus_reached {
                break;
            }

            // Check if progress was made this attempt
            if valid_response_count <= prev_valid_count {
                // No new valid responses — stop retrying
                break;
            }

            // Progress was made but consensus not yet reached.
            // Identify non-responding nodes from this attempt for retry.
            nodes_to_send.retain(|(nxid, _)| !attempt_responded_xids.contains(nxid));
        }

        // Log summary
        #[cfg(feature = "verbose-tracing")]
        {
            let invalid_count = per_node_results
                .iter()
                .filter(|r| r.disposition == TransactCommandDisposition::Invalid)
                .count();
            let responded_count = per_node_results.len();
            let no_response_count = total_nodes.saturating_sub(responded_count);
            let diag_elapsed = Timestamp::now().duration_since(diag_start);
            veilid_log!(self debug "TransactCmd done: cmd={} key={}{} valid={} invalid={} no_response={} skipped={} total={} required={} elapsed={} attempts={} result={}",
                command,
                opaque_record_key,
                if let Some(subkey) = opt_subkey { format!(" #{}", subkey) } else { "".to_string() },
                valid_response_count,
                invalid_count,
                no_response_count,
                total_nodes.saturating_sub(responded_count),
                total_nodes,
                required_strict_consensus_count,
                diag_elapsed,
                attempt,
                if valid_response_count >= required_strict_consensus_count { "CONSENSUS" } else { "FAILED" },
            );
        }

        // Add Skipped entries for nodes that never responded across all attempts
        let responded_xids: HashSet<_> = per_node_results
            .iter()
            .map(|pnr| pnr.node_transaction_id.clone())
            .collect();
        if responded_xids.len() < total_nodes {
            let skipped: Vec<_> = params
                .nodes
                .iter()
                .filter(|(nxid, _)| !responded_xids.contains(nxid))
                .map(
                    |(node_transaction_id, _)| OutboundTransactCommandPerNodeResult {
                        node_transaction_id: node_transaction_id.clone(),
                        disposition: TransactCommandDisposition::Skipped,
                        opt_seqs: None,
                        opt_subkey: None,
                        opt_value: None,
                        opt_expiration: None,
                    },
                )
                .collect();
            per_node_results.extend(skipped);
        }

        // Sort per node results by distance from record to assist with strict consensus checking
        per_node_results.sort_by(|a, b| {
            let dist_a = opaque_record_key
                .to_hash_coordinate()
                .distance(&a.node_transaction_id.node_id().to_hash_coordinate());
            let dist_b = opaque_record_key
                .to_hash_coordinate()
                .distance(&b.node_transaction_id.node_id().to_hash_coordinate());

            dist_a.cmp(&dist_b)
        });

        Ok(OutboundTransactCommandResult {
            params,
            per_node_results,
        })
    }

    ////////////////////////////////////////////////////////////////////////

    /// Handle a received 'TransactCommand' query
    #[cfg_attr(feature = "instrument", instrument(level = "debug", target = "dht", ret(Display), err, fields(duration, __VEILID_LOG_KEY = self.log_key(), opt_value.len = opt_value.as_ref().map(|x| x.value_data().data_size())), skip(self, opt_value, _opt_seqs)))]
    pub async fn inbound_transact_command(
        &self,
        opaque_record_key: &OpaqueRecordKey,
        transaction_id: u64,
        command: TransactCommand,
        _opt_seqs: Option<Vec<ValueSeqNum>>,
        opt_subkey: Option<ValueSubkey>,
        opt_value: Option<Arc<SignedValueData>>,
    ) -> VeilidAPIResult<NetworkResult<InboundTransactCommandResult>> {
        record_duration_fut(async {
            let remote_record_store = self.get_remote_record_store()?;

            let transaction_id =
                match remote_record_store.lookup_inbound_transaction_id(transaction_id)? {
                    Some(id) => id,
                    None => {
                        return Ok(NetworkResult::value(
                            InboundTransactCommandResult::InvalidTransaction,
                        ));
                    }
                };

            let res = match command {
                TransactCommand::End => {
                    remote_record_store
                        .end_inbound_transaction(opaque_record_key, transaction_id)
                        .await?
                }
                TransactCommand::Commit => {
                    remote_record_store
                        .commit_inbound_transaction(opaque_record_key, transaction_id, || {
                            RemoteRecordDetail {}
                        })
                        .await?
                }
                TransactCommand::Rollback => {
                    remote_record_store
                        .rollback_inbound_transaction(opaque_record_key, transaction_id)
                        .await?
                }
                TransactCommand::Get => {
                    remote_record_store
                        .inbound_transaction_get(opaque_record_key, transaction_id, opt_subkey)
                        .await?
                }
                TransactCommand::Set => {
                    let Some(subkey) = opt_subkey else {
                        return Ok(NetworkResult::invalid_message("missing subkey"));
                    };
                    let Some(value) = opt_value else {
                        return Ok(NetworkResult::invalid_message("missing value"));
                    };
                    remote_record_store
                        .inbound_transaction_set(opaque_record_key, transaction_id, subkey, value)
                        .await?
                }
            };

            Ok(NetworkResult::value(res))
        })
        .await
    }
}
