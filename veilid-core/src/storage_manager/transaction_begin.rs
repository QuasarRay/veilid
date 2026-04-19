use std::sync::Arc;

use super::*;

impl_veilid_log_facility!("stor");

/// The context of the outbound_transact_begin operation
struct OutboundTransactBeginContext {
    /// The descriptor we have
    pub opt_descriptor: Option<Arc<SignedValueDescriptor>>,
    /// The best sequence numbers so far
    pub seqs: Vec<ValueSeqNum>,
    /// The routes that were locked by this transaction
    pub locked_routes: LockedRoutes,
}

/// parameters required to begin a transaction
#[derive(Debug, Clone)]
pub(super) struct OutboundTransactBeginParams {
    /// The transaction handle
    pub transaction_handle: OutboundTransactionHandle,
    /// The record key being transacted
    pub opaque_record_key: OpaqueRecordKey,
    /// The safety selection used for the transaction
    pub safety_selection: SafetySelection,
    /// The signer used to sign the transaction
    pub signing_keypair: KeyPair,
}

/// The result of the outbound_transact_begin operation
#[derive(Debug)]
pub(super) struct OutboundTransactBeginResult {
    /// The parameters used for this begin
    pub params: OutboundTransactBeginParams,
    /// Fanout result
    pub fanout_result: FanoutResult,
    /// The combined list of newest sequence numbers from the transaction nodes
    pub seqs: Vec<ValueSeqNum>,
    /// The descriptor for the record
    pub descriptor: Arc<SignedValueDescriptor>,
    /// The routes that were locked by this transaction
    pub locked_routes: LockedRoutes,
}

/// The result of the inbound_transact_begin operation
#[derive(Clone, Debug)]
pub(crate) enum InboundTransactBeginResult {
    /// Value transacted successfully
    Success(TransactBeginSuccess),
    /// Transaction unavailable due to limits
    TransactionUnavailable,
    /// Descriptor required but not provided,
    NeedDescriptor,
}

/// The result of a single successful transaction begin
#[derive(Debug, Clone)]
pub(crate) struct TransactBeginSuccess {
    /// Transaction id
    pub transaction_id: InboundTransactionId,
    /// Expiration timestamp
    pub expiration: Timestamp,
    /// Descriptor
    pub opt_descriptor: Option<Arc<SignedValueDescriptor>>,
    /// Sequence numbers for record
    pub seqs: Vec<ValueSeqNum>,
}

impl StorageManager {
    ////////////////////////////////////////////////////////////////////////

    /// Perform a transact begin query on the network for a single record
    /// This routine uses fanout and stores the fanout result and individual transaction ids in xxxx
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "dht", skip_all, err)
    )]
    pub(super) async fn outbound_transact_begin(
        &self,
        params: OutboundTransactBeginParams,
    ) -> VeilidAPIResult<OutboundTransactBeginResult> {
        let transaction_handle = params.transaction_handle.clone();
        let opaque_record_key = params.opaque_record_key.clone();
        let safety_selection = params.safety_selection.clone();
        let signing_keypair = params.signing_keypair.clone();
        let routing_domain = RoutingDomain::PublicInternet;

        // Get the DHT parameters for 'TransactBegin'
        let config = self.config();
        let (node_count, consensus_count, consensus_width, fanout_tasks) = (
            config.network.dht.max_find_node_count as usize,
            config.network.dht.set_value_count as usize,
            config.network.dht.consensus_width as usize,
            config.network.dht.set_value_fanout as usize,
        );

        let timeout = self
            .rpc_processor()
            .get_safety_selection_timeout(&safety_selection);

        // Get the nodes we know are caching this value to seed the fanout
        let init_fanout_queue = self
            .get_value_nodes(&opaque_record_key)?
            .unwrap_or_default()
            .into_iter()
            .filter(|x| {
                x.node_info(routing_domain)
                    .map(|ni| ni.has_all_capabilities(&[VEILID_CAPABILITY_DHT]))
                    .unwrap_or_default()
            })
            .collect();

        // Get the descriptor for this record if we have it
        let opt_descriptor = {
            let local_record_store = self.get_local_record_store()?;
            local_record_store.with_record(&opaque_record_key, |record| record.descriptor())?
        };

        // Make operation context, seeded with prior state
        let context = Arc::new(Mutex::new(OutboundTransactBeginContext {
            opt_descriptor,
            seqs: vec![],
            locked_routes: LockedRoutes::new(self.registry()),
        }));

        let descriptor_cache = self.descriptor_cache.clone();

        // Routine to call to generate fanout
        let call_routine = {
            let context = context.clone();
            let registry = self.registry();
            let transaction_handle = transaction_handle.clone();
            let opaque_record_key = opaque_record_key.clone();
            let safety_selection = safety_selection.clone();
            let descriptor_cache = descriptor_cache.clone();
            let signing_keypair = signing_keypair.clone();
            Arc::new(
                move |next_node: NodeRef| -> PinBoxFutureStatic<FanoutCallResult> {
                    let context = context.clone();
                    let registry = registry.clone();
                    let transaction_handle = transaction_handle.clone();
                    let opaque_record_key = opaque_record_key.clone();
                    let safety_selection = safety_selection.clone();
                    let descriptor_cache = descriptor_cache.clone();
                    let signing_keypair = signing_keypair.clone();
                    Box::pin(async move {

                        let rpc_processor = registry.rpc_processor();
                        let storage_manager = registry.storage_manager();

                        // check the cache to see if we should send the descriptor
                        let node_id = next_node.node_ids().get(opaque_record_key.kind()).unwrap_or_log();
                        let dc_key = DescriptorCacheKey{ opaque_record_key: opaque_record_key.clone(), node_id };
                        let mut descriptor_mode = DescriptorMode::new(descriptor_cache.lock().get(&dc_key).is_none(), context.lock().opt_descriptor.clone());

                        let dest = Destination::direct(next_node.routing_domain_filtered(routing_domain), Some(safety_selection.clone()));

                        // send across the wire, with a retry if the remote needed the descriptor
                        let tva = loop {
                            // send across the wire
                            let tva = match
                                rpc_processor
                                    .rpc_call_transact_begin(
                                        dest.clone(),
                                        opaque_record_key.clone(),
                                        descriptor_mode.clone(),
                                        signing_keypair.clone(),
                                    )
                                    .await? {
                                    NetworkResult::Timeout => {
                                        return Ok(FanoutCallOutput{peer_info_list: vec![], disposition: FanoutCallDisposition::Timeout});
                                    }
                                    NetworkResult::ServiceUnavailable(_) |
                                    NetworkResult::NoConnection(_)  |
                                    NetworkResult::AlreadyExists(_) |
                                    NetworkResult::InvalidMessage(_) => {
                                        return Ok(FanoutCallOutput{peer_info_list: vec![], disposition: FanoutCallDisposition::Invalid});
                                    }
                                    NetworkResult::Value(v) => v
                                };
                            // Do a retry if we needed to send the descriptor
                            // (if the cache was wrong)
                            if tva.answer.accepted && tva.answer.descriptor_mode.is_want() {
                                match descriptor_mode {
                                    DescriptorMode::Want => {
                                        // If both sides want the descriptor but do not have it then the record does not exist
                                    }
                                    DescriptorMode::Have(signed_value_descriptor) => {
                                        // If the server wants the descriptor and we have it, then send it
                                        descriptor_mode = DescriptorMode::Send(signed_value_descriptor);

                                        veilid_log!(registry debug target:"network_result", "Retrying to send descriptor");
                                        // Save locked routes in the context
                                        {
                                            let mut ctx = context.lock();
                                            if let Some(mut locked_routes) = tva.answer_context.waitable_reply_context.opt_locked_routes {
                                                ctx.locked_routes.take_from(&mut locked_routes);
                                            }
                                        }
                                        continue;
                                    }
                                    DescriptorMode::Send(_) => {
                                        // If the server wants the descriptor and we already sent it, then something is wrong
                                        veilid_log!(registry error target:"network_result", "Got 'need_descriptor' when descriptor was already sent: node={} record_key={}", next_node, opaque_record_key);
                                    }
                                }
                            }

                            break tva;
                        };

                        // Save locked routes in the context
                        {
                            let mut ctx = context.lock();
                            if let Some(mut locked_routes) = tva.answer_context.waitable_reply_context.opt_locked_routes {
                                ctx.locked_routes.take_from(&mut locked_routes);
                            }
                        }


                        let answer = tva.answer;

                        // Check if we got an accepted result
                        if !answer.accepted {
                            // Return peers if we have some
                            veilid_log!(registry debug target:"network_result", "TransactBegin missed, fanout call returned peers {}", answer.peers.len());
                            return Ok(FanoutCallOutput{peer_info_list:answer.peers, disposition: FanoutCallDisposition::Rejected});
                        }

                        // Get the transaction id
                        let Some(xid) = answer.transaction_id else {
                            veilid_log!(registry debug target:"network_result", "TransactBegin accepted but returned no transaction id, try again later");
                            return Ok(FanoutCallOutput{peer_info_list:answer.peers, disposition: FanoutCallDisposition::Rejected});
                        };

                        // If the node was close enough to accept the value and we got a transaction id
                        let descriptor = {
                            let mut ctx = context.lock();

                            // Get the descriptor and cache if we sent the descriptor or if we received one
                            let Some(descriptor) = ctx.opt_descriptor.clone().or(answer.descriptor_mode.opt_arc_descriptor()) else {
                                // Record does not exist
                                veilid_log!(registry debug target:"network_result", "TransactBegin record did not exist, fanout call returned peers {}", answer.peers.len());
                                return Ok(FanoutCallOutput{peer_info_list:answer.peers, disposition: FanoutCallDisposition::Rejected});
                            };
                            if descriptor_mode.is_send() || answer.descriptor_mode.is_send() || answer.descriptor_mode.is_have() {
                                descriptor_cache.lock().insert(dc_key,());
                            }

                            let schema = match descriptor.schema() {
                                Ok(s) => s,
                                Err(_) => {
                                    veilid_log!(registry debug target:"network_result", "TransactBegin received invalid schema");
                                    return Ok(FanoutCallOutput{peer_info_list:vec![], disposition: FanoutCallDisposition::Invalid});
                                }
                            };
                            let subkey_count = schema.subkey_count();

                            // Get the sequence number state at the point of the transaction
                            if answer.seqs.len() != subkey_count {
                                veilid_log!(registry debug target:"network_result", "wrong number of seqs returned {} (wanted {})",
                                    answer.seqs.len(),
                                    subkey_count);
                                return Ok(FanoutCallOutput{peer_info_list: answer.peers, disposition: FanoutCallDisposition::Invalid});
                            }

                            #[cfg(feature = "verbose-tracing")]
                            veilid_log!(registry debug "Begin fanout accepted: record={} node={} xid={} seqs={}", opaque_record_key, next_node, xid, answer.seqs.to_table_string());

                            // Update descriptor in context so we don't send/want it more than necessary
                            ctx.opt_descriptor = Some(descriptor.clone());

                            // If we have a prior seqs list, merge in the new seqs
                            if ctx.seqs.is_empty() {
                                ctx.seqs = answer.seqs.clone()
                            } else {
                                for pair in ctx.seqs.iter_mut().zip(answer.seqs.iter()) {
                                    let ctx_seq = pair.0;
                                    let answer_seq = *pair.1;

                                    ctx_seq.max_assign(answer_seq);
                                }
                            }

                            descriptor
                        };

                        // Add transaction id node to record state immediately
                        // rather than waiting for the fanout to complete, so we can start handling the keepalives right away
                        {
                            let mut inner = storage_manager.inner.lock();
                            let otm = &mut inner.outbound_transaction_manager;
                            let outbound_transaction_state = otm
                                .get_transaction_state_mut(&transaction_handle)
                                .map_err(|e| RPCError::internal(e.to_string()))?;
                            let Some(record_state) = outbound_transaction_state.get_record_state_mut(&opaque_record_key) else {
                                veilid_log!(registry debug target:"network_result", "missing record state recording begin result: {}", opaque_record_key);
                                return Err(RPCError::internal("record state not found"));
                            };
                            let nt = record_state
                                .new_node_transaction(NodeTransactionParams {
                                    kind: opaque_record_key.kind(),
                                    xid,
                                    node_ref: next_node.clone(),
                                    expiration: answer.expiration,
                                })
                                .map_err(|e| RPCError::internal(e.to_string()))?;

                            // Register with the keepalive processor for this node transaction
                            storage_manager.outbound_transaction_keepalive_processor.register(
                                transaction_handle, opaque_record_key, nt.node_xid().clone(), dest, answer.expiration, descriptor,
                            );
                        }

                        // Return peers if we have some
                        veilid_log!(registry debug target:"network_result", "TransactBegin fanout call returned peers {}", answer.peers.len());

                        // Transact doesn't actually use the fanout queue consensus tracker
                        Ok(FanoutCallOutput { peer_info_list: answer.peers, disposition: FanoutCallDisposition::Accepted})
                    }.instrument(tracing::trace_span!("outbound_begin_transact_value fanout call"))) as PinBoxFuture<FanoutCallResult>
                },
            )
        };

        // Routine to call to check if we're done at each step
        let check_done = {
            Arc::new(move |fanout_result: &FanoutResult| {
                match fanout_result.kind {
                    FanoutResultKind::Incomplete => {
                        // Keep going
                        FanoutDoneDisposition::NotDone
                    }
                    FanoutResultKind::Timeout | FanoutResultKind::Exhausted => {
                        // Signal we're done and stop anything still in progress
                        FanoutDoneDisposition::DoneEarly
                    }
                    FanoutResultKind::Consensus => {
                        // Signal we're done, but let the lanes in progress finish
                        // This allows us to collect up to consensus_width (10) nodes
                        // instead of stopping at strict_consensus_count (5), giving headroom
                        // for node failures during the Set/Commit phases
                        FanoutDoneDisposition::Done
                    }
                }
            })
        };

        // Call the fanout
        let routing_table = self.routing_table();
        let hash_coordinate = opaque_record_key.to_hash_coordinate();
        let fanout_call = FanoutCall::new(
            &routing_table,
            FanoutCallParams {
                name: format!("outbound_transact_begin({})", Timestamp::now_increasing()),
                hash_coordinate,
                node_count,
                fanout_tasks,
                consensus_count,
                consensus_width,
                timeout,
            },
            capability_fanout_peer_info_filter(vec![VEILID_CAPABILITY_DHT]),
            call_routine,
            check_done,
        );

        let shutdown_stop_source = self
            .startup_lock
            .stop_token()
            .ok_or_else(VeilidAPIError::not_initialized)?;

        let fanout_result = fanout_call
            .run(
                init_fanout_queue,
                FanoutQueueMode::ThrottleAtConsensus,
                shutdown_stop_source,
            )
            .await?;

        let mut ctx = context.lock();

        veilid_log!(self debug target: "network_result", "TransactBegin Fanout: {:#}", fanout_result);

        let descriptor = ctx.opt_descriptor.clone().unwrap_or_log();
        let seqs = if fanout_result.value_nodes.is_empty() {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug "Fanout for {} had no value_nodes, using default seqs (kind={:?})",
                opaque_record_key, fanout_result.kind);
            vec![ValueSeqNum::NONE; descriptor.schema().unwrap_or_log().subkey_count()]
        } else {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug "Fanout for {} completed: kind={:?}, value_nodes={}, ctx.seqs={}",
                opaque_record_key,
                fanout_result.kind,
                fanout_result.value_nodes.len(),
                ctx.seqs.to_table_string()
            );
            ctx.seqs.clone()
        };

        let result = OutboundTransactBeginResult {
            params,
            fanout_result,
            seqs,
            descriptor,
            locked_routes: ctx.locked_routes.take(),
        };

        Ok(result)
    }

    ////////////////////////////////////////////////////////////////////////

    /// Handle a received 'TransactBegin' query
    #[cfg_attr(feature = "instrument", instrument(level = "debug", target = "dht", ret(Display), err, fields(duration, __VEILID_LOG_KEY = self.log_key(), opt_descriptor = opt_descriptor.is_some()), skip(self, opt_descriptor)))]
    pub async fn inbound_transact_begin(
        &self,
        opaque_record_key: OpaqueRecordKey,
        opt_descriptor: Option<SignedValueDescriptor>,
        want_descriptor: bool,
        signing_member_id: MemberId,
    ) -> VeilidAPIResult<NetworkResult<InboundTransactBeginResult>> {
        record_duration_fut(async {
            // Can't provide descriptor and want descriptor
            if opt_descriptor.is_some() && want_descriptor {
                return VeilidAPIResult::Ok(NetworkResult::invalid_message(
                    "can't provide descriptor and want descriptor",
                ));
            }

            let remote_record_store = self.get_remote_record_store()?;

            remote_record_store
                .begin_inbound_transaction(
                    &opaque_record_key,
                    opt_descriptor,
                    want_descriptor,
                    signing_member_id,
                )
                .await
                .map(NetworkResult::value)
        })
        .await
    }
}
