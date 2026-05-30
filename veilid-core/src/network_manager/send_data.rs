use super::*;
use stop_token::future::FutureExt as _;

impl_veilid_log_facility!("net");

impl NetworkManager {
    /// Send raw data to a dial info
    ///
    /// Sending to a dialinfo does not require determining a NodeContactMethod
    /// Sending directly does not apply any dial info filtering as the direct
    /// dialinfo is already specified.
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn send_data_direct(
        &self,
        node_ref: NodeRef,
        dial_info: DialInfo,
        data: Bytes,
    ) -> EyreResult<SendDataResult> {
        let ncm = NodeContactMethod::Direct {
            target_di: dial_info.clone(),
        };
        let nr = pin_future_closure!(self.send_data_ncm_direct(node_ref, dial_info, data)).await?;
        Ok(SendDataResult::new(
            NodeContactMethodResult::Resolved(ncm),
            nr,
        ))
    }

    /// Send raw data to a node
    ///
    /// Sending to a node requires determining a NodeContactMethod.
    /// NodeContactMethod is how to reach a node given the context of our current node, which may
    /// include information about the existing connections and network state of our node.
    /// NodeContactMethod calculation requires first calculating the per-RoutingDomain ContactMethod
    /// between the source and destination PeerInfo, which is a stateless operation.
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn send_data(
        &self,
        node_ref: FilteredNodeRef,
        data: Bytes,
    ) -> EyreResult<SendDataResult> {
        let mut ncm_result = self.get_node_contact_method(node_ref.clone())?;

        loop {
            // Boxed because calling rpc_call_signal() is recursive to send_data()
            let sdr = pin_future_closure!(self.try_node_contact_method(
                ncm_result,
                node_ref.clone(),
                data.clone(),
            ))
            .await?;

            let (ncm_back, nres) = sdr.destructure();

            match &nres {
                NetworkResult::Timeout => {
                    self.inner
                        .lock()
                        .node_contact_method_cache
                        .record_contact_method_failure(&ncm_back);

                    // Timeouts may retry with a different method
                    match ncm_back {
                        NodeContactMethodResult::Resolved(NodeContactMethod::SignalReverse {
                            relay_di,
                        })
                        | NodeContactMethodResult::Resolved(NodeContactMethod::SignalHolePunch {
                            relay_di,
                            ..
                        }) => {
                            ncm_result = NodeContactMethodResult::Resolved(
                                NodeContactMethod::InboundRelay { relay_di },
                            );
                            continue;
                        }
                        other => break Ok(SendDataResult::new(other, nres)),
                    }
                }
                NetworkResult::ServiceUnavailable(_)
                | NetworkResult::NoConnection(_)
                | NetworkResult::AlreadyExists(_)
                | NetworkResult::InvalidMessage(_) => {
                    self.inner
                        .lock()
                        .node_contact_method_cache
                        .record_contact_method_failure(&ncm_back);
                    break Ok(SendDataResult::new(ncm_back, nres));
                }
                NetworkResult::Value(_) => {
                    self.inner
                        .lock()
                        .node_contact_method_cache
                        .record_contact_method_success(&ncm_back);
                    break Ok(SendDataResult::new(ncm_back, nres));
                }
            }
        }
    }

    /// Send an inbound-relayed envelope to a node
    ///
    /// Inbound relaying to a node should only be done to nodes that
    /// are already available via an existing flow. Flows from valid relay destinations
    /// are 'protected' in the connection table, and for connectionless flows, they are
    /// pinged regularly to ensure they have a last_flow with maintained firewall state.
    ///
    /// We should never need to create new flows or connections to destinations of inbound relaying.
    ///
    /// Restricting relaying to established/existing flows minimizes the amount of work
    /// being done by the relay and puts the effort to maintain the flow on the node that
    /// benefits from the relay.
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn send_inbound_relay_data(
        &self,
        destination_node_ref: FilteredNodeRef,
        data: Bytes,
    ) -> EyreResult<()> {
        let _ = self
            .send_data_ncm_existing(destination_node_ref, data)
            .await?;
        Ok(())
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn try_node_contact_method(
        &self,
        ncm_result: NodeContactMethodResult,
        destination_node_ref: FilteredNodeRef,
        data: Bytes,
    ) -> EyreResult<SendDataResult> {
        #[cfg(feature = "verbose-tracing")]
        veilid_log!(self debug
            "ContactMethod: {} for {:?}",
            ncm_result, destination_node_ref
        );

        // Try the contact method
        let nres = match &ncm_result {
            // No contact method resolved: last-chance attempt over any existing inbound flow.
            // Punished is included — passive: we won't open new connections, but we can
            // still respond on a flow they already have to us.
            NodeContactMethodResult::NoRoutingDomain
            | NodeContactMethodResult::NoPeerInfo
            | NodeContactMethodResult::NoContactMethod
            | NodeContactMethodResult::Punished => {
                pin_future_closure!(self.send_data_unreachable(destination_node_ref, data)).await?
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::Existing) => {
                // The node must have an existing connection, for example connecting to your own
                // relay is something that must always have a flow already
                pin_future_closure!(self.send_data_ncm_existing(destination_node_ref, data)).await?
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::OutboundRelay { relay_nr }) => {
                // Sending to an outbound relay must already have an established flow to the
                // outbound relay. All relays have flows that are maintained by the relay
                // background task, so this should exist already.
                pin_future_closure!(self.send_data_ncm_existing(relay_nr.clone(), data)).await?
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::InboundRelay { relay_di }) => {
                pin_future_closure!(self.send_data_ncm_direct(
                    destination_node_ref.unfiltered(),
                    relay_di.clone(),
                    data
                ))
                .await?
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::Direct { target_di }) => {
                pin_future_closure!(self.send_data_ncm_direct(
                    destination_node_ref.unfiltered(),
                    target_di.clone(),
                    data
                ))
                .await?
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::SignalReverse { relay_di }) => {
                pin_future_closure!(self.send_data_ncm_signal_reverse(
                    relay_di.clone(),
                    destination_node_ref.clone(),
                    data.clone()
                ))
                .await?
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::SignalHolePunch {
                relay_di,
                hole_punch_di,
                reverse_hole_punch_di,
            }) => {
                pin_future_closure!(self.send_data_ncm_signal_hole_punch(
                    relay_di.clone(),
                    hole_punch_di.clone(),
                    reverse_hole_punch_di.clone(),
                    destination_node_ref.clone(),
                    data.clone()
                ))
                .await?
            }
        };

        Ok(SendDataResult::new(ncm_result, nres))
    }

    /// Send data to unreachable node
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn send_data_unreachable(
        &self,
        target_node_ref: FilteredNodeRef,
        data: Bytes,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        // First try to send data to the last connection we've seen this peer on
        let Some(flow) = target_node_ref.last_flow() else {
            return Ok(NetworkResult::no_connection_other(format!(
                "node was unreachable: {}",
                target_node_ref
            )));
        };

        let net = self.net();
        let unique_flow =
            match pin_future!(net.send_data_to_existing_flow(flow, data).measure_debug(
                TimestampDuration::new_secs(1),
                veilid_log_dbg!(
                    self,
                    "NetworkManager::send_data_unreachable send_data_to_existing_flow"
                )
            ))
            .await?
            {
                SendDataToExistingFlowResult::Sent(unique_flow) => unique_flow,
                SendDataToExistingFlowResult::NotSent(_) => {
                    return Ok(NetworkResult::no_connection_other(
                        "failed to send to existing flow",
                    ));
                }
            };

        // Update timestamp for this last connection since we just sent to it
        self.set_last_flow(target_node_ref.unfiltered(), flow, Timestamp::now());

        Ok(NetworkResult::value(unique_flow))
    }

    /// Send data using NodeContactMethod::Existing
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn send_data_ncm_existing(
        &self,
        target_node_ref: FilteredNodeRef,
        data: Bytes,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        // First try to send data to the last connection we've seen this peer on
        let Some(flow) = target_node_ref.last_flow() else {
            return Ok(NetworkResult::no_connection_other(format!(
                "should have found an existing connection: {}",
                target_node_ref
            )));
        };

        let net = self.net();
        let unique_flow =
            match pin_future!(net.send_data_to_existing_flow(flow, data).measure_debug(
                TimestampDuration::new_secs(1),
                veilid_log_dbg!(
                    self,
                    "NetworkManager::send_data_ncm_existing send_data_to_existing_flow"
                )
            ))
            .await?
            {
                SendDataToExistingFlowResult::Sent(unique_flow) => unique_flow,
                SendDataToExistingFlowResult::NotSent(_) => {
                    return Ok(NetworkResult::no_connection_other(
                        "failed to send to existing flow",
                    ));
                }
            };

        // Update timestamp for this last connection since we just sent to it
        self.set_last_flow(target_node_ref.unfiltered(), flow, Timestamp::now());

        Ok(NetworkResult::value(unique_flow))
    }

    /// Send data using NodeContactMethod::SignalReverse
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn send_data_ncm_signal_reverse(
        &self,
        relay_di: DialInfo,
        target_node_ref: FilteredNodeRef,
        data: Bytes,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        // Make a noderef that meets the sequencing requirements
        // But is not protocol-specific, or address-family-specific
        // as a signalled node gets to choose its own dial info for the reverse connection.
        let (_sorted, seq_dif) = target_node_ref
            .dial_info_filter()
            .apply_sequencing(target_node_ref.sequencing());
        let seq_target_node_ref = if seq_dif.is_ordered_only() {
            target_node_ref
                .unfiltered()
                .sequencing_filtered(Sequencing::EnsureOrdered)
        } else {
            target_node_ref
                .unfiltered()
                .sequencing_filtered(Sequencing::NoPreference)
        };

        let data = if let Some(flow) = seq_target_node_ref.last_flow() {
            let net = self.net();
            match pin_future!(net.send_data_to_existing_flow(flow, data).measure_debug(
                TimestampDuration::new_secs(1),
                veilid_log_dbg!(
                    self,
                    "NetworkManager::send_data_ncm_signal_reverse send_data_to_existing_flow"
                )
            ))
            .await?
            {
                SendDataToExistingFlowResult::Sent(unique_flow) => {
                    // Update timestamp for this last connection since we just sent to it
                    self.set_last_flow(target_node_ref.unfiltered(), flow, Timestamp::now());

                    return Ok(NetworkResult::value(unique_flow));
                }
                SendDataToExistingFlowResult::NotSent(data) => {
                    // Couldn't send data to existing connection
                    // so pass the data back out
                    data
                }
            }
        } else {
            // No last connection
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug
                "No last flow in reverse connect for {:?}",
                target_node_ref
            );

            data
        };

        let config = self.config();
        let excessive_reverse_connect_duration = TimestampDuration::new_ms(
            (config.network.connection_initial_timeout_ms * 2
                + config.network.reverse_connection_receipt_time_ms)
                .into(),
        );

        let unique_flow = network_result_try!(
            pin_future!(self
                .do_reverse_connect(relay_di.clone(), target_node_ref.unfiltered(), data)
                .measure_debug(
                    excessive_reverse_connect_duration,
                    veilid_log_dbg!(
                        self,
                        "NetworkManager::send_data_ncm_signal_reverse do_reverse_connect"
                    )
                ))
            .await?
        );
        Ok(NetworkResult::value(unique_flow))
    }

    /// Send data using NodeContactMethod::SignalHolePunch
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn send_data_ncm_signal_hole_punch(
        &self,
        relay_di: DialInfo,
        hole_punch_di: DialInfo,
        reverse_hole_punch_di: DialInfo,
        target_node_ref: FilteredNodeRef,
        data: Bytes,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        // Make a noderef that meets the sequencing requirements
        // But is not protocol-specific, or address-family-specific
        // as a signalled node gets to choose its own dial info for the holepunched connection.
        let (_sorted, seq_dif) = target_node_ref
            .dial_info_filter()
            .apply_sequencing(target_node_ref.sequencing());
        let seq_target_node_ref = if seq_dif.is_ordered_only() {
            target_node_ref
                .unfiltered()
                .sequencing_filtered(Sequencing::EnsureOrdered)
        } else {
            target_node_ref
                .unfiltered()
                .sequencing_filtered(Sequencing::NoPreference)
        };

        let data = if let Some(flow) = seq_target_node_ref.last_flow() {
            let net = self.net();
            match pin_future!(net.send_data_to_existing_flow(flow, data).measure_debug(
                TimestampDuration::new_secs(1),
                veilid_log_dbg!(
                    self,
                    "NetworkManager::send_data_ncm_signal_hole_punch send_data_to_existing_flow"
                )
            ))
            .await?
            {
                SendDataToExistingFlowResult::Sent(unique_flow) => {
                    // Update timestamp for this last connection since we just sent to it
                    self.set_last_flow(target_node_ref.unfiltered(), flow, Timestamp::now());

                    return Ok(NetworkResult::value(unique_flow));
                }
                SendDataToExistingFlowResult::NotSent(data) => {
                    // Couldn't send data to existing connection
                    // so pass the data back out
                    data
                }
            }
        } else {
            // No last connection
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug
                "No last flow in hole punch for {:?}",
                target_node_ref
            );

            data
        };

        let hole_punch_receipt_time = TimestampDuration::new_ms(
            (self.config().network.hole_punch_receipt_time_ms * 2).into(),
        );

        let unique_flow = network_result_try!(
            pin_future!(self
                .do_hole_punch(
                    relay_di,
                    hole_punch_di,
                    reverse_hole_punch_di,
                    target_node_ref.unfiltered(),
                    data
                )
                .measure_debug(
                    hole_punch_receipt_time,
                    veilid_log_dbg!(
                        self,
                        "NetworkManager::send_data_ncm_signal_hole_punch do_hole_punch"
                    )
                ))
            .await?
        );

        Ok(NetworkResult::value(unique_flow))
    }

    /// Send data using NodeContactMethod::Direct
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn send_data_ncm_direct(
        &self,
        node_ref: NodeRef,
        dial_info: DialInfo,
        data: Bytes,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        // Reuse only the existing flow whose remote address matches the target dial info
        let filtered_node_ref =
            node_ref.custom_filtered(NodeRefFilter::from(dial_info.make_filter()));

        let target_addr = dial_info.socket_address();
        let data = if let Some(flow) = filtered_node_ref.last_flow_to(target_addr) {
            #[cfg(feature = "verbose-tracing")]
            veilid_log!(self debug
                "ExistingConnection: {:?} for {:?}",
                flow, filtered_node_ref
            );

            let net = self.net();
            match pin_future!(net.send_data_to_existing_flow(flow, data).measure_debug(
                TimestampDuration::new_secs(1),
                veilid_log_dbg!(
                    self,
                    "NetworkManager::send_data_ncm_direct send_data_to_existing_flow"
                )
            ))
            .await?
            {
                SendDataToExistingFlowResult::Sent(unique_flow) => {
                    self.set_last_flow(node_ref, flow, Timestamp::now());
                    return Ok(NetworkResult::value(unique_flow));
                }
                SendDataToExistingFlowResult::NotSent(d) => {
                    node_ref.clear_last_flow(flow);
                    d
                }
            }
        } else {
            data
        };

        // No matching existing flow; create a new connection.
        let net = self.net();
        let unique_flow = network_result_try!(
            pin_future!(net.send_data_to_dial_info(dial_info.clone(), data)).await?
        );

        self.set_last_flow(node_ref, unique_flow.flow, Timestamp::now());

        Ok(NetworkResult::value(unique_flow))
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip(self), err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn get_node_contact_method(
        &self,
        target_node_ref: FilteredNodeRef,
    ) -> EyreResult<NodeContactMethodResult> {
        let routing_table = self.routing_table();

        // If a node is punished, then don't try to contact it
        if target_node_ref
            .node_ids()
            .iter()
            .any(|nid| self.address_filter().is_node_id_punished(nid.clone()))
        {
            veilid_log!(self trace "node id was punished {:?}", target_node_ref);
            return Ok(NodeContactMethodResult::Punished);
        }

        // Figure out the best routing domain to get the contact method over
        let routing_domain = match target_node_ref.best_routing_domain() {
            Some(rd) => rd,
            None => {
                veilid_log!(self trace "no routing domain for node {:?}", target_node_ref);
                return Ok(NodeContactMethodResult::NoRoutingDomain);
            }
        };

        // Peer A is our own node
        // Use whatever node info we've calculated so far
        let peer_a = routing_table.get_current_peer_info(routing_domain);
        let peer_a_published = routing_table.get_published_peer_info(routing_domain);

        let own_node_info_ts = peer_a.node_info().timestamp();
        let own_published_node_info_ts = peer_a_published.map(|p| p.node_info().timestamp());

        // Peer B is the target node, get the whole peer info now
        let Some(peer_b) = target_node_ref.get_peer_info(routing_domain) else {
            veilid_log!(self trace "no node info for node {:?}", target_node_ref);
            return Ok(NodeContactMethodResult::NoPeerInfo);
        };

        // Calculate the dial info failures list
        let address_filter = self.address_filter();
        let dial_info_failures = {
            let mut dial_info_failures_with_ts = Vec::<(DialInfo, Timestamp)>::new();
            for did in peer_b
                .node_info()
                .filtered_dial_info_details(DialInfoDetail::NO_SORT, &|_| true)
            {
                if let Some(ts) = address_filter.get_transport_failed_ts(&did.dial_info) {
                    dial_info_failures_with_ts.push((did.dial_info, ts));
                }
            }
            // Put in order of oldest to newest failure
            dial_info_failures_with_ts.sort_by_key(|a| a.1);

            // Return just the dialinfo
            dial_info_failures_with_ts
                .into_iter()
                .map(|x| x.0)
                .collect::<Vec<_>>()
        };

        // Get cache key
        let ncm_key = NodeContactMethodCacheKey {
            node_ids: target_node_ref.node_ids(),
            own_node_info_ts,
            own_published_node_info_ts,
            target_node_info_ts: peer_b.node_info().timestamp(),
            target_node_ref_filter: target_node_ref.filter(),
            target_node_ref_sequencing: target_node_ref.sequencing(),
            dial_info_failures,
        };
        if let Some(ncm_result) = self.inner.lock().node_contact_method_cache.get(&ncm_key) {
            return Ok(ncm_result);
        }

        // Determine if the published peer info is the same as our current peer info
        // This is important because published peer info can lag behind current peer info
        // and we don't want old published peer info to be considered 'published' for the purposes
        // of contact method calculation and caching.
        // This disables hole punching and reverse connections when the published peer info is stale, which
        // will revert back to inbound relay only for the duration of the stale period.
        let peer_a_published = own_published_node_info_ts == Some(own_node_info_ts);

        // Calculate the node contact method
        let routing_table = self.routing_table();
        let ncm_result = match Self::get_node_contact_method_inner(
            &routing_table,
            routing_domain,
            target_node_ref.clone(),
            peer_a.clone(),
            peer_a_published,
            peer_b.clone(),
            &ncm_key,
        )? {
            Some(ncm) => NodeContactMethodResult::Resolved(ncm),
            None => {
                veilid_log!(self trace "no contact method kind for: routing_domain={:?}, target_node_ref={:?}, peer_a={:?}, peer_b={:?}, ncm_key={:?}", routing_domain, target_node_ref, peer_a, peer_b, ncm_key);
                NodeContactMethodResult::NoContactMethod
            }
        };

        self.inner
            .lock()
            .node_contact_method_cache
            .insert(ncm_key.clone(), ncm_result.clone());

        Ok(ncm_result)
    }

    /// Figure out how to reach a node from our own node over the best routing domain and reference the nodes we want to access
    /// Uses NodeRefs to ensure nodes are referenced, this is not a part of 'RoutingTable' because RoutingTable is not
    /// allowed to use NodeRefs due to recursive locking
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = routing_table.log_key()))
    )]
    fn get_node_contact_method_inner(
        routing_table: &RoutingTable,
        routing_domain: RoutingDomain,
        target_node_ref: FilteredNodeRef,
        peer_a: Arc<PeerInfo>,
        peer_a_published: bool,
        peer_b: Arc<PeerInfo>,
        ncm_key: &NodeContactMethodCacheKey,
    ) -> EyreResult<Option<NodeContactMethod>> {
        // Dial info filter comes from the target node ref but must be filtered by this node's outbound capabilities
        let dial_info_filter = target_node_ref.dial_info_filter().filtered(
            DialInfoFilter::all()
                .with_address_type_set(peer_a.node_info().address_types())
                .with_protocol_type_set(peer_a.node_info().outbound_protocols()),
        );
        let sequencing = target_node_ref.sequencing();

        // Make sort that deprioritizes dial info that have recently failed
        let dial_info_preference_map = ncm_key
            .dial_info_failures
            .iter()
            .cloned()
            .enumerate()
            .map(|(a, b)|
                // Map dial info failures in order to a 1-based index,
                // so that a 0 index can be reserved for dialinfo that have never failed.
                (b, a + 1))
            .collect::<BTreeMap<_, _>>();
        let context_sort: Option<Box<DialInfoDetailSort>> = if ncm_key.dial_info_failures.is_empty()
        {
            None
        } else {
            Some(Box::new(move |a: &DialInfoDetail, b: &DialInfoDetail| {
                // Compare index in preference map, with zero as the most preferential
                // in the event the dial info has never failed (hence the a+1 above)
                let ats = dial_info_preference_map
                    .get(&a.dial_info)
                    .copied()
                    .unwrap_or_default();
                let bts = dial_info_preference_map
                    .get(&b.dial_info)
                    .copied()
                    .unwrap_or_default();
                ats.cmp(&bts)
            }))
        };

        // Get the best contact method with these parameters from the routing domain
        let cm = routing_table.get_contact_method(
            routing_domain,
            peer_a.clone(),
            peer_a_published,
            peer_b.clone(),
            dial_info_filter,
            sequencing,
            context_sort.as_deref(),
        );

        // Translate the raw contact method to a referenced contact method
        let ncm = match cm {
            ContactMethod::Unreachable => None,
            ContactMethod::Existing => Some(NodeContactMethod::Existing),
            ContactMethod::Direct(target_di) => Some(NodeContactMethod::Direct { target_di }),
            ContactMethod::SignalReverse(relay_di) => {
                Some(NodeContactMethod::SignalReverse { relay_di })
            }
            ContactMethod::SignalHolePunch(relay_di, hole_punch_di, reverse_hole_punch_di) => {
                Some(NodeContactMethod::SignalHolePunch {
                    relay_di,
                    hole_punch_di,
                    reverse_hole_punch_di,
                })
            }
            ContactMethod::InboundRelay(relay_di) => {
                Some(NodeContactMethod::InboundRelay { relay_di })
            }
            ContactMethod::OutboundRelay(outbound_relay_id) => {
                // Outbound relays must be in the routing table
                let mut relay_nr = routing_table
                    .lookup_node_id_with_filter(
                        outbound_relay_id.clone(),
                        routing_domain.into(),
                        dial_info_filter,
                    )?
                    .ok_or_else(|| {
                        eyre!(
                            "couldn't look up relay for outbound relay: {} with filter {:?}",
                            outbound_relay_id,
                            dial_info_filter
                        )
                    })?;
                relay_nr.set_sequencing(sequencing);
                Some(NodeContactMethod::OutboundRelay { relay_nr })
            }
        };

        Ok(ncm)
    }

    /// Send a reverse connection signal and wait for the return receipt over it
    /// Then send the data across the new connection
    /// Only usable for PublicInternet routing domain
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn do_reverse_connect(
        &self,
        relay_di: DialInfo,
        target_nr: NodeRef,
        data: Bytes,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        // Detect if network is stopping so we can break out of this
        let Some(stop_token) = self.startup_context.startup_lock.stop_token() else {
            return Ok(NetworkResult::service_unavailable("network is stopping"));
        };

        // Build a return receipt for the signal
        let receipt_timeout = TimestampDuration::new_ms(
            self.config().network.reverse_connection_receipt_time_ms as u64,
        );
        let (receipt, eventual_value) = self
            .generate_single_shot_receipt(receipt_timeout, Bytes::new())
            .await?;

        // Get relay routing domain
        let Some(routing_domain) = self
            .routing_table()
            .routing_domain_for_address(relay_di.address())
        else {
            return Ok(NetworkResult::no_connection_other(
                "No routing domain for relay for reverse connect",
            ));
        };

        // Get our published peer info
        let Some(published_peer_info) =
            self.routing_table().get_published_peer_info(routing_domain)
        else {
            return Ok(NetworkResult::no_connection_other(
                "Network class not yet valid for reverse connect",
            ));
        };

        // Issue the signal
        let rpc = self.rpc_processor();
        network_result_try!(pin_future!(rpc.rpc_call_signal(
            Destination::relay(relay_di.clone(), target_nr.clone()),
            SignalInfo::ReverseConnect {
                receipt,
                peer_info: published_peer_info
            },
        ))
        .await
        .wrap_err("failed to send signal")?);

        // Wait for the return receipt
        let inbound_nr = match eventual_value
            .timeout_at(stop_token)
            .in_current_span()
            .await
        {
            Err(_) => {
                return Ok(NetworkResult::service_unavailable("network is stopping"));
            }
            Ok(v) => {
                let receipt_event = v.take_value().unwrap_or_log();
                match receipt_event {
                    ReceiptEvent::ReturnedPrivate { private_route: _ }
                    | ReceiptEvent::ReturnedOutOfBand
                    | ReceiptEvent::ReturnedSafety => {
                        return Ok(NetworkResult::invalid_message(
                            "reverse connect receipt should be returned in-band",
                        ));
                    }
                    ReceiptEvent::ReturnedInBand { inbound_noderef } => inbound_noderef,
                    ReceiptEvent::Expired => {
                        return Ok(NetworkResult::timeout());
                    }
                    ReceiptEvent::Cancelled => {
                        return Ok(NetworkResult::no_connection_other(format!(
                            "reverse connect receipt cancelled from {}",
                            target_nr
                        )))
                    }
                }
            }
        };

        // We expect the inbound noderef to be the same as the target noderef
        // if they aren't the same, we should error on this and figure out what then hell is up
        if !target_nr.same_entry(&inbound_nr) {
            bail!("unexpected noderef mismatch on reverse connect");
        }

        // And now use the existing connection to send over
        if let Some(flow) = inbound_nr.last_flow() {
            let net = self.net();
            match pin_future!(net.send_data_to_existing_flow(flow, data)).await? {
                SendDataToExistingFlowResult::Sent(unique_flow) => {
                    Ok(NetworkResult::value(unique_flow))
                }
                SendDataToExistingFlowResult::NotSent(_) => Ok(NetworkResult::no_connection_other(
                    "unable to send over reverse connection",
                )),
            }
        } else {
            Ok(NetworkResult::no_connection_other(format!(
                "reverse connection dropped from {}",
                target_nr
            )))
        }
    }

    /// Send a hole punch signal and do a negotiating ping and wait for the return receipt
    /// Then send the data across the new connection
    /// Only usable for PublicInternet routing domain
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn do_hole_punch(
        &self,
        relay_di: DialInfo,
        hole_punch_di: DialInfo,
        reverse_hole_punch_di: DialInfo,
        target_nr: NodeRef,
        data: Bytes,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        // Detect if network is stopping so we can break out of this
        let Some(stop_token) = self.startup_context.startup_lock.stop_token() else {
            return Ok(NetworkResult::service_unavailable("network is stopping"));
        };

        // Build a return receipt for the signal
        let receipt_timeout =
            TimestampDuration::new_ms(self.config().network.hole_punch_receipt_time_ms as u64);
        let (receipt, eventual_value) = self
            .generate_single_shot_receipt(receipt_timeout, Bytes::new())
            .await?;

        // Get relay routing domain
        let Some(routing_domain) = self
            .routing_table()
            .routing_domain_for_address(relay_di.address())
        else {
            return Ok(NetworkResult::no_connection_other(
                "No routing domain for relay for hole punch",
            ));
        };

        // Get our published peer info
        let Some(published_peer_info) =
            self.routing_table().get_published_peer_info(routing_domain)
        else {
            return Ok(NetworkResult::no_connection_other(
                "Network class not yet valid for hole punch",
            ));
        };

        // Do our half of the hole punch by sending an empty packet
        // Both sides will do this and then the receipt will get sent over the punched hole
        // Don't bother storing the returned flow as the 'last flow' because the other side of the hole
        // punch should come through and create a real 'last connection' for us if this succeeds
        let net = self.net();
        network_result_try!(pin_future!(net.send_hole_punch(hole_punch_di.clone())).await?);

        // Add small delay to encourage packets to be delivered in order
        sleep(HOLE_PUNCH_DELAY_MS).await;

        // Issue the signal
        let rpc = self.rpc_processor();
        network_result_try!(pin_future!(rpc.rpc_call_signal(
            Destination::relay(relay_di, target_nr.clone()),
            SignalInfo::HolePunch {
                receipt,
                peer_info: published_peer_info,
                opt_dial_info: Some(reverse_hole_punch_di),
            },
        ))
        .await
        .wrap_err("failed to send signal")?);

        // Another hole punch after the signal for UDP redundancy
        let net = self.net();
        network_result_try!(pin_future!(net.send_hole_punch(hole_punch_di)).await?);

        // Wait for the return receipt
        let inbound_nr = match eventual_value
            .timeout_at(stop_token)
            .in_current_span()
            .await
        {
            Err(_) => {
                return Ok(NetworkResult::service_unavailable("network is stopping"));
            }
            Ok(v) => {
                let receipt_event = v.take_value().unwrap_or_log();
                match receipt_event {
                    ReceiptEvent::ReturnedPrivate { private_route: _ }
                    | ReceiptEvent::ReturnedOutOfBand
                    | ReceiptEvent::ReturnedSafety => {
                        return Ok(NetworkResult::invalid_message(
                            "hole punch receipt should be returned in-band",
                        ));
                    }
                    ReceiptEvent::ReturnedInBand { inbound_noderef } => inbound_noderef,
                    ReceiptEvent::Expired => {
                        return Ok(NetworkResult::timeout());
                    }
                    ReceiptEvent::Cancelled => {
                        return Ok(NetworkResult::no_connection_other(format!(
                            "hole punch receipt cancelled from {}",
                            target_nr
                        )))
                    }
                }
            }
        };

        // We expect the inbound noderef to be the same as the target noderef
        // if they aren't the same, we should error on this and figure out what then hell is up
        if !target_nr.same_entry(&inbound_nr) {
            bail!(
                "unexpected noderef mismatch on hole punch {}, expected {}",
                inbound_nr,
                target_nr
            );
        }

        // And now use the existing connection to send over
        if let Some(flow) = inbound_nr.last_flow() {
            match self.net().send_data_to_existing_flow(flow, data).await? {
                SendDataToExistingFlowResult::Sent(unique_flow) => {
                    Ok(NetworkResult::value(unique_flow))
                }
                SendDataToExistingFlowResult::NotSent(_) => Ok(NetworkResult::no_connection_other(
                    "unable to send over hole punch",
                )),
            }
        } else {
            Ok(NetworkResult::no_connection_other(format!(
                "hole punch dropped from {}",
                target_nr
            )))
        }
    }
}
