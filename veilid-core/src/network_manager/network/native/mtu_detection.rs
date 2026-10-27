//! How large our packets can be in each address family, and what we advertise we take.
//! - A family starts at the safe size and waits for a probe before it settles
//! - Only an egress move or a change of the egress interface's mtu starts it over
//! - A probe is a full-size StatusQ asking for a full-size answer, sent beside a plain one to the
//!   same peer: the plain answer arriving alone says the big packets were lost

use super::*;
use futures_util::future::{select, Either};
use std::pin::pin;

/// Peers that can answer a probe, gathered per family each time one is due
const MTU_PROBE_CANDIDATES: usize = 8;
/// Peers probed per family in one pass; a black hole needs two losses and no full round trip
const MTU_PROBE_PEERS: usize = 4;
/// Peers an unsettled family remembers as tried, after which it forgets them all
const MTU_PROBE_TRIED_MAX: usize = 256;
/// Once the plain answer is in, the probe's answer gets this many of its round trips
const MTU_PROBE_RTT_FACTOR: u64 = 3;
/// The probe's answer gets at least this percent of the RPC timeout
const MTU_PROBE_GRACE_PERCENT: u32 = 33;

impl NativeNetwork {
    /// Starts over every in-use family whose egress moved or whose interface mtu changed
    pub(super) fn refresh_family_mtus(
        &self,
        interface_address_state: &NetworkInterfaceAddressState,
        family_global: AddressTypeSet,
        moved: AddressTypeSet,
    ) {
        let egress_mtus = family_global
            .iter()
            .map(|address_type| {
                let opt_egress = match address_type {
                    AddressType::IPV4 => interface_address_state.egress_v4.as_ref(),
                    AddressType::IPV6 => interface_address_state.egress_v6.as_ref(),
                };
                let interface_mtu = opt_egress.and_then(|egress| {
                    self.interfaces.with_interfaces(|interfaces| {
                        interfaces
                            .get(&egress.interface)
                            .and_then(|intf| intf.mtu())
                    })
                });
                (address_type, interface_mtu)
            })
            .collect::<Vec<_>>();

        let generation = self.interface_address_generation.load(Ordering::Relaxed);
        {
            let mut inner = self.inner.lock();
            inner
                .family_mtus
                .retain(|address_type, _| family_global.contains(*address_type));
            for (address_type, interface_mtu) in egress_mtus {
                let unchanged = !moved.contains(address_type)
                    && inner
                        .family_mtus
                        .get(&address_type)
                        .is_some_and(|family_mtu| family_mtu.interface_mtu == interface_mtu);
                if unchanged {
                    continue;
                }
                let family_mtu = FamilyMtu::new(interface_mtu, address_type, generation);
                veilid_log!(self debug "{} mtu starts over: interface mtu {:?}, {:?}", address_type, interface_mtu, family_mtu.state);
                inner.family_mtus.insert(address_type, family_mtu);
            }
        }

        self.apply_family_mtus();
    }

    /// Puts each family's sizes where the send path reads them, and where TCP listeners announce
    /// them
    fn apply_family_mtus(&self) {
        let family_mtus = self.inner.lock().family_mtus.clone();
        let network_manager = self.network_manager();
        let own_mtus = network_manager.own_mtus();
        for address_type in AddressTypeSet::all() {
            let safe = (SAFE_TRANSPORT_MTU, SAFE_TRANSPORT_MTU);
            let ((udp, tcp), (udp_limit, tcp_limit)) = family_mtus
                .get(&address_type)
                .map(|family_mtu| {
                    (
                        family_mtu.mtus(address_type),
                        family_mtu.limits(address_type),
                    )
                })
                .unwrap_or((safe, safe));
            own_mtus.set(
                LowLevelTransportType {
                    low_level_protocol_type: LowLevelProtocolType::UDP,
                    address_type,
                },
                udp,
                udp_limit,
            );
            own_mtus.set(
                LowLevelTransportType {
                    low_level_protocol_type: LowLevelProtocolType::TCP,
                    address_type,
                },
                tcp,
                tcp_limit,
            );
        }

        let inner = self.inner.lock();
        for (addr, listener_mss_handle) in &inner.listener_mss_handles {
            listener_mss_handle.set_mss(own_tcp_mss(&self.registry(), *addr));
        }
    }

    /// What our peer info says we take; None while any family is still detecting
    pub(super) fn receive_mtus(&self) -> Option<TransportMtus> {
        let inner = self.inner.lock();
        if inner
            .family_mtus
            .values()
            .any(|family_mtu| family_mtu.state == FamilyMtuState::Detecting)
        {
            return None;
        }
        let mut receive_mtus = TransportMtus::default();
        for (address_type, family_mtu) in &inner.family_mtus {
            let (udp, tcp) = family_mtu.mtus(*address_type);
            receive_mtus.set(
                LowLevelTransportType {
                    low_level_protocol_type: LowLevelProtocolType::UDP,
                    address_type: *address_type,
                },
                udp,
            );
            receive_mtus.set(
                LowLevelTransportType {
                    low_level_protocol_type: LowLevelProtocolType::TCP,
                    address_type: *address_type,
                },
                tcp,
            );
        }
        Some(receive_mtus)
    }

    /// Probes every family a probe can still settle, and puts what the probes show into effect
    pub(super) async fn mtu_detection_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        _cur_ts: Timestamp,
    ) -> EyreResult<()> {
        let pending = self
            .inner
            .lock()
            .family_mtus
            .iter()
            .filter(|(_, family_mtu)| {
                matches!(
                    family_mtu.state,
                    FamilyMtuState::Detecting | FamilyMtuState::Unprobed
                )
            })
            .map(|(address_type, family_mtu)| (*address_type, family_mtu.clone()))
            .collect::<Vec<_>>();

        let mut changed = false;
        for (address_type, family_mtu) in pending {
            let (full_udp, _) = family_mtu.limits(address_type);
            let candidates = self.mtu_probe_candidates(address_type, full_udp, &family_mtu.tried);

            let mut outcomes = Vec::new();
            let mut tried = Vec::new();
            for (node, dial_info) in candidates.into_iter().take(MTU_PROBE_PEERS) {
                tried.push(node.best_node_id());
                let outcome = Box::pin(self.mtu_probe(node, dial_info, full_udp)).await;
                outcomes.push(outcome);
                // One full round trip settles the family; losses wait on every peer's word
                if outcome == MtuProbeOutcome::Full {
                    break;
                }
            }
            let mut verdict = probe_verdict(&outcomes);

            // A family still detecting settles at the safe size rather than hold up publication
            if verdict.is_none()
                && family_mtu.state == FamilyMtuState::Detecting
                && (!tried.is_empty() || self.public_internet_waits_on_mtus())
            {
                verdict = Some(FamilyMtuState::Unprobed);
            }

            changed |= self.settle_family_mtu(address_type, family_mtu.generation, tried, verdict);
        }

        if changed {
            self.commit_family_mtus();
        }
        Ok(())
    }

    /// Peers not yet tried that can answer a probe over UDP in a family, those already
    /// advertising our full size first
    fn mtu_probe_candidates(
        &self,
        address_type: AddressType,
        full_udp: u16,
        tried: &BTreeSet<NodeId>,
    ) -> Vec<(NodeRef, DialInfo)> {
        let routing_table = self.routing_table();
        let routing_domain = RoutingDomain::PublicInternet;
        let dial_info_filter = DialInfoFilter::all()
            .with_protocol_type(ProtocolType::UDP)
            .with_address_type(address_type);
        let advertises_mtus: RoutingTableEntryFilter =
            Box::new(|opt_snapshot: &Option<BucketEntrySnapshot>, _cur_ts| {
                opt_snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.public_internet.peer_info.as_ref())
                    .is_some_and(|peer_info| !peer_info.node_info().receive_mtus().is_empty())
            });
        let filters = VecDeque::from([
            routing_table.make_inbound_dial_info_entry_filter(routing_domain, dial_info_filter),
            advertises_mtus,
        ]);
        let nodes = routing_table.find_fast_non_local_nodes_filtered(
            routing_domain,
            MTU_PROBE_CANDIDATES,
            filters,
        );

        let udp = LowLevelTransportType {
            low_level_protocol_type: LowLevelProtocolType::UDP,
            address_type,
        };
        let mut candidates = nodes
            .into_iter()
            .filter(|node| !tried.contains(&node.best_node_id()))
            .filter_map(|node| {
                let node_info = node.node_info(routing_domain)?;
                let dial_info = node_info
                    .dial_info_detail_list()
                    .iter()
                    .find(|did| {
                        !did.class.requires_signal()
                            && did.dial_info.matches_filter(&dial_info_filter)
                    })?
                    .dial_info
                    .clone();
                let at_full = node_info
                    .receive_mtus()
                    .get(udp)
                    .is_some_and(|mtu| mtu >= full_udp);
                Some((at_full, node, dial_info))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(at_full, _, _)| !*at_full);
        candidates
            .into_iter()
            .map(|(_, node, dial_info)| (node, dial_info))
            .collect()
    }

    /// Sends one peer a full-size probe and a plain StatusQ together over a UDP dial info
    async fn mtu_probe(&self, node: NodeRef, dial_info: DialInfo, size: u16) -> MtuProbeOutcome {
        let rpc_processor = self.rpc_processor();
        let destination = Destination::dial_info(dial_info, node);
        // Only the datagram the answer arrived in says what the path carried
        let filled = size.saturating_sub(MTU_PROBE_FILL_SLACK);
        let answered_full = |res: &Result<StatusResult, RPCError>| {
            matches!(res, Ok(StatusResult::Sent(answer))
                if answer.opt_mtu_probe_datagram_len.is_some_and(|len| len >= filled))
        };
        // The probe went out and nothing came back
        let probe_lost = |res: &Result<StatusResult, RPCError>| {
            matches!(res, Ok(StatusResult::Failed(sdr))
                if sdr.unique_flow().is_some())
        };

        let probe = pin!(rpc_processor.rpc_call_status(destination.clone(), Some(size)));
        let plain = pin!(rpc_processor.rpc_call_status(destination, None));
        match select(probe, plain).await {
            Either::Left((probe_res, plain)) => {
                if answered_full(&probe_res) {
                    return MtuProbeOutcome::Full;
                }
                let lost = probe_lost(&probe_res);
                match plain.await {
                    Ok(StatusResult::Sent(_)) if lost => MtuProbeOutcome::Lost,
                    _ => MtuProbeOutcome::Inconclusive,
                }
            }
            Either::Right((plain_res, probe)) => {
                let Ok(StatusResult::Sent(plain_answer)) = plain_res else {
                    return if answered_full(&probe.await) {
                        MtuProbeOutcome::Full
                    } else {
                        MtuProbeOutcome::Inconclusive
                    };
                };
                let rpc_timeout_ms = self.config().internal().network.rpc.timeout_ms;
                let floor_ms = u64::from(rpc_timeout_ms * MTU_PROBE_GRACE_PERCENT / 100);
                let rtt_ms = plain_answer.answer.answer_context.latency.as_u64() / 1000;
                let grace_ms = (rtt_ms * MTU_PROBE_RTT_FACTOR)
                    .max(floor_ms)
                    .min(u64::from(rpc_timeout_ms));
                match timeout(grace_ms as u32, probe).await {
                    Ok(probe_res) if answered_full(&probe_res) => MtuProbeOutcome::Full,
                    Ok(probe_res) if probe_lost(&probe_res) => MtuProbeOutcome::Lost,
                    // The plain answer is in and the probe's never came within its grace
                    Err(_) => MtuProbeOutcome::Lost,
                    Ok(_) => MtuProbeOutcome::Inconclusive,
                }
            }
        }
    }

    /// Whether PublicInternet publication waits on nothing but our mtus
    fn public_internet_waits_on_mtus(&self) -> bool {
        matches!(
            self.routing_table()
                .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>()
                .state()
                .inbound_stage,
            RoutingDomainInboundStage::NeedsTransportMtus
        )
    }

    /// Records the peers tried and any verdict, unless the family started over meanwhile
    fn settle_family_mtu(
        &self,
        address_type: AddressType,
        generation: u64,
        tried: Vec<NodeId>,
        opt_verdict: Option<FamilyMtuState>,
    ) -> bool {
        let mut inner = self.inner.lock();
        let Some(family_mtu) = inner.family_mtus.get_mut(&address_type) else {
            return false;
        };
        if family_mtu.generation != generation {
            return false;
        }
        family_mtu.tried.extend(tried);
        if family_mtu.tried.len() > MTU_PROBE_TRIED_MAX {
            family_mtu.tried.clear();
        }
        let Some(verdict) = opt_verdict else {
            return false;
        };
        if family_mtu.state == verdict {
            return false;
        }
        veilid_log!(self debug "{} mtu: {:?} -> {:?}", address_type, family_mtu.state, verdict);
        family_mtu.state = verdict;
        // A settled family probes no more, so the peers it tried no longer matter
        if verdict != FamilyMtuState::Unprobed {
            family_mtu.tried.clear();
        }
        true
    }

    /// Puts settled sizes into effect, then into both routing domains' peer info
    fn commit_family_mtus(&self) {
        self.apply_family_mtus();
        let receive_mtus = self.receive_mtus();
        let routing_table = self.routing_table();

        let public_internet = routing_table
            .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
        let mut editor = public_internet.edit();
        editor.set_receive_mtus(receive_mtus);
        editor.commit();
        public_internet.publish_peer_info();

        let local_network = routing_table
            .get_specific_routing_domain_controller::<LocalNetworkRoutingDomainController>();
        let mut editor = local_network.edit();
        editor.set_receive_mtus(receive_mtus);
        editor.commit();
        local_network.publish_peer_info();
    }
}
