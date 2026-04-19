mod tasks;

use super::*;

impl_veilid_log_facility!("rtab");

pub struct LocalNetworkRoutingDomainControllerUnlockedInner {
    registry: VeilidComponentRegistry,
    detail: Box<RwLock<LocalNetworkRoutingDomainDetail>>,
    /// Published peer info for this routing domain
    published_peer_info: Mutex<Option<Arc<PeerInfo>>>,
    /// Background process to check LocalNetwork nodes to see if they are still alive and for reliability
    ping_validator_local_network_task: TickTask<EyreReport>,
}

impl fmt::Debug for LocalNetworkRoutingDomainControllerUnlockedInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalNetworkRoutingDomainControllerUnlockedInner")
            .field("detail", &self.detail)
            .field("published_peer_info", &self.published_peer_info)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct LocalNetworkRoutingDomainController {
    unlocked_inner: Arc<LocalNetworkRoutingDomainControllerUnlockedInner>,
}

impl core::ops::Deref for LocalNetworkRoutingDomainController {
    type Target = LocalNetworkRoutingDomainControllerUnlockedInner;

    fn deref(&self) -> &Self::Target {
        &self.unlocked_inner
    }
}

impl_veilid_component_accessors!(LocalNetworkRoutingDomainController);

impl SpecificRoutingDomainController for LocalNetworkRoutingDomainController {
    const ROUTING_DOMAIN: RoutingDomain = RoutingDomain::LocalNetwork;
    type Detail = LocalNetworkRoutingDomainDetail;
    type Editor<'a> = RoutingDomainEditorLocalNetwork<'a>;

    fn read(&self) -> RwLockReadGuard<'_, Self::Detail> {
        self.unlocked_inner.detail.read()
    }
    fn write(&self) -> RwLockWriteGuard<'_, Self::Detail> {
        self.unlocked_inner.detail.write()
    }
    fn edit(&self) -> Self::Editor<'_> {
        RoutingDomainEditorLocalNetwork::new(self)
    }
}

impl LocalNetworkRoutingDomainController {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        let detail = Box::new(RwLock::new(LocalNetworkRoutingDomainDetail::new(
            registry.clone(),
        )));
        let unlocked_inner = LocalNetworkRoutingDomainControllerUnlockedInner {
            registry,
            detail,
            published_peer_info: Default::default(),
            ping_validator_local_network_task: TickTask::new(
                "ping_validator_local_network_task",
                1,
            ),
        };
        let this = Self {
            unlocked_inner: Arc::new(unlocked_inner),
        };
        this.setup_tasks();
        this
    }
}

impl RoutingDomainController for LocalNetworkRoutingDomainController {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Read access to the routing domain detail
    fn read_dyn(&self) -> MappedRwLockReadGuard<'_, dyn RoutingDomainDetail> {
        RwLockReadGuard::map(self.unlocked_inner.detail.read(), |x| {
            x as &dyn RoutingDomainDetail
        })
    }

    /// Write access to the routing domain detail
    fn write_dyn(&self) -> MappedRwLockWriteGuard<'_, dyn RoutingDomainDetail> {
        RwLockWriteGuard::map(self.unlocked_inner.detail.write(), |x| {
            x as &mut dyn RoutingDomainDetail
        })
    }

    /// Editor access to common fields in the routing domain detail
    fn edit_dyn(&self) -> Box<dyn RoutingDomainEditor + '_> {
        Box::new(RoutingDomainEditorLocalNetwork::new(self))
    }

    fn routing_domain(&self) -> RoutingDomain {
        RoutingDomain::LocalNetwork
    }

    /// Start up the routing domain controller
    fn startup(&self) -> PinBoxFuture<'_, EyreResult<()>> {
        Box::pin(async move {
            // Publish peer info
            self.publish_peer_info();
            Ok(())
        })
    }

    /// Shut down the routing domain controller
    fn shutdown(&self) -> PinBoxFuture<'_, ()> {
        Box::pin(async move {
            // Unpublish peer info
            self.unpublish_peer_info();
        })
    }

    fn tick(&self) -> PinBoxFuture<'_, EyreResult<()>> {
        Box::pin(LocalNetworkRoutingDomainController::tick(self))
    }

    fn cancel_tasks(&self) -> PinBoxFuture<'_, ()> {
        Box::pin(LocalNetworkRoutingDomainController::cancel_tasks(self))
    }

    ///////////////////////////////////////////////////////////////////////////////////////

    fn state(&self) -> RoutingDomainState {
        let detail = self.read_dyn();
        let entry_summary = detail.get_entry_summary();
        let low_water_mark = detail.get_low_water_mark();

        // Determine inbound stage
        let (inbound_stage, relay_status, current_peer_info) = {
            let relay_status = detail.relay_status();
            let current_peer_info = detail.get_peer_info();

            let inbound_stage = if !detail.confirmed() {
                if detail.address_types().is_empty() || detail.outbound_protocols().is_empty() {
                    RoutingDomainInboundStage::Invalid
                } else {
                    RoutingDomainInboundStage::NeedsDialInfoConfirmation
                }
            } else if detail.address_types().is_empty() || detail.outbound_protocols().is_empty() {
                RoutingDomainInboundStage::Unusable
            } else if relay_status.needs_more_relays() && detail.relays().is_empty() {
                // If relays are wanted, they are all allocated at the same time, so we either have all the relays
                // we need, or we don't have any at all
                RoutingDomainInboundStage::NeedsRelays
            } else {
                RoutingDomainInboundStage::ReadyToPublish
            };

            (inbound_stage, relay_status, current_peer_info)
        };

        // Determine outbound stage
        let outbound_stage = {
            let outbound_state = if detail.address_types().is_empty()
                || detail.outbound_protocols().is_empty()
                || !self.network_manager().network_is_started()
            {
                RoutingDomainOutboundStage::Invalid
            } else {
                RoutingDomainOutboundStage::ReadyToOperate
            };

            // More to do here...
            outbound_state
        };

        let is_ready_inbound = matches!(inbound_stage, RoutingDomainInboundStage::ReadyToPublish);
        let is_ready_outbound =
            matches!(outbound_stage, RoutingDomainOutboundStage::ReadyToOperate);

        RoutingDomainState {
            inbound_stage,
            outbound_stage,
            relay_status,
            current_peer_info,
            entry_summary,
            low_water_mark,
            is_ready_inbound,
            is_ready_outbound,
        }
    }

    fn get_health(&self) -> RoutingDomainHealth {
        let state = self.state();

        let entry_summary = state.entry_summary;
        let low_water_mark = state.low_water_mark;

        let is_ready_inbound = matches!(
            state.inbound_stage,
            RoutingDomainInboundStage::ReadyToPublish
        );
        let is_ready_outbound = matches!(
            state.outbound_stage,
            RoutingDomainOutboundStage::ReadyToOperate
        );

        RoutingDomainHealth {
            entry_summary,
            low_water_mark,
            is_ready_inbound,
            is_ready_outbound,
        }
    }

    fn publish_peer_info(&self) -> bool {
        let (opt_old_peer_info, opt_new_peer_info) = {
            let state = self.state();

            let new_peer_info = if matches!(
                state.inbound_stage,
                RoutingDomainInboundStage::ReadyToPublish
            ) {
                state.current_peer_info
            } else {
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(self debug "[LocalNetwork] Not publishing peer info because it is not ready to publish");
                return false;
            };

            // Don't publish if the peer info hasnt changed from our previous publication
            let mut ppi_lock = self.published_peer_info.lock();
            let opt_old_peer_info = (*ppi_lock).clone();

            if let Some(old_peer_info) = &opt_old_peer_info {
                if new_peer_info.equivalent(old_peer_info) {
                    #[cfg(feature = "verbose-tracing")]
                    veilid_log!(self debug "[LocalNetwork] Not publishing peer info because it is equivalent");
                    return false;
                }
            }

            veilid_log!(self debug "[LocalNetwork] Published new peer info: {}", new_peer_info);
            *ppi_lock = Some(new_peer_info.clone());

            (opt_old_peer_info, Some(new_peer_info))
        };

        if let Err(e) = self.event_bus().post(PeerInfoChangeEvent {
            routing_domain: RoutingDomain::LocalNetwork,
            opt_old_peer_info,
            opt_new_peer_info,
        }) {
            veilid_log!(self debug "Failed to post event: {}", e);
        }

        true
    }

    fn unpublish_peer_info(&self) {
        let mut ppi_lock = self.published_peer_info.lock();
        let opt_old_peer_info = ppi_lock.clone();
        if opt_old_peer_info.is_none() {
            return;
        }
        veilid_log!(self debug "[LocalNetwork] Unpublished peer info");
        *ppi_lock = None;
        if let Err(e) = self.event_bus().post(PeerInfoChangeEvent {
            routing_domain: RoutingDomain::LocalNetwork,
            opt_old_peer_info,
            opt_new_peer_info: None,
        }) {
            veilid_log!(self debug "Failed to post event: {}", e);
        }
    }

    fn get_published_peer_info(&self) -> Option<Arc<PeerInfo>> {
        self.published_peer_info.lock().clone()
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "rtab", skip(self, context_sort), fields(__VEILID_LOG_KEY = self.log_key()), ret))]
    fn get_contact_method(
        &self,
        peer_a: Arc<PeerInfo>,
        _peer_a_published: bool,
        peer_b: Arc<PeerInfo>,
        dial_info_filter: DialInfoFilter,
        sequencing: Sequencing,
        context_sort: Option<&DialInfoDetailSort>,
    ) -> ContactMethod {
        // Get the nodeinfos for convenience
        let node_a = peer_a.node_info();
        let node_b = peer_b.node_info();

        // Get the node ids that would be used between these peers
        let cck = common_crypto_kinds(&peer_a.node_ids().kinds(), &peer_b.node_ids().kinds());
        let Some(_best_ck) = cck.first().copied() else {
            // No common crypto kinds between these nodes, can't contact
            return ContactMethod::Unreachable;
        };

        if let Some(target_did) = self.best_dial_info_detail_between_nodes(
            node_a,
            node_b,
            dial_info_filter,
            sequencing,
            context_sort,
        ) {
            match target_did.class {
                DialInfoClass::Direct => return ContactMethod::Direct(target_did.dial_info),
                DialInfoClass::Mapped
                | DialInfoClass::FullConeNAT
                | DialInfoClass::Blocked
                | DialInfoClass::AddressRestrictedNAT
                | DialInfoClass::PortRestrictedNAT => {
                    veilid_log!(self warn "LocalNetwork dial info found with non-direct class: {}:\n{:#?}", target_did, peer_b);
                    return ContactMethod::Unreachable;
                }
            }
        }

        ContactMethod::Unreachable
    }
}
