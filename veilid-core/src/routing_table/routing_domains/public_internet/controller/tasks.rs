use super::*;

impl_veilid_log_facility!("rtab");

impl PublicInternetRoutingDomainController {
    pub fn setup_tasks(&self) {
        // Set up bootstrap task
        impl_setup_task_async_clone!(self, bootstrap_task, bootstrap_task_routine);

        // Set up peer minimum refresh task
        impl_setup_task_async_clone!(
            self,
            peer_minimum_refresh_task,
            peer_minimum_refresh_task_routine
        );

        // Set up 'closest peers refresh' task
        impl_setup_task_async_clone!(
            self,
            closest_peers_refresh_task,
            closest_peers_refresh_task_routine
        );

        // Set ping validator tick task
        impl_setup_task_async_clone!(
            self,
            ping_validator_public_internet_task,
            ping_validator_public_internet_task_routine
        );

        // Set relay management tick task
        impl_setup_task_async_clone!(self, relay_management_task, relay_management_task_routine);

        // Set private route management tick task
        impl_setup_task_async_clone!(
            self,
            private_route_management_task,
            private_route_management_task_routine
        );
    }

    fn check_bootstrap(state: &RoutingDomainState) -> bool {
        match state.outbound_stage {
            RoutingDomainOutboundStage::Invalid => false,
            RoutingDomainOutboundStage::NeedsBootstrap => true,
            RoutingDomainOutboundStage::NeedsPublishedPeerInfo
            | RoutingDomainOutboundStage::NeedsMoreTestedNodes
            | RoutingDomainOutboundStage::NeedsSafetyRoutes
            | RoutingDomainOutboundStage::ReadyToOperate => false,
        }
    }

    // Peer minimum refresh may need to happen before we have published peer info
    // and it may need to happen for some crypto kinds and not others
    fn check_peer_minimum_refresh(state: &RoutingDomainState, nodes_needed: &NodesNeeded) -> bool {
        match state.outbound_stage {
            RoutingDomainOutboundStage::Invalid | RoutingDomainOutboundStage::NeedsBootstrap => {
                false
            }
            RoutingDomainOutboundStage::NeedsPublishedPeerInfo
            | RoutingDomainOutboundStage::NeedsMoreTestedNodes
            | RoutingDomainOutboundStage::NeedsSafetyRoutes
            | RoutingDomainOutboundStage::ReadyToOperate => {
                !nodes_needed.needs_peer_minimum_refresh.is_empty()
            }
        }
    }

    // Finding closer peers is best done after we have published peer info
    // so that when we find them, they will also put us in their routing table
    fn check_closest_peers_refresh(state: &RoutingDomainState) -> bool {
        match state.outbound_stage {
            RoutingDomainOutboundStage::Invalid
            | RoutingDomainOutboundStage::NeedsBootstrap
            | RoutingDomainOutboundStage::NeedsPublishedPeerInfo => false,
            RoutingDomainOutboundStage::NeedsMoreTestedNodes
            | RoutingDomainOutboundStage::NeedsSafetyRoutes
            | RoutingDomainOutboundStage::ReadyToOperate => true,
        }
    }

    fn check_ping_validator_public_internet(state: &RoutingDomainState) -> bool {
        match state.outbound_stage {
            RoutingDomainOutboundStage::Invalid => false,
            RoutingDomainOutboundStage::NeedsBootstrap => false,
            RoutingDomainOutboundStage::NeedsPublishedPeerInfo
            | RoutingDomainOutboundStage::NeedsMoreTestedNodes
            | RoutingDomainOutboundStage::NeedsSafetyRoutes
            | RoutingDomainOutboundStage::ReadyToOperate => true,
        }
    }

    fn check_relay_management(state: &RoutingDomainState) -> bool {
        match state.inbound_stage {
            RoutingDomainInboundStage::Invalid
            | RoutingDomainInboundStage::NeedsDialInfoConfirmation
            | RoutingDomainInboundStage::Unusable => false,
            RoutingDomainInboundStage::NeedsRelays | RoutingDomainInboundStage::ReadyToPublish => {
                state.relay_status.needs_more_relays()
            }
        }
    }

    fn check_private_route_management(state: &RoutingDomainState) -> bool {
        match state.outbound_stage {
            RoutingDomainOutboundStage::Invalid
            | RoutingDomainOutboundStage::NeedsBootstrap
            | RoutingDomainOutboundStage::NeedsPublishedPeerInfo
            | RoutingDomainOutboundStage::NeedsMoreTestedNodes => false,
            RoutingDomainOutboundStage::NeedsSafetyRoutes
            | RoutingDomainOutboundStage::ReadyToOperate => true,
        }
    }

    pub async fn tick(&self) -> EyreResult<()> {
        let state = self.state();
        let nodes_needed = self.nodes_needed();

        if Self::check_bootstrap(&state) {
            self.bootstrap_task.tick().await?;
        }
        if Self::check_peer_minimum_refresh(&state, &nodes_needed) {
            self.peer_minimum_refresh_task.tick().await?;
        }
        if Self::check_closest_peers_refresh(&state) {
            self.closest_peers_refresh_task.tick().await?;
        }
        if Self::check_ping_validator_public_internet(&state) {
            self.ping_validator_public_internet_task.tick().await?;
        }
        if Self::check_relay_management(&state) {
            self.relay_management_task.tick().await?;
        }
        if Self::check_private_route_management(&state) {
            self.private_route_management_task.tick().await?;
        }

        Ok(())
    }

    pub async fn cancel_tasks(&self) {
        veilid_log!(self debug "stopping PublicInternet bootstrap task");
        if let Err(e) = self.bootstrap_task.stop().await {
            veilid_log!(self warn "bootstrap_task not stopped: {}", e);
        }

        veilid_log!(self debug "stopping PublicInternet peer minimum refresh task");
        if let Err(e) = self.peer_minimum_refresh_task.stop().await {
            veilid_log!(self warn "peer_minimum_refresh_task not stopped: {}", e);
        }

        veilid_log!(self debug "stopping PublicInternet closest peers refresh task");
        if let Err(e) = self.closest_peers_refresh_task.stop().await {
            veilid_log!(self warn "closest_peers_refresh_task not stopped: {}", e);
        }

        veilid_log!(self debug "stopping PublicInternet ping_validator tasks");
        if let Err(e) = self.ping_validator_public_internet_task.stop().await {
            veilid_log!(self warn "ping_validator_public_internet_task not stopped: {}", e);
        }

        veilid_log!(self debug "stopping PublicInternet relay management task");
        if let Err(e) = self.relay_management_task.stop().await {
            veilid_log!(self warn "relay_management_task not stopped: {}", e);
        }
        veilid_log!(self debug "stopping PublicInternet private route management task");
        if let Err(e) = self.private_route_management_task.stop().await {
            veilid_log!(self warn "private_route_management_task not stopped: {}", e);
        }
    }
}
