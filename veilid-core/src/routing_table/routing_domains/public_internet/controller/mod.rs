mod bootstrap;
mod closest_peers_refresh;
mod contact_method;
mod peer_minimum_refresh;
mod ping_validations;
mod private_route_management;

mod relay_management;
mod state;
mod tasks;

use super::*;

pub use state::NodesNeeded;

impl_veilid_log_facility!("rtab");

/// How frequently we tick the relay management routine
pub const RELAY_MANAGEMENT_INTERVAL_SECS: u32 = 1;

/// How frequently we tick the private route management routine
pub const PRIVATE_ROUTE_MANAGEMENT_INTERVAL_SECS: u32 = 1;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct PublicInternetRoutingDomainControllerUnlockedInner {
    registry: VeilidComponentRegistry,
    detail: Box<RwLock<dyn RoutingDomainDetail>>,
    /// Published peer info for this routing domain
    published_peer_info: Mutex<Option<Arc<PeerInfo>>>,
    /// Last time we pinged checked the active watches
    opt_active_watch_keepalive_ts: Mutex<Option<Timestamp>>,

    /// Background process to get our initial routing table
    bootstrap_task: TickTask<EyreReport>,
    /// Background process to get more nodes for each crypto kind
    peer_minimum_refresh_task: TickTask<EyreReport>,
    /// Background process to ensure we have enough nodes close to our own in our routing table
    closest_peers_refresh_task: TickTask<EyreReport>,
    /// Background process to check PublicInternet nodes to see if they are still alive and for reliability
    ping_validator_public_internet_task: TickTask<EyreReport>,
    /// Background process to keep relays up
    relay_management_task: TickTask<EyreReport>,
    /// Background process to keep private routes up
    private_route_management_task: TickTask<EyreReport>,
}

impl fmt::Debug for PublicInternetRoutingDomainControllerUnlockedInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicInternetRoutingDomainControllerUnlockedInner")
            .field("detail", &self.detail)
            .field("published_peer_info", &self.published_peer_info)
            .field(
                "opt_active_watch_keepalive_ts",
                &self.opt_active_watch_keepalive_ts,
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct PublicInternetRoutingDomainController {
    unlocked_inner: Arc<PublicInternetRoutingDomainControllerUnlockedInner>,
}

impl core::ops::Deref for PublicInternetRoutingDomainController {
    type Target = PublicInternetRoutingDomainControllerUnlockedInner;

    fn deref(&self) -> &Self::Target {
        &self.unlocked_inner
    }
}

impl_veilid_component_accessors!(PublicInternetRoutingDomainController);

impl PublicInternetRoutingDomainController {
    pub fn new(registry: VeilidComponentRegistry) -> Self {
        let config = registry.config();
        let detail = Box::new(RwLock::new(PublicInternetRoutingDomainDetail::new(
            registry.clone(),
        )));
        let unlocked_inner = PublicInternetRoutingDomainControllerUnlockedInner {
            registry,
            detail,
            published_peer_info: Default::default(),
            opt_active_watch_keepalive_ts: Default::default(),
            bootstrap_task: TickTask::new("bootstrap_task", 1),
            peer_minimum_refresh_task: TickTask::new("peer_minimum_refresh_task", 1),
            closest_peers_refresh_task: TickTask::new_ms(
                "closest_peers_refresh_task",
                config.network.dht.min_peer_refresh_time_ms,
            ),
            ping_validator_public_internet_task: TickTask::new(
                "ping_validator_public_internet_task",
                1,
            ),
            relay_management_task: TickTask::new(
                "relay_management_task",
                RELAY_MANAGEMENT_INTERVAL_SECS,
            ),
            private_route_management_task: TickTask::new(
                "private_route_management_task",
                PRIVATE_ROUTE_MANAGEMENT_INTERVAL_SECS,
            ),
        };
        let this = Self {
            unlocked_inner: Arc::new(unlocked_inner),
        };
        this.setup_tasks();
        this
    }
}

impl RoutingDomainController for PublicInternetRoutingDomainController {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Read access to the routing domain detail
    fn read(&self) -> RwLockReadGuard<'_, dyn RoutingDomainDetail> {
        self.unlocked_inner.detail.read()
    }

    /// Write access to the routing domain detail
    fn write(&self) -> RwLockWriteGuard<'_, dyn RoutingDomainDetail> {
        self.unlocked_inner.detail.write()
    }

    fn routing_domain(&self) -> RoutingDomain {
        RoutingDomain::PublicInternet
    }

    /// Start up the routing domain controller
    fn startup(&self) -> PinBoxFuture<'_, EyreResult<()>> {
        Box::pin(async move {
            // Nothing to do
            Ok(())
        })
    }

    /// Shut down the routing domain controller
    fn shutdown(&self) -> PinBoxFuture<'_, ()> {
        Box::pin(async move {
            // Unpublish peer info
            veilid_log!(self debug "PublicInternet: unpublishing peer info");
            self.unpublish_peer_info();
        })
    }

    fn tick(&self) -> PinBoxFuture<'_, EyreResult<()>> {
        Box::pin(PublicInternetRoutingDomainController::tick(self))
    }

    fn cancel_tasks(&self) -> PinBoxFuture<'_, ()> {
        Box::pin(PublicInternetRoutingDomainController::cancel_tasks(self))
    }

    fn state(&self) -> RoutingDomainState {
        PublicInternetRoutingDomainController::state(self)
    }

    fn get_health(&self) -> RoutingDomainHealth {
        let state = self.state();

        let entry_summary = state.entry_summary;
        let low_water_mark = state.low_water_mark;
        let is_ready_inbound = state.is_ready_inbound;
        let is_ready_outbound = state.is_ready_outbound;

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

            let opt_new_peer_info = if matches!(
                state.inbound_stage,
                RoutingDomainInboundStage::ReadyToPublish
            ) {
                Some(state.current_peer_info)
            } else {
                None
            };

            // Don't publish if the peer info hasnt changed from our previous publication
            let mut ppi_lock = self.published_peer_info.lock();
            let opt_old_peer_info = (*ppi_lock).clone();

            if let Some(old_peer_info) = &opt_old_peer_info {
                if let Some(new_peer_info) = &opt_new_peer_info {
                    if new_peer_info.equivalent(old_peer_info) {
                        veilid_log!(self debug "[PublicInternet] Not publishing peer info because it is equivalent");
                        return false;
                    }
                }
            } else if opt_new_peer_info.is_none() {
                veilid_log!(self debug "[PublicInternet] Not publishing peer info because it is still None");
                return false;
            }

            if let Some(new_peer_info) = &opt_new_peer_info {
                veilid_log!(self debug "[PublicInternet] Published new peer info: {}", new_peer_info);
            } else {
                veilid_log!(self debug "[PublicInternet] Unpublishing because current peer info is invalid");
            }

            *ppi_lock = opt_new_peer_info.clone();

            (opt_old_peer_info, opt_new_peer_info)
        };

        if let Err(e) = self.event_bus().post(PeerInfoChangeEvent {
            routing_domain: RoutingDomain::PublicInternet,
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
        veilid_log!(self debug "[PublicInternet] Unpublished peer info");
        *ppi_lock = None;
        if let Err(e) = self.event_bus().post(PeerInfoChangeEvent {
            routing_domain: RoutingDomain::PublicInternet,
            opt_old_peer_info,
            opt_new_peer_info: None,
        }) {
            veilid_log!(self debug "Failed to post event: {}", e);
        }
    }

    fn get_published_peer_info(&self) -> Option<Arc<PeerInfo>> {
        self.published_peer_info.lock().clone()
    }

    fn get_contact_method(
        &self,
        peer_a: Arc<PeerInfo>,
        peer_b: Arc<PeerInfo>,
        dial_info_filter: DialInfoFilter,
        sequencing: Sequencing,
        context_sort: Option<&DialInfoDetailSort>,
    ) -> ContactMethod {
        PublicInternetRoutingDomainController::get_contact_method(
            self,
            peer_a,
            peer_b,
            dial_info_filter,
            sequencing,
            context_sort,
        )
    }
}
