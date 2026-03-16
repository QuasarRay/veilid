use super::*;

/// The lifecycle stage of the routing domain's inbound connectivity
#[derive(Debug, Copy, Clone)]
pub enum RoutingDomainInboundStage {
    /// No network setup (no inbound/outbound protocols, address types, or capabilities). No dialinfo confirmation.
    Invalid,
    /// Network setup, but no dialinfo confirmation.
    NeedsDialInfoConfirmation,
    /// Network setup, dialinfo confirmation, but no address types or outbound protocols are enabled.
    Unusable,
    /// Network setup, dialinfo confirmation, address types + protocol types are valid, but 1+ relays must be selected because of missing dialinfo.
    NeedsRelays,
    /// Network setup, dialinfo confirmation, address types + protocol types are valid, and all relays needed are selected.
    ReadyToPublish,
}

/// The lifecycle stage of the routing domain's outbound connectivity
#[derive(Debug, Copy, Clone)]
pub enum RoutingDomainOutboundStage {
    /// No network setup (no inboundoutbound protocols, address types, or capabilities). No dialinfo confirmation.
    Invalid,
    /// Network setup but routing table is is too small, bootstrap is needed.
    NeedsBootstrap,
    /// Needs to have published peer info to allocate safety routes because the nodes that we contact need full connectivity
    NeedsPublishedPeerInfo,
    /// Needs to have more tested nodes to allocate routes because the nodes that we contact need full connectivity
    NeedsMoreTestedNodes,
    /// Needs background safety routes to be allocated so we can do routing operations
    NeedsSafetyRoutes,
    /// Ready to perform all operations
    ReadyToOperate,
}

/// Combined state information for the routing domain
#[derive(Debug)]
pub struct RoutingDomainState {
    /// The lifecycle stage of the routing domain's inbound connectivity
    pub inbound_stage: RoutingDomainInboundStage,
    /// The lifecycle stage of the routing domain's outbound connectivity
    pub outbound_stage: RoutingDomainOutboundStage,
    /// The relay status of the routing domain
    pub relay_status: Arc<RelayStatus>,
    /// The current peer info of the routing domain
    pub current_peer_info: Arc<PeerInfo>,
    /// The entry snapshot used to calculate this routing domain's state
    pub entry_summary: Arc<EntrySummary>,
    /// If this routing domain is ready for inbound use (dialinfo, relays, peer info, etc)
    pub is_ready_inbound: bool,
    /// If this routing domain is ready for outbound use (dialinfo, bootstrapped, safety routes, etc)
    pub is_ready_outbound: bool,
}
