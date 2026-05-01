use super::*;

pub struct PeerInfoChangeEvent {
    pub routing_domain: RoutingDomain,
    pub opt_old_peer_info: Option<Arc<PeerInfo>>,
    pub opt_new_peer_info: Option<Arc<PeerInfo>>,
}

#[derive(Clone, Copy, Debug)]
pub struct RoutingDomainCommitEvent {
    pub routing_domain: RoutingDomain,
    #[expect(dead_code)]
    pub peer_info_changed: bool,
    pub confirmation_changed: bool,
    pub dial_info_changed: bool,
    pub relays_changed: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct RoutingDomainReadyEvent {
    #[expect(dead_code)]
    pub routing_domain: RoutingDomain,
    #[expect(dead_code)]
    pub is_ready_inbound: bool,
    #[expect(dead_code)]
    pub is_ready_outbound: bool,
}
