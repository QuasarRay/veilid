use super::*;

/// Externally visible health metrics for a routing domain
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct RoutingDomainHealth {
    /// Entry snapshot summary of the routing table per RoutingDomain and CryptoKind
    pub entry_summary: Arc<EntrySummary>,
    /// If this routing domain is ready for inbound use (dialinfo, relays, peer info, etc)
    pub is_ready_inbound: bool,
    /// If this routing domain is ready for outbound use (dialinfo, bootstrapped, safety routes, etc)
    pub is_ready_outbound: bool,
}

impl RoutingDomainHealth {
    /// Whether or not this routing domain is ready for all use (inbound and outbound)
    #[must_use]
    pub fn ready(&self) -> bool {
        self.is_ready_inbound && self.is_ready_outbound
    }
}
