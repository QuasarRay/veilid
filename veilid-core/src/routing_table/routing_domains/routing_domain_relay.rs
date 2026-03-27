use super::*;

#[derive(Debug, Clone)]
pub struct RoutingDomainRelay {
    pub relay_node: FilteredNodeRef,
    pub relay_kind: RelayKind,
    pub pings: Vec<RelayPing>,
    pub dial_info_details: Vec<DialInfoDetail>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RoutingDomainRelayState {
    pub last_keepalive: Timestamp,
    pub last_optimized: Timestamp,
}

impl fmt::Display for RoutingDomainRelayState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Keepalive:{}\nOptimized:{}",
            f.to_string(self.last_keepalive),
            f.to_string(self.last_optimized)
        )
    }
}

impl PartialEq for RoutingDomainRelay {
    fn eq(&self, other: &Self) -> bool {
        self.relay_node.equivalent(&other.relay_node)
            && self.relay_kind == other.relay_kind
            && self.pings == other.pings
            && self.dial_info_details == other.dial_info_details
    }
}

impl Eq for RoutingDomainRelay {}

impl RoutingDomainRelay {
    pub fn new(routing_domain: RoutingDomain, relay_node: NodeRef, relay_kind: RelayKind) -> Self {
        RoutingDomainRelay {
            relay_node: relay_node
                .custom_filtered(NodeRefFilter::new().with_routing_domain(routing_domain)),
            relay_kind,
            dial_info_details: vec![],
            pings: vec![],
        }
    }
}

impl fmt::Display for RoutingDomainRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#}: {}\nPings:\n{}\nDial Info Details:\n{}",
            self.relay_kind,
            self.relay_node,
            indent_all_string(
                f.to_multiline_indexed_string(self.pings.iter().map(|p| f.to_string(p)))
            ),
            indent_all_string(f.to_multiline_indexed_string(
                self.dial_info_details.iter().map(|d| f.to_string(d))
            ))
        )
    }
}
