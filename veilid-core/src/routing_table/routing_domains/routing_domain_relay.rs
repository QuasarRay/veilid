use super::*;

/// The routing domain's record of the output of the relay management task
/// containing everything the rest of the system needs to know about a single relay
#[derive(Debug, Clone)]
pub struct RoutingDomainRelay {
    pub relay_id: NodeId,
    pub relay_node: FilteredNodeRef,
    pub relay_kind: RelayKind,
    /// The relay's peer info as last applied; our peer info describes the relay from this alone
    pub relay_peer_info: Option<Arc<PeerInfo>>,
    pub pings: Vec<RelayPing>,
    pub dial_info_details: Vec<DialInfoDetail>,
}

impl RoutingDomainRelay {
    /// Checks if this relay is configured the same way as another relay
    pub fn equivalent(&self, other: &Self) -> bool {
        self.relay_node.equivalent(&other.relay_node)
            && self.relay_kind == other.relay_kind
            && self.pings.len() == other.pings.len()
            && self
                .pings
                .iter()
                .zip(other.pings.iter())
                .all(|(a, b)| a.equivalent(b))
            && self.dial_info_details == other.dial_info_details
            && match (self.relay_info(), other.relay_info()) {
                (Some(a), Some(b)) => a.equivalent(&b),
                (None, None) => true,
                _ => false,
            }
    }

    /// The relay info our peer info carries for this relay
    pub fn relay_info(&self) -> Option<RelayInfo> {
        let relay_peer_info = self.relay_peer_info.as_ref()?;
        let node_info = relay_peer_info.node_info();
        Some(RelayInfo::new(
            node_info.timestamp(),
            relay_peer_info.node_ids().clone(),
            node_info.outbound_protocols(),
            node_info.address_types(),
            self.dial_info_details.clone(),
            self.relay_kind,
            *node_info.receive_mtus(),
        ))
    }

    /// The relay addresses the keepalive pings reach, each with the protocol it is pinged over
    pub fn keepalive_addresses(&self) -> impl Iterator<Item = PeerAddress> + '_ {
        self.pings.iter().map(|ping| ping.dial_info.peer_address())
    }
}

impl RoutingDomainRelay {
    pub fn new(routing_domain: RoutingDomain, relay_node: NodeRef, relay_kind: RelayKind) -> Self {
        let relay_node =
            relay_node.custom_filtered(NodeRefFilter::new().with_routing_domain(routing_domain));
        let relay_id = relay_node.best_node_id();
        let relay_peer_info = relay_node.get_peer_info(routing_domain);
        RoutingDomainRelay {
            relay_id,
            relay_node,
            relay_kind,
            relay_peer_info,
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
            )),
        )
    }
}

/// The record of a node that needs to be pinged to keep a relay alive
#[derive(Debug, Clone)]
pub struct RelayPing {
    pub node_ref: NodeRef,
    pub dial_info: DialInfo,
}

impl RelayPing {
    pub fn equivalent(&self, other: &Self) -> bool {
        self.node_ref.equivalent(&other.node_ref) && self.dial_info == other.dial_info
    }
}

impl fmt::Display for RelayPing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}",
            f.to_string(&self.node_ref),
            f.to_string(&self.dial_info)
        )
    }
}

/// The routing domain's state tracking for a single relay
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoutingDomainRelayState {
    /// When we last sent this relay a keepalive
    pub last_keepalive: Timestamp,
    /// When we last attempted to optimize this relay
    pub last_optimized: Timestamp,
    /// When this relay was selected; never updated while it serves
    pub selected_ts: Timestamp,
    /// The relay's latency sample count at its first check after selection, where its dwell starts
    pub selected_latency_samples: Option<u64>,
    /// Best tm90 since this relay settled in, its baseline; None until measured past the dwell
    pub best_tm90: Option<TimestampDuration>,
}

impl fmt::Display for RoutingDomainRelayState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Keepalive:{}\nOptimized:{}\nSelected:{}\nSelectedLatencySamples:{}\nBestTm90:{}",
            f.to_string(self.last_keepalive),
            f.to_string(self.last_optimized),
            f.to_string(self.selected_ts),
            self.selected_latency_samples
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            self.best_tm90
                .map(|t| t.to_string())
                .unwrap_or_else(|| "none".to_owned())
        )
    }
}
