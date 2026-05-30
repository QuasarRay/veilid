use super::*;

/// Pre-send outcome of choosing how to reach a node.
/// Resolved means we picked a contact method; other variants explain why we couldn't.
#[derive(Clone, Debug)]
pub enum NodeContactMethodResult {
    /// A contact method was picked and the send was attempted.
    Resolved(NodeContactMethod),
    /// Destination has no routing domain (e.g. target's relay address doesn't match any of ours).
    NoRoutingDomain,
    /// Target has no PeerInfo in the routing table for the chosen routing domain.
    NoPeerInfo,
    /// No compatible contact method could be derived from peer info.
    NoContactMethod,
    /// Target node id is administratively punished.
    Punished,
}

impl NodeContactMethodResult {
    pub fn opt_node_contact_method(&self) -> Option<&NodeContactMethod> {
        match self {
            NodeContactMethodResult::Resolved(ncm) => Some(ncm),
            _ => None,
        }
    }

    pub fn opt_transport_type(&self) -> Option<TransportType> {
        match self {
            NodeContactMethodResult::Resolved(ncm) => ncm.opt_transport_type(),
            _ => None,
        }
    }

    pub fn direct_dial_info(&self) -> Option<DialInfo> {
        match self {
            NodeContactMethodResult::Resolved(ncm) => ncm.direct_dial_info(),
            _ => None,
        }
    }
}

impl fmt::Display for NodeContactMethodResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeContactMethodResult::Resolved(ncm) => write!(f, "{}", f.to_string(ncm)),
            NodeContactMethodResult::NoRoutingDomain => write!(f, "NoRoutingDomain"),
            NodeContactMethodResult::NoPeerInfo => write!(f, "NoPeerInfo"),
            NodeContactMethodResult::NoContactMethod => write!(f, "NoContactMethod"),
            NodeContactMethodResult::Punished => write!(f, "Punished"),
        }
    }
}
