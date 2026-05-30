use super::*;

/// Mechanism required to contact another node
#[derive(Clone, Debug)]
pub enum NodeContactMethod {
    /// Connection should have already existed
    Existing,
    /// Contact the node directly
    Direct { target_di: DialInfo },
    /// Request via signal the node connect back directly
    SignalReverse { relay_di: DialInfo },
    /// Request via signal the node negotiate a hole punch
    SignalHolePunch {
        relay_di: DialInfo,
        hole_punch_di: DialInfo,
        reverse_hole_punch_di: DialInfo,
    },
    /// Must use an inbound relay to reach the node
    InboundRelay { relay_di: DialInfo },
    /// Must use outbound relay to reach the node
    OutboundRelay { relay_nr: FilteredNodeRef },
}

impl NodeContactMethod {
    pub fn direct_dial_info(&self) -> Option<DialInfo> {
        match &self {
            NodeContactMethod::Direct { target_di } => Some(target_di.clone()),
            _ => None,
        }
    }

    /// Transport credited to the target's per-transport stats for this send attempt.
    /// A target accepts responsibility for the relay it published, so we always
    /// attribute to the target — never to the relay.
    pub fn opt_transport_type(&self) -> Option<TransportType> {
        match self {
            NodeContactMethod::Existing => None,
            NodeContactMethod::Direct { target_di } => Some(TransportType::from(target_di)),
            NodeContactMethod::InboundRelay { relay_di }
            | NodeContactMethod::SignalReverse { relay_di }
            | NodeContactMethod::SignalHolePunch { relay_di, .. } => {
                Some(TransportType::from(relay_di))
            }
            NodeContactMethod::OutboundRelay { relay_nr } => {
                relay_nr.last_flow().map(|f| f.transport_type())
            }
        }
    }
}

impl fmt::Display for NodeContactMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeContactMethod::Existing => write!(f, "Existing"),
            NodeContactMethod::Direct { target_di } => {
                write!(f, "Direct({})", f.to_string(target_di))
            }
            NodeContactMethod::SignalReverse { relay_di } => {
                write!(f, "SignalReverse(relay={})", f.to_string(relay_di))
            }
            NodeContactMethod::SignalHolePunch {
                relay_di,
                hole_punch_di,
                reverse_hole_punch_di,
            } => write!(
                f,
                "SignalHolePunch(relay={}, hole_punch={}, reverse_hole_punch={})",
                f.to_string(relay_di),
                f.to_string(hole_punch_di),
                f.to_string(reverse_hole_punch_di),
            ),
            NodeContactMethod::InboundRelay { relay_di } => {
                write!(f, "InboundRelay(relay={})", f.to_string(relay_di))
            }
            NodeContactMethod::OutboundRelay { relay_nr } => {
                write!(f, "OutboundRelay(relay={})", f.to_string(relay_nr))
            }
        }
    }
}
