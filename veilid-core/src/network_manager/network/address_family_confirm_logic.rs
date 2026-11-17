//! Decision logic for empirical address-family confirmation, used by the wasm
//! network and unit-tested on every platform.
//!
//! Invariant: a probe round that condemns every family defers rather than
//! confirming the empty set. An empty confirmed set stops all traffic, and with
//! no traffic no network-change event re-arms confirmation, so the node stays
//! dark until restart. Only a domain with no configured address types confirms
//! empty.
//!
//! Evidence of a family is an answer over a flow dialed at an address of that
//! family, or a peer's report of the address it saw us from. A flow to a named url
//! has no family of its own: the browser picks one when it resolves the name.

use super::*;

/// Minimum number of candidate nodes to probe an address family
pub(crate) const ADDR_FAMILY_MIN_NODES_TO_CONFIRM: usize = 4;
/// Unanswered probes that condemn an address family
pub(crate) const ADDR_FAMILY_FAILURE_THRESHOLD: usize = 3;

/// Address family probe result
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FamilyProbeDisposition {
    /// A peer saw us from an address of this family
    Supported,
    /// Enough probe failures to condemn this family
    Unsupported,
    /// Probes ran out before either conclusion: every answer came over another family
    Inconclusive,
    /// The stop token fired mid-round
    Cancelled,
}

/// What one probe of an address family brought back
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FamilyProbeAnswer {
    /// No answer came
    Unanswered,
    /// The peer answered. Holds the family of the address it saw us from, when the answer
    /// came over a flow to the peer itself
    Answered(Option<AddressType>),
}

/// The probes of one address family, folded in order into its disposition
#[derive(Debug)]
pub(crate) struct FamilyProbeRound {
    address_type: AddressType,
    failures: usize,
}

impl FamilyProbeRound {
    pub(crate) fn new(address_type: AddressType) -> Self {
        Self {
            address_type,
            failures: 0,
        }
    }

    /// Fold one probe in, returning the disposition once it is settled. An answer the peer
    /// saw from another family settles nothing: the dial went to a named url, which a
    /// browser reaches over whichever family it resolves
    pub(crate) fn record(&mut self, answer: FamilyProbeAnswer) -> Option<FamilyProbeDisposition> {
        match answer {
            FamilyProbeAnswer::Answered(Some(seen_from)) if seen_from == self.address_type => {
                Some(FamilyProbeDisposition::Supported)
            }
            FamilyProbeAnswer::Answered(_) => None,
            FamilyProbeAnswer::Unanswered => {
                self.failures += 1;
                (self.failures >= ADDR_FAMILY_FAILURE_THRESHOLD)
                    .then_some(FamilyProbeDisposition::Unsupported)
            }
        }
    }
}

/// True when a flow to this dial info runs over the dial info's own address family. A browser
/// dials WSS and WebTransport at the url, and reaches a named host over whichever family it
/// resolves
pub(crate) fn dial_info_names_its_address(dial_info: &DialInfo) -> bool {
    let dialed_at_the_socket_address = ProtocolType::UDP | ProtocolType::TCP | ProtocolType::WS;
    dialed_at_the_socket_address.contains(dial_info.protocol_type())
        || dial_info
            .request()
            .and_then(|request| SplitUrl::from_str(&request).ok())
            .is_some_and(|url| matches!(url.host, SplitUrlHost::IpAddr(_)))
}

/// True when traffic seen over a transport of a node proves the transport's address family:
/// the node offers the transport, and every dial info it offers on it names its address
pub(crate) fn transport_names_its_address<'a>(
    dial_infos: impl IntoIterator<Item = &'a DialInfo>,
    transport_type: TransportType,
) -> bool {
    let mut on_transport = dial_infos
        .into_iter()
        .filter(|dial_info| dial_info.transport_type() == transport_type)
        .peekable();
    on_transport.peek().is_some() && on_transport.all(dial_info_names_its_address)
}

/// Address family confirmation state
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum AddressFamilyConfirmState {
    /// No address types are configured for this routing domain
    NoConfiguredAddressTypes,
    /// All configured address types have been confirmed
    AllConfiguredConfirmed,
    /// Not enough candidates to verify unconfirmed address type
    NotEnoughCandidates,
    /// Confirm candidates to determine final set of address types
    ConfirmCandidates,
}

/// Outcome of one confirmation pass
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConfirmationPassOutcome {
    /// Publish this set and mark the domain confirmed
    Confirm(AddressTypeSet),
    /// Not enough evidence to conclude; leave unconfirmed so the worker retries
    Deferred,
}

/// Candidate inventory for one confirmation pass, generic over the candidate
/// handle so the decision logic tests off-network
pub(crate) struct AddressFamilyConfirmCandidates<N> {
    /// All address types configured for this routing domain
    pub(crate) configured_address_types: AddressTypeSet,
    /// All address types that have been positively seen since we started the confirmation process
    pub(crate) confirmed_address_types: AddressTypeSet,
    /// Nodes that can confirm an unconfirmed address type
    pub(crate) candidates: BTreeMap<AddressType, Vec<N>>,
}

impl<N> AddressFamilyConfirmCandidates<N> {
    /// Determine the current state of the address family confirmation process
    pub fn state(&self) -> AddressFamilyConfirmState {
        if self.configured_address_types.is_empty() {
            AddressFamilyConfirmState::NoConfiguredAddressTypes
        } else if self.confirmed_address_types == self.configured_address_types {
            AddressFamilyConfirmState::AllConfiguredConfirmed
        } else {
            let missing_address_types =
                self.configured_address_types - self.confirmed_address_types;
            for mat in missing_address_types {
                let candidates = self
                    .candidates
                    .get(&mat)
                    .as_ref()
                    .map(|c| c.len())
                    .unwrap_or(0);
                if candidates < ADDR_FAMILY_MIN_NODES_TO_CONFIRM {
                    return AddressFamilyConfirmState::NotEnoughCandidates;
                }
            }
            AddressFamilyConfirmState::ConfirmCandidates
        }
    }
}

/// Fold a probe round into a pass outcome. `seen_live` holds families already
/// confirmed by real traffic since the confirm request.
pub(crate) fn resolve_probe_dispositions(
    seen_live: AddressTypeSet,
    dispositions: &[(AddressType, FamilyProbeDisposition)],
) -> ConfirmationPassOutcome {
    let mut confirmed_address_types = seen_live;
    for (at, disposition) in dispositions {
        match disposition {
            FamilyProbeDisposition::Cancelled => return ConfirmationPassOutcome::Deferred,
            FamilyProbeDisposition::Supported => {
                confirmed_address_types.insert(*at);
            }
            FamilyProbeDisposition::Unsupported | FamilyProbeDisposition::Inconclusive => {}
        }
    }
    // All-condemned must defer, never confirm empty (see module doc)
    if confirmed_address_types.is_empty() {
        return ConfirmationPassOutcome::Deferred;
    }
    ConfirmationPassOutcome::Confirm(confirmed_address_types)
}
