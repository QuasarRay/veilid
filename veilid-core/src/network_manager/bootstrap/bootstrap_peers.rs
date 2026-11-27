use super::*;

/// Result of asking one bootstrap source
#[derive(Debug, Default)]
pub struct BootstrapPeers {
    /// Peers to bootstrap with, signatures verified
    pub peers: Vec<Arc<PeerInfo>>,
    /// The payload the source handed over, once it passed the trust rules
    pub payload: Option<SignedBootstrapPayload>,
}

impl BootstrapPeers {
    /// Fold another source's result in
    pub fn extend(&mut self, other: BootstrapPeers) {
        self.peers.extend(other.peers);
        if other.payload.as_ref().is_some_and(|op| {
            self.payload
                .as_ref()
                .is_none_or(|sp| op.payload().timestamp() > sp.payload().timestamp())
        }) {
            self.payload = other.payload;
        }
    }

    /// The payload's nodes that none of the peers answers for
    pub fn unanswered_payload_nodes(&self) -> Vec<BootstrapNode> {
        let Some(payload) = self.payload.as_ref() else {
            return vec![];
        };
        payload
            .payload()
            .bootstrap_nodes()
            .iter()
            .filter(|bsn| {
                !self
                    .peers
                    .iter()
                    .any(|pi| bsn.node_ids().contains_any_from_iter(pi.node_ids().iter()))
            })
            .cloned()
            .collect()
    }
}
