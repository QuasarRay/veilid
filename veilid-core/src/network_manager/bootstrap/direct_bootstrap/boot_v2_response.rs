use super::*;

pub const MAX_BOOTSTRAP_PEERS: usize = veilid_capnp::MAX_BOOTSTRAP_PEERS as usize;

/// What a B02T reply carries, as decoded by a client
#[derive(Debug, Default)]
pub struct BootV2Response {
    /// The signed payload bytes exactly as the server held them, None when it had none
    pub payload: Option<Bytes>,
    /// The peers the server offered, not yet verified
    pub peers: Vec<UnverifiedPeerInfo>,
}
