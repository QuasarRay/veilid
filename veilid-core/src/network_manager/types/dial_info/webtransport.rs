use super::*;

/// Most certificate hashes a WebTransport dial info carries
pub(crate) const MAX_CERT_HASHES: usize = veilid_capnp::MAX_WEB_TRANSPORT_CERT_HASHES as usize;

#[derive(Clone, Default, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct DialInfoWebTransport {
    pub socket_address: SocketAddress,
    pub request: String,
    pub cert_hashes: Vec<[u8; 32]>,
    #[serde(default)]
    pub expiration: Option<Timestamp>,
}
