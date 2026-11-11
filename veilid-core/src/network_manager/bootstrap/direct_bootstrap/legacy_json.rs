//! The JSON a 0.5.x node parses from a BOOT or B01T reply, frozen at the 0.5.8 shape.
//! One dial info kind a reader was not built with fails its whole parse, and WSS was an
//! optional feature there, so only UDP, TCP and WS entries are written. 0.5.8 rebuilds the
//! peer from the signed `node_info_message`, which carries every kind.

use super::*;

/// 0.5.8's `PeerInfo` as serde wrote it
#[derive(Clone, Debug, Serialize)]
pub struct LegacyPeerInfo {
    /// The routing domain the peer info was received for
    routing_domain: RoutingDomain,
    /// The node ids for each crypto kind in the node info
    node_ids: NodeIdGroup,
    /// The node info with the entries a 0.5.x reader can parse
    node_info: LegacyNodeInfo,
    /// The signed node info bytes, as received
    node_info_message: Bytes,
    /// The signatures over the node info message
    signatures: SignatureGroup,
}

/// 0.5.8's `NodeInfo`; `receive_mtus` and `expiration` had serde defaults there and are left out
#[derive(Clone, Debug, Serialize)]
pub struct LegacyNodeInfo {
    /// When the node info was generated
    timestamp: Timestamp,
    /// The envelope versions the node speaks
    envelope_support: Vec<EnvelopeVersion>,
    /// Public keys per crypto kind, the kinds 0.5.x knows
    crypto_info_list: Vec<LegacyCryptoInfo>,
    /// The node's capabilities
    capabilities: Vec<VeilidCapability>,
    /// Protocols the node dials out on, of those every 0.5.x build knows
    outbound_protocols: ProtocolTypeSet,
    /// Address families the node uses
    address_types: AddressTypeSet,
    /// Dial info of the kinds 0.5.x parses
    dial_info_detail_list: Vec<DialInfoDetail>,
    /// The node's relays
    relay_info_list: Vec<LegacyRelayInfo>,
}

/// 0.5.8's `RelayInfo`; `receive_mtus` had a serde default there and is left out
#[derive(Clone, Debug, Serialize)]
pub struct LegacyRelayInfo {
    /// When the relay info was generated
    timestamp: Timestamp,
    /// The relay's node ids
    node_ids: NodeIdGroup,
    /// Protocols the relay dials out on, of those every 0.5.x build knows
    outbound_protocols: ProtocolTypeSet,
    /// Address families the relay uses
    address_types: AddressTypeSet,
    /// Dial info of the kinds 0.5.x parses
    dial_info_detail_list: Vec<DialInfoDetail>,
    /// The kind of relay
    relay_kind: RelayKind,
}

/// 0.5.8's `CryptoInfo`: the variants that existed then
#[derive(Clone, Debug, Serialize)]
pub enum LegacyCryptoInfo {
    #[cfg(feature = "enable-crypto-none")]
    NONE { public_key: BarePublicKey },
    #[cfg(feature = "enable-crypto-vld0")]
    VLD0 { public_key: BarePublicKey },
}

/// Whether every 0.5.x build parses this dial info kind
fn legacy_dial_info(did: &DialInfoDetail) -> bool {
    matches!(
        did.dial_info.protocol_type(),
        ProtocolType::UDP | ProtocolType::TCP | ProtocolType::WS
    )
}

fn legacy_protocols(protocols: ProtocolTypeSet) -> ProtocolTypeSet {
    protocols & (ProtocolType::UDP | ProtocolType::TCP | ProtocolType::WS)
}

impl LegacyPeerInfo {
    pub fn from_peer_info(peer_info: &PeerInfo) -> Self {
        let ni = peer_info.node_info();
        let crypto_info_list = ni
            .crypto_info_list()
            .iter()
            .filter_map(|ci| match ci {
                #[cfg(feature = "enable-crypto-none")]
                CryptoInfo::NONE { public_key } => Some(LegacyCryptoInfo::NONE {
                    public_key: public_key.clone(),
                }),
                #[cfg(feature = "enable-crypto-vld0")]
                CryptoInfo::VLD0 { public_key } => Some(LegacyCryptoInfo::VLD0 {
                    public_key: public_key.clone(),
                }),
                #[allow(unreachable_patterns)]
                _ => None,
            })
            .collect();
        let relay_info_list = ni
            .relay_info_list()
            .iter()
            .map(|ri| LegacyRelayInfo {
                timestamp: ri.timestamp(),
                node_ids: ri.node_ids().clone(),
                outbound_protocols: legacy_protocols(ri.outbound_protocols()),
                address_types: ri.address_types(),
                dial_info_detail_list: ri
                    .dial_info_detail_list()
                    .iter()
                    .filter(|did| legacy_dial_info(did))
                    .cloned()
                    .collect(),
                relay_kind: ri.relay_kind(),
            })
            .collect();
        Self {
            routing_domain: peer_info.routing_domain(),
            node_ids: peer_info.node_ids().clone(),
            node_info: LegacyNodeInfo {
                timestamp: ni.timestamp(),
                envelope_support: ni.envelope_support().to_vec(),
                crypto_info_list,
                capabilities: ni.capabilities().to_vec(),
                outbound_protocols: legacy_protocols(ni.outbound_protocols()),
                address_types: ni.address_types(),
                dial_info_detail_list: ni
                    .dial_info_detail_list()
                    .iter()
                    .filter(|did| legacy_dial_info(did))
                    .cloned()
                    .collect(),
                relay_info_list,
            },
            node_info_message: peer_info.node_info_message().clone(),
            signatures: peer_info.signatures().clone(),
        }
    }
}
