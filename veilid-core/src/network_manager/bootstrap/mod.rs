mod bootstrap_cache;
mod bootstrap_peers;
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
mod bootstrap_record;
mod debug;
mod dial_info_converter;
mod direct_bootstrap;
mod payload;

use super::*;

impl_veilid_log_facility!("net");

/// Port a bootstrap host answers on when a bare name names it
pub const BOOTSTRAP_DIRECT_PORT: u16 = 5150;

/// Ceiling on served legacy record lines, far above any real bootstrap's output
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub const MAX_BOOTSTRAP_RECORD_STRINGS: usize = 64;

pub use bootstrap_cache::*;
pub use bootstrap_peers::*;
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub use bootstrap_record::*;
pub use dial_info_converter::*;
#[cfg(all(
    any(test, feature = "test-util"),
    any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1")
))]
pub use direct_bootstrap::legacy_json::LegacyPeerInfo;
#[cfg(any(test, feature = "test-util"))]
pub use direct_bootstrap::{BootV2Response, B02T_MAGIC};
pub use payload::*;

impl NetworkManager {
    /// The payload in the config's `bootstrap_records`, if any line holds one this node trusts.
    /// A line that fails its signature check is a configuration mistake and is said so
    pub fn config_bootstrap_payload(&self) -> Option<SignedBootstrapPayload> {
        let (record_strings, bootstrap_keys) = {
            let cfg = self.config();
            let rt = &cfg.network.routing_table;
            (rt.bootstrap_records.clone(), rt.bootstrap_keys.clone())
        };
        let crypto = self.crypto();
        let mut newest: Option<SignedBootstrapPayload> = None;
        for line in record_strings
            .iter()
            .filter(|line| SignedBootstrapPayload::is_payload_line(line))
        {
            let payload = match SignedBootstrapPayload::try_new_from_line(line) {
                Ok(v) => v,
                Err(e) => {
                    veilid_log!(self warn "Ignoring invalid configured bootstrap payload: {}", e);
                    continue;
                }
            };
            if !bootstrap_keys.is_empty() {
                if let Err(e) = payload.verify(&crypto, &bootstrap_keys) {
                    veilid_log!(self warn "Ignoring configured bootstrap payload: {}", e);
                    continue;
                }
            }
            if newest
                .as_ref()
                .is_none_or(|n| payload.payload().timestamp() > n.payload().timestamp())
            {
                newest = Some(payload);
            }
        }
        newest
    }

    /// Everything the config says this node serves, whether or not it ever bootstraps: the
    /// payload, and the legacy lines for nodes that still ask the old way. No lookup of any kind
    pub fn config_bootstrap_cache(&self) -> BootstrapCache {
        let cache = self
            .config_bootstrap_payload()
            .map(|payload| BootstrapCache::from_payload(&payload, None))
            .unwrap_or_default();
        #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
        let cache = {
            let mut cache = cache;
            let (record_strings, records) = self.parse_config_bootstrap_records();
            cache.union(BootstrapCache::from_records(record_strings, records));
            cache
        };
        cache
    }

    /// The configured payload as a bootstrap source: its nodes are asked directly
    pub fn config_bootstrap(&self) -> BootstrapPeers {
        let Some(payload) = self.config_bootstrap_payload() else {
            return BootstrapPeers::default();
        };
        if payload.payload().is_expired(Timestamp::now()) {
            veilid_log!(self warn "The configured bootstrap payload has expired");
            return BootstrapPeers::default();
        }
        let unanswered = payload.payload().bootstrap_nodes().to_vec();
        BootstrapPeers {
            peers: vec![],
            payload: Some(payload),
            unanswered,
        }
    }
}
