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

/// Directly reachable nodes a bootstrap reply offers per protocol and address family
pub const BOOTSTRAP_PEERS_PER_TYPE: usize = 2;

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
    /// The newest trusted payload in the config's `bootstrap_records`; bad lines are warned about
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

    /// The config's `bootstrap` entries that name something to ask; the rest are warned about
    pub fn config_bootstrap_entries(&self) -> Vec<String> {
        let entries = self.config().network.routing_table.bootstrap.clone();
        entries
            .into_iter()
            .filter(|entry| match check_bootstrap_entry(entry) {
                Ok(()) => true,
                Err(e) => {
                    veilid_log!(self warn "Ignoring invalid bootstrap entry {}: {}", entry, e);
                    false
                }
            })
            .collect()
    }

    /// What the config says this node serves, the configured payload and legacy lines, with no
    /// lookup
    pub fn config_bootstrap_cache(
        &self,
        payload: Option<&SignedBootstrapPayload>,
    ) -> BootstrapCache {
        let cache = payload
            .map(|payload| BootstrapCache::from_payload(payload, None))
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
}
