mod boot_v2_response;
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub(super) mod legacy_json;
mod peers;
#[cfg(feature = "enable-bootstrap-v0")]
mod v0;
#[cfg(feature = "enable-bootstrap-v1")]
mod v1;
mod v2;

use super::*;

pub use boot_v2_response::*;
pub use v2::*;

impl_veilid_log_facility!("net");

impl NetworkManager {
    /// Ask one dial info for the payload and its peers; a reply without the B02T magic is dropped
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", err, skip(self), fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn direct_bootstrap(&self, dial_info: DialInfo) -> EyreResult<BootstrapPeers> {
        if self.routing_table().matches_own_dial_info(&dial_info) {
            veilid_log!(self debug "Ignoring own dial info in bootstrap list: {}", dial_info);
            return Ok(BootstrapPeers::default());
        }

        let timeout_ms = self.config().internal().network.rpc.timeout_ms;
        let data = self.boot_v2_request_bytes();

        // Our own transport is suppressed, so this says nothing about the bootstrap node
        let NetworkAttempt::Performed(attempt) = self
            .net()
            .send_recv_data_unbound_to_dial_info(
                dial_info.clone(),
                data.clone(),
                SAFE_TRANSPORT_MTU,
                timeout_ms,
            )
            .await?
        else {
            return Ok(BootstrapPeers::default());
        };
        let out_data = network_result_value_or_log!(self attempt => [ format!(": dial_info={}, data.len={}", dial_info, data.len()) ]
        {
            return Ok(BootstrapPeers::default());
        });

        if out_data.len() < B02T_MAGIC.len() || &out_data[0..B02T_MAGIC.len()] != B02T_MAGIC {
            veilid_log!(self debug "Bootstrap {} answered without B02T and needs upgrading", dial_info);
            return Ok(BootstrapPeers::default());
        }

        let response = self.decode_boot_v2_response(&out_data[B02T_MAGIC.len()..])?;
        Ok(self.accept_boot_v2_response(response))
    }

    /// Send a bootstrap reply down the flow its request came in on
    async fn send_bootstrap_reply(
        &self,
        flow: Flow,
        reply: Bytes,
    ) -> EyreResult<NetworkResult<()>> {
        let net = self.net();
        match pin_future_closure!(net.send_data_to_existing_flow(flow, reply, SAFE_TRANSPORT_MTU))
            .await?
        {
            NetworkAttempt::Performed(NetworkResult::Value(_)) => Ok(NetworkResult::value(())),
            NetworkAttempt::Performed(NetworkResult::Timeout) => Ok(NetworkResult::timeout()),
            _ => Ok(NetworkResult::no_connection_other(
                "bootstrap reply could not be sent",
            )),
        }
    }

    /// Apply the trust rules to a reply. With bootstrap keys the payload must carry a trusted
    /// signature and every peer must be one of its nodes; without keys everything offered is
    /// taken. A payload older than the one this node holds, from config or learned, is refused
    pub(in crate::network_manager) fn accept_boot_v2_response(
        &self,
        response: BootV2Response,
    ) -> BootstrapPeers {
        let bootstrap_keys = self.config().network.routing_table.bootstrap_keys.clone();
        let routing_table = self.routing_table();
        let crypto = self.crypto();
        let cur_ts = Timestamp::now();

        let payload = response.payload.and_then(|bytes| {
            let payload = match SignedBootstrapPayload::try_new_from_bytes(bytes) {
                Ok(v) => v,
                Err(e) => {
                    veilid_log!(self debug "Dropping undecodable bootstrap payload: {}", e);
                    return None;
                }
            };
            if !bootstrap_keys.is_empty() {
                if let Err(e) = payload.verify(&crypto, &bootstrap_keys) {
                    veilid_log!(self debug "Dropping bootstrap payload: {}", e);
                    return None;
                }
            }
            if payload.payload().is_expired(cur_ts) {
                veilid_log!(self debug "Dropping expired bootstrap payload from {}", payload.payload().timestamp());
                return None;
            }
            let floor = routing_table.bootstrap_payload_floor();
            if floor.is_some_and(|floor| payload.payload().timestamp() < floor) {
                veilid_log!(self debug "Dropping bootstrap payload from {} older than the one held", payload.payload().timestamp());
                return None;
            }
            Some(payload)
        });

        let mut peers = Vec::<Arc<PeerInfo>>::new();
        for unverified in response.peers {
            let pi = match unverified.verify_and_extract(&routing_table) {
                Ok(pi) => pi,
                Err(e) => {
                    veilid_log!(self debug "Dropping bootstrap peer {}: {}", unverified.node_ids(), e);
                    continue;
                }
            };
            if !bootstrap_keys.is_empty()
                && !payload
                    .as_ref()
                    .is_some_and(|p| p.payload().names_node(pi.node_ids()))
            {
                veilid_log!(self debug "Dropping bootstrap peer {} not named by the payload", pi.node_ids());
                continue;
            }
            peers.push(Arc::new(pi));
        }

        let unanswered = payload
            .as_ref()
            .map(|p| {
                p.payload()
                    .bootstrap_nodes()
                    .iter()
                    .filter(|bsn| {
                        !peers
                            .iter()
                            .any(|pi| bsn.node_ids().contains_any_from_iter(pi.node_ids().iter()))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        BootstrapPeers {
            peers,
            payload,
            unanswered,
        }
    }
}
