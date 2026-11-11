use super::*;

impl_veilid_log_facility!("net");

impl NetworkManager {
    /// Direct bootstrap v0 (BOOT) request handler, answering nodes of the previous version
    /// with the JSON they parse
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip(self), ret, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn handle_boot_v0_request(&self, flow: Flow) -> EyreResult<NetworkResult<()>> {
        // Get a bunch of nodes with a range of crypto kinds, protocols and capabilities
        let bootstrap_nodes = self.find_bootstrap_nodes_filtered(2);

        // Serialize out peer info
        let bootstrap_peerinfo: Vec<legacy_json::LegacyPeerInfo> = bootstrap_nodes
            .iter()
            .filter_map(|nr| nr.get_peer_info(RoutingDomain::PublicInternet))
            .map(|pi| legacy_json::LegacyPeerInfo::from_peer_info(&pi))
            .collect();
        let json_bytes: Bytes = serialize_json(bootstrap_peerinfo).into();

        veilid_log!(self trace "BOOT reponse: {}", String::from_utf8_lossy(&json_bytes));

        // Reply with a chunk of signed routing table
        let net = self.net();
        match pin_future_closure!(net.send_data_to_existing_flow(
            flow,
            json_bytes,
            SAFE_TRANSPORT_MTU
        ))
        .await?
        {
            NetworkAttempt::Performed(NetworkResult::Value(_)) => Ok(NetworkResult::value(())),
            NetworkAttempt::Performed(NetworkResult::Timeout) => Ok(NetworkResult::timeout()),
            _ => Ok(NetworkResult::no_connection_other(
                "bootstrap reply could not be sent",
            )),
        }
    }
}
