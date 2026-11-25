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
        let bootstrap_nodes = self.find_bootstrap_nodes_filtered(BOOTSTRAP_PEERS_PER_TYPE);

        // Serialize out peer info
        let bootstrap_peerinfo: Vec<legacy_json::LegacyPeerInfo> = bootstrap_nodes
            .iter()
            .filter_map(|nr| nr.get_peer_info(RoutingDomain::PublicInternet))
            .map(|pi| legacy_json::LegacyPeerInfo::from_peer_info(&pi))
            .collect();
        let json_bytes: Bytes = serialize_json(bootstrap_peerinfo).into();

        veilid_log!(self trace "BOOT reponse: {}", String::from_utf8_lossy(&json_bytes));

        self.send_bootstrap_reply(flow, json_bytes).await
    }
}
