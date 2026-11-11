use super::*;

impl_veilid_log_facility!("net");

impl NetworkManager {
    /// This node's PublicInternet addresses, one per line, for a reverse lookup by the caller
    #[cfg_attr(not(feature = "debug-api"), expect(dead_code))]
    pub fn debug_info_bootstrap_addresses(&self) -> String {
        let routing_table = self.routing_table();
        let mut addrs: Vec<IpAddr> = routing_table
            .dial_info_details(RoutingDomain::PublicInternet)
            .iter()
            .map(|did| did.dial_info.socket_address().ip_addr())
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
            .iter()
            .map(|a| format!("{}\n", a))
            .collect::<Vec<_>>()
            .join("")
    }

    /// This node as a bootstrap server, the line an operator signs into a payload
    pub fn debug_info_bootstrap_node(&self) -> String {
        match self.own_bootstrap_node() {
            Ok(bsn) => match bsn.to_line() {
                Ok(line) => format!("{}\n", line),
                Err(e) => format!("Bootstrap node line error: {}\n", e),
            },
            Err(e) => format!("{}\n", e),
        }
    }

    /// The bootstrap record lines for this node: the legacy TXT forms when they are built in,
    /// and the node line. `hostname` names this host in the legacy forms
    #[cfg_attr(not(feature = "debug-api"), expect(dead_code))]
    pub fn debug_info_bootstrap_records(
        &self,
        hostname: Option<String>,
        signing_key_pairs: KeyPairGroup,
    ) -> String {
        let mut out = "Bootstrap Records:\n".to_owned();
        #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
        {
            let routing_table = self.routing_table();
            let dial_info_details = routing_table.dial_info_details(RoutingDomain::PublicInternet);
            if dial_info_details.is_empty() {
                return "No PublicInternet DialInfo for bootstrap records\n".to_owned();
            }
            let Some(hostname) = hostname else {
                return "A hostname is required for the legacy record lines\n".to_owned();
            };
            let bsrec = BootstrapRecord::new(
                routing_table.public_keys(),
                VALID_ENVELOPE_VERSIONS.to_vec(),
                dial_info_details,
                Some(Timestamp::now().as_u64() / 1_000_000u64),
                vec![],
            );
            #[cfg(feature = "enable-bootstrap-v0")]
            match bsrec.to_v0_string(&hostname) {
                Ok(v) => out += &format!("V0:\n{}\n", v),
                Err(e) => out += &format!("V0 error: {}\n", e),
            }
            #[cfg(feature = "enable-bootstrap-v1")]
            for skp in signing_key_pairs.iter() {
                match bsrec.to_v1_string(self, &hostname, skp.clone()) {
                    Ok(v) => out += &format!("V1 ({}):\n{}\n", skp.kind(), v),
                    Err(e) => out += &format!("V1 ({}) error: {}\n", skp.kind(), e),
                }
            }
            #[cfg(not(feature = "enable-bootstrap-v1"))]
            let _ = signing_key_pairs;
        }
        #[cfg(not(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1")))]
        {
            let _ = (hostname, signing_key_pairs);
        }
        out += "V2 node:\n";
        out += &self.debug_info_bootstrap_node();
        out
    }

    /// Sign node lines into a payload line. No keypairs makes an unsigned payload
    #[cfg_attr(not(feature = "debug-api"), expect(dead_code))]
    pub fn debug_info_bootstrap_payload(
        &self,
        lifetime: Option<TimestampDuration>,
        cache_ttl: Option<TimestampDuration>,
        node_lines: &[String],
        signing_key_pairs: KeyPairGroup,
    ) -> String {
        let mut bootstrap_nodes = Vec::with_capacity(node_lines.len());
        for line in node_lines {
            match BootstrapNode::try_new_from_line(line) {
                Ok(bsn) => bootstrap_nodes.push(bsn),
                Err(e) => return format!("Invalid bootstrap node line: {}\n", e),
            }
        }
        if bootstrap_nodes.is_empty() {
            return "No bootstrap node lines given\n".to_owned();
        }
        let now = Timestamp::now();
        let payload = BootstrapPayload::new(
            now,
            lifetime.map(|lifetime| now.later(lifetime)),
            cache_ttl,
            bootstrap_nodes,
        );
        let key_pairs: Vec<KeyPair> = signing_key_pairs.iter().cloned().collect();
        match SignedBootstrapPayload::try_new_signed(&self.crypto(), payload, &key_pairs) {
            Ok(signed) => format!("{}\n", signed.to_line()),
            Err(e) => format!("Bootstrap payload error: {}\n", e),
        }
    }

    /// This node's ids and published PublicInternet dial infos as a bootstrap server
    pub fn own_bootstrap_node(&self) -> EyreResult<BootstrapNode> {
        let routing_table = self.routing_table();
        let dial_infos: Vec<DialInfo> = routing_table
            .dial_info_details(RoutingDomain::PublicInternet)
            .into_iter()
            .map(|did| did.dial_info)
            .collect();
        if dial_infos.is_empty() {
            bail!("No PublicInternet dial info for a bootstrap node line");
        }
        Ok(BootstrapNode::new(routing_table.node_ids(), dial_infos))
    }
}
