use super::*;

impl_veilid_log_facility!("net");

/// Bootstrap v2 FOURCC, the reply's first four bytes and the marker a request carries
pub const B02T_MAGIC: &[u8; 4] = b"B02T";

/// Per-peer size allowance while filling a reply: the largest signatures any kind produces
/// plus the message framing around them, before the encoded size is checked for real
const BOOT_V2_PEER_SIZE_ALLOWANCE: usize = 3400;

impl NetworkManager {
    /// The request a client sends. The legacy magic in front lets a server of the previous
    /// version answer with a reply this client ignores, instead of banning an unknown tag
    pub fn boot_v2_request_bytes(&self) -> Bytes {
        let mut out = Vec::with_capacity(8);
        let keyed = !self
            .config()
            .network
            .routing_table
            .bootstrap_keys
            .is_empty();
        #[cfg(feature = "enable-bootstrap-v1")]
        if keyed {
            out.extend_from_slice(B01T_MAGIC);
        }
        #[cfg(feature = "enable-bootstrap-v0")]
        if !keyed {
            out.extend_from_slice(BOOT_MAGIC);
        }
        #[cfg(not(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1")))]
        let _ = keyed;
        out.extend_from_slice(B02T_MAGIC);
        Bytes::from(out)
    }

    /// Whether a request's tag and marker ask for a v2 reply
    pub fn is_boot_v2_request(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        if &data[0..4] == B02T_MAGIC {
            return true;
        }
        let legacy = &data[0..4] == BOOT_MAGIC || &data[0..4] == B01T_MAGIC;
        legacy && data.len() >= 8 && &data[4..8] == B02T_MAGIC
    }

    /// Build the B02T reply: the held payload as its bytes, then peers within the message cap.
    /// Answers an unauthenticated packet, so this touches no resolver, does no I/O and signs
    /// nothing; what is held is served as is, and a re-check that has come due, for a stale
    /// learned copy or for having nothing to serve, is left to the bootstrap task
    pub fn boot_v2_response(&self) -> Result<Bytes, RPCError> {
        let routing_table = self.routing_table();
        let routing_domain = RoutingDomain::PublicInternet;
        let cur_ts = Timestamp::now();
        let cache = routing_table.get_served_bootstrap_cache(routing_domain);
        if cache.recheck_due(cur_ts) {
            routing_table.request_bootstrap_recheck(routing_domain);
        }
        let payload = cache.served_payload(cur_ts);

        // Own peer info first, then the payload's nodes, then reliable direct nodes
        let mut peers = Vec::<Arc<PeerInfo>>::new();
        let mut seen = HashSet::<NodeId>::new();
        let mut push = |pi: Arc<PeerInfo>| {
            if pi.is_expired(cur_ts) || pi.node_ids().iter().any(|id| seen.contains(id)) {
                return;
            }
            seen.extend(pi.node_ids().iter().cloned());
            peers.push(pi);
        };
        if let Some(pi) = routing_table.get_published_peer_info(routing_domain) {
            push(pi);
        }
        if let Some(payload) = &payload {
            for bsn in payload.payload().bootstrap_nodes() {
                for node_id in bsn.node_ids().iter() {
                    let Some(nr) = routing_table.lookup_node_id(node_id.clone()).ok().flatten()
                    else {
                        continue;
                    };
                    if let Some(pi) = nr.get_peer_info(routing_domain) {
                        push(pi);
                        break;
                    }
                }
            }
        }
        for nr in self.find_bootstrap_nodes_filtered(2) {
            if let Some(pi) = nr.get_peer_info(routing_domain) {
                push(pi);
            }
        }

        // Fill up to the cap by estimate, then trim to the encoded truth
        let payload_bytes = payload.as_ref().map(|p| p.bytes().clone());
        let mut budget = MAX_MESSAGE_SIZE
            .saturating_sub(B02T_MAGIC.len())
            .saturating_sub(payload_bytes.as_ref().map(|b| b.len()).unwrap_or(0))
            .saturating_sub(BOOT_V2_PEER_SIZE_ALLOWANCE);
        let mut kept = Vec::with_capacity(peers.len().min(MAX_BOOTSTRAP_PEERS));
        for pi in peers {
            let cost =
                pi.node_info_message().len() + pi.signatures().len() * BOOT_V2_PEER_SIZE_ALLOWANCE;
            if kept.len() >= MAX_BOOTSTRAP_PEERS || cost > budget {
                break;
            }
            budget -= cost;
            kept.push(pi);
        }
        loop {
            let encoded = encode_boot_v2_response(payload_bytes.as_deref(), &kept)?;
            if encoded.len() <= MAX_MESSAGE_SIZE || kept.pop().is_none() {
                return Ok(encoded);
            }
        }
    }

    /// Direct bootstrap v2 request handler
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "net", skip(self), ret, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn handle_boot_v2_request(&self, flow: Flow) -> EyreResult<NetworkResult<()>> {
        let response = self
            .boot_v2_response()
            .map_err(|e| eyre!("B02T response could not be built: {}", e))?;
        veilid_log!(self trace "B02T response: {} bytes", response.len());

        let net = self.net();
        match pin_future_closure!(net.send_data_to_existing_flow(
            flow,
            response,
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

    /// Decode a reply's body, the bytes after the magic. Peers that fail to decode are dropped
    /// one at a time; the payload bytes are kept exactly as they arrived
    pub(in crate::network_manager) fn decode_boot_v2_response(
        &self,
        body: &[u8],
    ) -> EyreResult<BootV2Response> {
        let decode_context = RPCDecodeContext {
            registry: self.registry(),
            origin_routing_domain: RoutingDomain::PublicInternet,
        };
        let mut cursor = std::io::Cursor::new(body);
        let reader = capnp::serialize_packed::read_message(
            &mut cursor,
            capnp::message::ReaderOptions::new(),
        )
        .wrap_err("bad B02T response message")?;
        let reader = reader
            .get_root::<veilid_capnp::boot_v2_response::Reader>()
            .wrap_err("bad B02T response root")?;

        let payload_bytes = reader.get_payload().wrap_err("bad B02T payload")?;
        let payload = (!payload_bytes.is_empty()).then(|| Bytes::copy_from_slice(payload_bytes));

        let peers_reader = reader.get_peers().wrap_err("bad B02T peers")?;
        if peers_reader.len() as usize > MAX_BOOTSTRAP_PEERS {
            bail!("too many peers in B02T response: {}", peers_reader.len());
        }
        let mut peers = Vec::with_capacity(peers_reader.len() as usize);
        for peer_reader in peers_reader {
            match decode_peer_info(&decode_context, &peer_reader) {
                Ok(pi) => peers.push(pi),
                Err(e) => {
                    veilid_log!(self debug "Dropping undecodable bootstrap peer: {}", e);
                }
            }
        }

        Ok(BootV2Response { payload, peers })
    }
}

/// Encode a reply from the payload bytes as held and verified peer infos
fn encode_boot_v2_response(
    payload: Option<&[u8]>,
    peers: &[Arc<PeerInfo>],
) -> Result<Bytes, RPCError> {
    let mut message = ::capnp::message::Builder::new_default();
    let mut builder = message.init_root::<veilid_capnp::boot_v2_response::Builder>();
    builder.set_payload(payload.unwrap_or_default());
    let mut peers_builder = builder.reborrow().init_peers(
        peers
            .len()
            .try_into()
            .map_err(RPCError::map_invalid_format("out of bound error"))?,
    );
    for (i, pi) in peers.iter().enumerate() {
        encode_peer_info(
            &UnverifiedPeerInfo::from_verified(pi),
            &mut peers_builder.reborrow().get(
                i.try_into()
                    .map_err(RPCError::map_invalid_format("out of bound error"))?,
            ),
        )?;
    }
    let body = canonical_message_builder_to_bytes_writer_packed(message, |size| {
        BytesWriter::with_capacity(size)
    })?
    .into_inner();
    let mut out = BytesMut::with_capacity(B02T_MAGIC.len() + body.len());
    out.extend_from_slice(B02T_MAGIC);
    out.extend_from_slice(&body);
    Ok(out.freeze())
}
