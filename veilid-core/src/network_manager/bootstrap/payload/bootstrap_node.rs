use super::*;
use data_encoding::BASE64URL_NOPAD;

/// Prefix of the line a host prints for the operator to sign into a payload
pub const BOOTSTRAP_NODE_LINE_PREFIX: &str = "node|";

pub const MAX_BOOTSTRAP_NODE_IDS: usize = veilid_capnp::MAX_BOOTSTRAP_NODE_IDS as usize;
pub const MAX_BOOTSTRAP_NODE_DIAL_INFOS: usize = veilid_capnp::MAX_DIAL_INFO_DETAILS as usize;

/// One bootstrap server as the operator signs it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapNode {
    /// The node's ids per crypto kind
    node_ids: NodeIdGroup,
    /// Where B02T reaches it when no peer info is at hand
    dial_infos: Vec<DialInfo>,
}

impl BootstrapNode {
    pub fn new(node_ids: NodeIdGroup, mut dial_infos: Vec<DialInfo>) -> Self {
        dial_infos.sort_unstable();
        dial_infos.dedup();
        Self {
            node_ids,
            dial_infos,
        }
    }

    pub fn node_ids(&self) -> &NodeIdGroup {
        &self.node_ids
    }

    pub fn dial_infos(&self) -> &[DialInfo] {
        &self.dial_infos
    }

    /// The line a host prints: `node|<base64url of the packed message>`
    pub fn to_line(&self) -> VeilidAPIResult<String> {
        let mut message = ::capnp::message::Builder::new_default();
        let mut builder = message.init_root::<veilid_capnp::bootstrap_node::Builder>();
        self.encode(&mut builder)?;
        let bytes = canonical_message_builder_to_bytes_writer_packed(message, |size| {
            BytesWriter::with_capacity(size)
        })?
        .into_inner()
        .freeze();
        Ok(format!(
            "{}{}",
            BOOTSTRAP_NODE_LINE_PREFIX,
            BASE64URL_NOPAD.encode(&bytes)
        ))
    }

    pub fn try_new_from_line(line: &str) -> VeilidAPIResult<Self> {
        let Some(encoded) = line.trim().strip_prefix(BOOTSTRAP_NODE_LINE_PREFIX) else {
            apibail_parse_error!("not a bootstrap node line", line);
        };
        let bytes = BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|e| VeilidAPIError::parse_error(format!("bad node line: {}", e), line))?;
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let reader = capnp::serialize_packed::read_message(
            &mut cursor,
            capnp::message::ReaderOptions::new(),
        )
        .map_err(|e| VeilidAPIError::parse_error(format!("bad node line: {}", e), line))?;
        let node_reader = reader
            .get_root::<veilid_capnp::bootstrap_node::Reader>()
            .map_err(VeilidAPIError::internal)?;
        Ok(Self::decode(&node_reader)?)
    }

    pub(super) fn encode(
        &self,
        builder: &mut veilid_capnp::bootstrap_node::Builder,
    ) -> Result<(), RPCError> {
        let mut ids_builder = builder.reborrow().init_node_ids(
            self.node_ids
                .len()
                .try_into()
                .map_err(RPCError::map_invalid_format("out of bound error"))?,
        );
        for (i, node_id) in self.node_ids.iter().enumerate() {
            encode_node_id(
                node_id,
                &mut ids_builder.reborrow().get(
                    i.try_into()
                        .map_err(RPCError::map_invalid_format("out of bound error"))?,
                ),
            );
        }
        let mut dis_builder = builder.reborrow().init_dial_infos(
            self.dial_infos
                .len()
                .try_into()
                .map_err(RPCError::map_invalid_format("out of bound error"))?,
        );
        for (i, dial_info) in self.dial_infos.iter().enumerate() {
            encode_dial_info(
                dial_info,
                &mut dis_builder.reborrow().get(
                    i.try_into()
                        .map_err(RPCError::map_invalid_format("out of bound error"))?,
                ),
            )?;
        }
        Ok(())
    }

    /// Unknown dial info protocols are dropped, the rest kept, as peer info decodes them
    pub(super) fn decode(reader: &veilid_capnp::bootstrap_node::Reader) -> Result<Self, RPCError> {
        rpc_ignore_missing_property!(reader, node_ids);
        let ids_reader = reader.get_node_ids()?;
        rpc_ignore_max_len!(ids_reader, MAX_BOOTSTRAP_NODE_IDS);
        let mut node_ids = NodeIdGroup::new();
        for id_reader in ids_reader {
            let Some(node_id) = decode_node_id(&id_reader).ignore_ok()? else {
                continue;
            };
            node_ids.add(node_id);
        }
        if node_ids.is_empty() {
            return Err(RPCError::protocol("bootstrap node has no node ids"));
        }

        rpc_ignore_missing_property!(reader, dial_infos);
        let dis_reader = reader.get_dial_infos()?;
        rpc_ignore_max_len!(dis_reader, MAX_BOOTSTRAP_NODE_DIAL_INFOS);
        let mut dial_infos = Vec::with_capacity(dis_reader.len() as usize);
        for di_reader in dis_reader {
            let Some(dial_info) = decode_dial_info(&di_reader).ignore_ok()? else {
                continue;
            };
            dial_infos.push(dial_info);
        }
        Ok(Self::new(node_ids, dial_infos))
    }
}
