use super::*;

pub const MAX_BOOTSTRAP_NODES: usize = veilid_capnp::MAX_BOOTSTRAP_NODES as usize;
/// What a payload's cache ttl of zero means
pub const DEFAULT_BOOTSTRAP_CACHE_TTL: TimestampDuration =
    TimestampDuration::new_secs(veilid_capnp::DEFAULT_BOOTSTRAP_CACHE_TTL_SECS);

/// The operator's statement of a network's bootstrap servers
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapPayload {
    /// When the operator signed it
    timestamp: Timestamp,
    /// When it stops being accepted, None for never
    expiration: Option<Timestamp>,
    /// How long a learned copy is served before its source is re-checked, None for the default
    cache_ttl: Option<TimestampDuration>,
    /// The bootstrap servers
    bootstrap_nodes: Vec<BootstrapNode>,
}

impl BootstrapPayload {
    pub fn new(
        timestamp: Timestamp,
        expiration: Option<Timestamp>,
        cache_ttl: Option<TimestampDuration>,
        bootstrap_nodes: Vec<BootstrapNode>,
    ) -> Self {
        Self {
            timestamp,
            expiration,
            cache_ttl,
            bootstrap_nodes,
        }
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn expiration(&self) -> Option<Timestamp> {
        self.expiration
    }

    pub fn is_expired(&self, cur_ts: Timestamp) -> bool {
        self.expiration.is_some_and(|exp| cur_ts >= exp)
    }

    /// The ttl the payload asks for, or the default when it leaves it unset
    pub fn cache_ttl(&self) -> TimestampDuration {
        self.cache_ttl.unwrap_or(DEFAULT_BOOTSTRAP_CACHE_TTL)
    }

    pub fn bootstrap_nodes(&self) -> &[BootstrapNode] {
        &self.bootstrap_nodes
    }

    /// Whether a peer's ids name one of the bootstrap servers
    pub fn names_node(&self, node_ids: &NodeIdGroup) -> bool {
        self.bootstrap_nodes
            .iter()
            .any(|bsn| bsn.node_ids().contains_any_from_iter(node_ids.iter()))
    }

    pub(super) fn encode_message(&self) -> Result<Bytes, RPCError> {
        let mut message = ::capnp::message::Builder::new_default();
        let mut builder = message.init_root::<veilid_capnp::bootstrap_payload::Builder>();
        builder.set_timestamp(self.timestamp.as_u64());
        builder.set_expiration(self.expiration.map(|x| x.as_u64()).unwrap_or_default());
        builder.set_cache_ttl(self.cache_ttl.map(|x| x.as_u64()).unwrap_or_default());
        let mut bss_builder = builder.reborrow().init_bootstrap_nodes(
            self.bootstrap_nodes
                .len()
                .try_into()
                .map_err(RPCError::map_invalid_format("out of bound error"))?,
        );
        for (i, bsn) in self.bootstrap_nodes.iter().enumerate() {
            bsn.encode(
                &mut bss_builder.reborrow().get(
                    i.try_into()
                        .map_err(RPCError::map_invalid_format("out of bound error"))?,
                ),
            )?;
        }
        Ok(
            canonical_message_builder_to_bytes_writer_packed(message, |size| {
                BytesWriter::with_capacity(size)
            })?
            .into_inner()
            .freeze(),
        )
    }

    /// A bootstrap server this build cannot decode at all is dropped; the payload stands
    pub(super) fn decode_message(payload_message: &[u8]) -> Result<Self, RPCError> {
        let mut cursor = std::io::Cursor::new(payload_message);
        let reader = capnp::serialize_packed::read_message(
            &mut cursor,
            capnp::message::ReaderOptions::new(),
        )
        .map_err(RPCError::map_protocol("bad bootstrap payload message"))?;
        let reader = reader
            .get_root::<veilid_capnp::bootstrap_payload::Reader>()
            .map_err(RPCError::protocol)?;

        let timestamp = Timestamp::new(reader.get_timestamp());
        let expiration = Some(Timestamp::new(reader.get_expiration())).filter(|x| !x.is_zero());
        let cache_ttl =
            Some(TimestampDuration::new(reader.get_cache_ttl())).filter(|x| !x.is_zero());

        rpc_ignore_missing_property!(reader, bootstrap_nodes);
        let bss_reader = reader.get_bootstrap_nodes()?;
        rpc_ignore_max_len!(bss_reader, MAX_BOOTSTRAP_NODES);
        let mut bootstrap_nodes = Vec::with_capacity(bss_reader.len() as usize);
        for bsn_reader in bss_reader {
            let Some(bsn) = BootstrapNode::decode(&bsn_reader).ignore_ok()? else {
                continue;
            };
            bootstrap_nodes.push(bsn);
        }

        Ok(Self {
            timestamp,
            expiration,
            cache_ttl,
            bootstrap_nodes,
        })
    }
}

/// Parse an operator-facing lifetime: `<N>y`, `<N>mo`, `<N>d`, combinable, or `none`/`0` for no
/// expiration. A year is 365 days and a month 30
#[cfg_attr(
    not(any(feature = "debug-api", test, feature = "test-util")),
    expect(dead_code)
)]
pub fn parse_record_lifetime(s: &str) -> Option<Option<TimestampDuration>> {
    let s = s.trim().to_ascii_lowercase();
    if s == "none" || s == "0" {
        return Some(None);
    }
    const DAY_US: u64 = 86_400_000_000;
    let mut total: u64 = 0;
    let mut digits: u64 = 0;
    let mut have_digits = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(d) = c.to_digit(10) {
            digits = digits.checked_mul(10)?.checked_add(d as u64)?;
            have_digits = true;
            continue;
        }
        if !have_digits {
            return None;
        }
        let days = match c {
            'y' => 365u64,
            'd' => 1u64,
            'm' if chars.peek() == Some(&'o') => {
                chars.next();
                30u64
            }
            _ => return None,
        };
        total = total.checked_add(digits.checked_mul(days)?.checked_mul(DAY_US)?)?;
        digits = 0;
        have_digits = false;
    }
    if have_digits || total == 0 {
        return None;
    }
    Some(Some(TimestampDuration::new(total)))
}
