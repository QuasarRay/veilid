use super::*;

/// What this node holds to answer bootstrap requests, kept across restarts
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapCache {
    /// The newest accepted payload, as its line
    #[serde(default)]
    payload_line: Option<String>,
    /// When that payload was signed: the floor a later payload must reach
    #[serde(default)]
    payload_timestamp: Option<Timestamp>,
    /// When that payload stops being served, None for never
    #[serde(default)]
    payload_expiration: Option<Timestamp>,
    /// How long a learned copy is served before its source is re-checked
    #[serde(default)]
    cache_ttl: Option<TimestampDuration>,
    /// When a learned copy arrived, None for a copy from config
    #[serde(default)]
    received_at: Option<Timestamp>,
    /// When the source was last asked again, whatever it answered
    #[serde(default)]
    rechecked_at: Option<Timestamp>,
    /// Legacy record lines served to B01T requests, verbatim
    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    #[serde(default)]
    record_strings: Vec<String>,
    /// The legacy lines parsed, so the peer list needs no parsing on the serve path
    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    #[serde(default)]
    records: Vec<BootstrapRecord>,
}

impl BootstrapCache {
    /// A cache holding one payload; `received_at` is None for a payload that came from config
    pub fn from_payload(payload: &SignedBootstrapPayload, received_at: Option<Timestamp>) -> Self {
        Self {
            payload_line: Some(payload.to_line()),
            payload_timestamp: Some(payload.payload().timestamp()),
            payload_expiration: payload.payload().expiration(),
            cache_ttl: Some(payload.payload().cache_ttl()),
            received_at,
            rechecked_at: None,
            #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
            record_strings: vec![],
            #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
            records: vec![],
        }
    }

    /// A cache holding legacy record lines only
    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    pub fn from_records(record_strings: Vec<String>, records: Vec<BootstrapRecord>) -> Self {
        let mut this = Self {
            record_strings,
            records,
            ..Default::default()
        };
        this.normalize_records();
        this
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
        if !self.record_strings.is_empty() {
            return false;
        }
        self.payload_line.is_none()
    }

    pub fn payload_timestamp(&self) -> Option<Timestamp> {
        self.payload_timestamp
    }

    pub fn payload_expiration(&self) -> Option<Timestamp> {
        self.payload_expiration
    }

    pub fn cache_ttl(&self) -> Option<TimestampDuration> {
        self.cache_ttl
    }

    pub fn received_at(&self) -> Option<Timestamp> {
        self.received_at
    }

    /// Whether a payload is held that has not expired
    pub fn serves_payload(&self, cur_ts: Timestamp) -> bool {
        self.payload_line.is_some() && self.payload_expiration.is_none_or(|exp| cur_ts < exp)
    }

    /// The payload to serve, decoded from its line, while it has not expired
    pub fn served_payload(&self, cur_ts: Timestamp) -> Option<SignedBootstrapPayload> {
        if !self.serves_payload(cur_ts) {
            return None;
        }
        let line = self.payload_line.as_ref()?;
        SignedBootstrapPayload::try_new_from_line(line).ok()
    }

    /// Whether the source should be asked again: nothing is left to serve, or a learned copy
    /// has been served past its ttl. Either comes due once per cache period
    pub fn recheck_due(&self, cur_ts: Timestamp) -> bool {
        // A config copy still being served is the operator's to replace
        if self.received_at.is_none() && self.serves_payload(cur_ts) {
            return false;
        }
        let ttl = self.cache_ttl.unwrap_or(DEFAULT_BOOTSTRAP_CACHE_TTL);
        self.received_at
            .max(self.rechecked_at)
            .is_none_or(|last| cur_ts >= last.later(ttl))
    }

    /// Start a new cache period after a re-check, whether or not anything changed
    pub fn mark_rechecked(&mut self, cur_ts: Timestamp) {
        self.rechecked_at = Some(cur_ts);
    }

    /// Fold another cache in: the newer payload wins, with a config copy taking ties
    pub fn union(&mut self, other: BootstrapCache) {
        let other_newer = match (self.payload_timestamp, other.payload_timestamp) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(mine), Some(theirs)) => {
                theirs > mine || (theirs == mine && other.received_at.is_none())
            }
        };
        if other_newer {
            self.payload_line = other.payload_line;
            self.payload_timestamp = other.payload_timestamp;
            self.payload_expiration = other.payload_expiration;
            self.cache_ttl = other.cache_ttl;
            self.received_at = other.received_at;
        }
        self.rechecked_at = self.rechecked_at.max(other.rechecked_at);
        #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
        {
            self.record_strings.extend(other.record_strings);
            self.records.extend(other.records);
            self.normalize_records();
        }
    }

    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    pub fn record_strings(&self) -> &[String] {
        &self.record_strings
    }

    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    pub fn records(&self) -> &[BootstrapRecord] {
        &self.records
    }

    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    fn normalize_records(&mut self) {
        self.record_strings.sort_unstable();
        self.record_strings.dedup();
        self.record_strings.truncate(MAX_BOOTSTRAP_RECORD_STRINGS);
        self.records = BootstrapRecord::merge_all(core::mem::take(&mut self.records));
    }
}
