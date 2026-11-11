use super::*;

impl_veilid_log_facility!("net");

/// Legacy record line version an unsigned TXT record carries
pub const BOOTSTRAP_TXT_VERSION_0: u8 = 0;
/// Legacy record line version a signed TXT record carries
pub const BOOTSTRAP_TXT_VERSION_1: u8 = 1;

/// The legacy record line versions this build still parses and serves
pub const SUPPORTED_BOOTSTRAP_RECORD_VERSIONS: &[u8] = &[
    #[cfg(feature = "enable-bootstrap-v0")]
    BOOTSTRAP_TXT_VERSION_0,
    #[cfg(feature = "enable-bootstrap-v1")]
    BOOTSTRAP_TXT_VERSION_1,
];

/// One bootstrap server as a legacy record line describes it. Parsed only to serve the line
/// onward and name its peer; nothing in it is resolved or dialed by this build
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapRecord {
    /// The node's public keys
    public_keys: PublicKeyGroup,
    /// The envelope versions the node speaks
    envelope_support: Vec<EnvelopeVersion>,
    /// The node's dial info; empty when parsed from a line, full when generating one
    dial_info_details: Vec<DialInfoDetail>,
    /// When a v1 line was signed, in seconds since the epoch
    timestamp_secs: Option<u64>,
    /// Fields between the timestamp and the signature, covered by the signature
    extra: Vec<String>,
}

impl BootstrapRecord {
    pub fn new(
        public_keys: PublicKeyGroup,
        mut envelope_support: Vec<EnvelopeVersion>,
        mut dial_info_details: Vec<DialInfoDetail>,
        timestamp_secs: Option<u64>,
        extra: Vec<String>,
    ) -> Self {
        envelope_support.sort_unstable();
        dial_info_details.sort_unstable();

        Self {
            public_keys,
            envelope_support,
            dial_info_details,
            timestamp_secs,
            extra,
        }
    }

    pub fn public_keys(&self) -> &PublicKeyGroup {
        &self.public_keys
    }
    pub fn envelope_support(&self) -> &[EnvelopeVersion] {
        &self.envelope_support
    }
    pub fn dial_info_details(&self) -> &[DialInfoDetail] {
        &self.dial_info_details
    }
    pub fn timestamp_secs(&self) -> Option<u64> {
        self.timestamp_secs
    }
    #[expect(dead_code)]
    pub fn extra(&self) -> &[String] {
        &self.extra
    }

    /// Merge records that share any public key into one record apiece
    pub fn merge_all(records: Vec<BootstrapRecord>) -> Vec<BootstrapRecord> {
        let mut merged: Vec<BootstrapRecord> = Vec::new();
        for mut bsrec in records {
            let mut mbi = 0;
            while mbi < merged.len() {
                if merged[mbi]
                    .public_keys()
                    .contains_any_from_iter(bsrec.public_keys().iter())
                {
                    // Merge record, pop this one out
                    let mbr = merged.remove(mbi);
                    bsrec.merge(mbr);
                } else {
                    // No overlap, go to next record
                    mbi += 1;
                }
            }
            merged.push(bsrec);
        }
        merged
    }

    pub fn merge(&mut self, other: BootstrapRecord) {
        self.public_keys.add_all_from_iter(other.public_keys.iter());
        for x in other.envelope_support {
            if !self.envelope_support.contains(&x) {
                self.envelope_support.push(x);
                self.envelope_support.sort_unstable();
            }
        }
        for did in other.dial_info_details {
            if !self.dial_info_details.contains(&did) {
                self.dial_info_details.push(did);
            }
        }
        self.dial_info_details.sort_unstable();
        if let Some(ts) = self.timestamp_secs.as_mut() {
            if let Some(other_ts) = other.timestamp_secs {
                // Use earliest timestamp if merging
                ts.min_assign(other_ts);
            }
        } else {
            self.timestamp_secs = other.timestamp_secs;
        }
        self.extra.extend_from_slice(&other.extra);
    }

    /// The fields every line version shares. Every dial info is written relative to the one
    /// `hostname`, which the operator names: it is what readers resolve
    fn to_vcommon_string(&self, hostname: &str) -> EyreResult<String> {
        let valid_envelope_versions = self
            .envelope_support()
            .iter()
            .map(|x| {
                if x.bytes()[0..3] == *b"ENV" {
                    x.to_string().split_off(3)
                } else {
                    x.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(",");

        let public_keys = self
            .public_keys
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");

        if hostname.trim().is_empty() {
            bail!("A hostname is required for a bootstrap record line");
        }
        let mut short_urls: Vec<String> = self
            .dial_info_details()
            .iter()
            .map(|did| to_short_dial_info(&did.dial_info).short_url)
            .collect();
        if short_urls.is_empty() {
            bail!("No dial info for bootstrap host");
        }
        short_urls.sort_unstable();
        short_urls.dedup();

        Ok(format!(
            "|{}|{}|{}|{}",
            valid_envelope_versions,
            public_keys,
            hostname.trim(),
            short_urls.join(",")
        ))
    }

    #[cfg(feature = "enable-bootstrap-v0")]
    pub fn to_v0_string(&self, hostname: &str) -> EyreResult<String> {
        let vcommon = self.to_vcommon_string(hostname)?;
        Ok(format!("{}{}", BOOTSTRAP_TXT_VERSION_0, vcommon))
    }

    #[cfg(feature = "enable-bootstrap-v1")]
    pub fn to_v1_string(
        &self,
        network_manager: &NetworkManager,
        hostname: &str,
        signing_key_pair: KeyPair,
    ) -> EyreResult<String> {
        let vcommon = self.to_vcommon_string(hostname)?;
        let Some(ts) = self.timestamp_secs() else {
            bail!("timestamp required for bootstrap v1 format");
        };
        let mut v1 = format!("{}{}|{}|", BOOTSTRAP_TXT_VERSION_1, vcommon, ts);

        let crypto = network_manager.crypto();
        let sig =
            match crypto.generate_signatures(v1.as_bytes(), &[signing_key_pair], |_kp, sig| {
                sig.to_string()
            }) {
                Ok(v) => {
                    let Some(sig) = v.first().cloned() else {
                        bail!("No signature generated");
                    };
                    sig
                }
                Err(e) => {
                    bail!("Failed to generate signature: {}", e);
                }
            };

        v1 += &sig;
        Ok(v1)
    }

    /// Parse a v0 line for serving: keys and envelope support, no dial info
    #[cfg(feature = "enable-bootstrap-v0")]
    pub fn try_new_from_v0_str(record_str: &str) -> EyreResult<BootstrapRecord> {
        let fields: Vec<String> = record_str
            .trim()
            .split('|')
            .map(|x| x.trim().to_owned())
            .collect();
        if Self::line_version(&fields)? != BOOTSTRAP_TXT_VERSION_0 {
            bail!("not a v0 bootstrap record");
        }
        if fields.len() != 5 {
            bail!("invalid number of fields in bootstrap v0 txt record");
        }
        Ok(BootstrapRecord::new(
            Self::parse_public_keys(&fields[2])?,
            Self::parse_envelope_support(&fields[1])?,
            vec![],
            None,
            vec![],
        ))
    }

    /// Parse a v1 line for serving, checking its signature against `signing_keys` when there
    /// are any. The signature covers the line exactly as written, up to itself
    #[cfg(feature = "enable-bootstrap-v1")]
    pub fn try_new_from_v1_str(
        network_manager: &NetworkManager,
        record_str: &str,
        signing_keys: &[PublicKey],
    ) -> EyreResult<BootstrapRecord> {
        let record_str = record_str.trim();
        let fields: Vec<String> = record_str.split('|').map(|x| x.trim().to_owned()).collect();
        if Self::line_version(&fields)? != BOOTSTRAP_TXT_VERSION_1 {
            bail!("not a v1 bootstrap record");
        }
        if fields.len() < 7 {
            bail!("invalid number of fields in bootstrap v1 txt record");
        }

        let sigstring = fields.last().unwrap_or_log();
        let sig =
            Signature::from_str(sigstring).wrap_err("invalid signature for bootstrap v1 record")?;
        let signed_str = &record_str[0..record_str.len() - sigstring.len()];

        if !signing_keys.is_empty() {
            let mut validated = false;
            for key in signing_keys {
                if let Some(valid_keys) = network_manager.crypto().verify_signatures(
                    std::slice::from_ref(key),
                    signed_str.as_bytes(),
                    std::slice::from_ref(&sig),
                )? {
                    if valid_keys.contains(key) {
                        validated = true;
                        break;
                    }
                }
            }
            if !validated {
                bail!(
                    "bootstrap record did not have valid signature: {}",
                    record_str
                );
            }
        }

        let secs_u64 = u64::from_str(&fields[5]).wrap_err("invalid timestamp")?;
        let extra = fields[6..fields.len() - 1].to_vec();

        Ok(BootstrapRecord::new(
            Self::parse_public_keys(&fields[2])?,
            Self::parse_envelope_support(&fields[1])?,
            vec![],
            Some(secs_u64),
            extra,
        ))
    }

    fn line_version(fields: &[String]) -> EyreResult<u8> {
        fields
            .first()
            .and_then(|x| x.parse::<u8>().ok())
            .ok_or_else(|| eyre!("invalid version in bootstrap record"))
    }

    fn parse_envelope_support(field: &str) -> EyreResult<Vec<EnvelopeVersion>> {
        let mut envelope_support = Vec::new();
        for ess in field.split(',') {
            let ess = ess.trim();
            let es = if ess.len() == 1 {
                let mut envb: [u8; 4] = *b"ENV0";
                envb[3] = ess.as_bytes()[0];
                EnvelopeVersion::from(envb)
            } else if ess.len() == 4 {
                ess.parse::<EnvelopeVersion>()
                    .map_err(|e| eyre!("invalid envelope version in bootstrap record: {}", e))?
            } else {
                bail!(
                    "invalid envelope version length in bootstrap record: {}",
                    ess
                );
            };
            envelope_support.push(es);
        }
        envelope_support.sort_unstable();
        envelope_support.dedup();
        Ok(envelope_support)
    }

    fn parse_public_keys(field: &str) -> EyreResult<PublicKeyGroup> {
        let mut public_keys = PublicKeyGroup::new();
        for public_key_str in field.split(',') {
            let public_key_str = public_key_str.trim();
            let public_key = PublicKey::from_str(public_key_str).map_err(|e| {
                eyre!(
                    "Invalid public key in bootstrap record {}: {}",
                    public_key_str,
                    e
                )
            })?;
            public_keys.add(public_key);
        }
        Ok(public_keys)
    }
}

impl NetworkManager {
    /// The version a legacy line declares, if this build serves it
    fn bootstrap_record_version(record_string: &str) -> Option<u8> {
        let version = record_string
            .trim()
            .split_once('|')
            .and_then(|x| u8::from_str(x.0).ok())?;
        SUPPORTED_BOOTSTRAP_RECORD_VERSIONS
            .contains(&version)
            .then_some(version)
    }

    /// The legacy lines in the config, parsed one at a time so one bad entry does not discard
    /// the rest. Returns the strings that parsed and the records they parsed to
    pub(super) fn parse_config_bootstrap_records(&self) -> (Vec<String>, Vec<BootstrapRecord>) {
        let (record_strings, signing_keys) = {
            let cfg = self.config();
            let rt = &cfg.network.routing_table;
            (rt.bootstrap_records.clone(), rt.bootstrap_keys.clone())
        };
        #[cfg(not(feature = "enable-bootstrap-v1"))]
        let _ = &signing_keys;

        let mut kept_strings = Vec::new();
        let mut records = Vec::new();
        for record_string in &record_strings {
            if SignedBootstrapPayload::is_payload_line(record_string) {
                continue;
            }
            let Some(version) = Self::bootstrap_record_version(record_string) else {
                veilid_log!(self warn "Ignoring unsupported configured bootstrap record: {}", record_string);
                continue;
            };
            let result = match version {
                #[cfg(feature = "enable-bootstrap-v0")]
                BOOTSTRAP_TXT_VERSION_0 => BootstrapRecord::try_new_from_v0_str(record_string),
                #[cfg(feature = "enable-bootstrap-v1")]
                BOOTSTRAP_TXT_VERSION_1 => {
                    BootstrapRecord::try_new_from_v1_str(self, record_string, &signing_keys)
                }
                _ => continue,
            };
            match result {
                Ok(record) => {
                    kept_strings.push(record_string.trim().to_owned());
                    records.push(record);
                }
                Err(e) => {
                    veilid_log!(self warn "Ignoring invalid configured bootstrap record: {}: {}", record_string, e);
                }
            }
        }

        (kept_strings, BootstrapRecord::merge_all(records))
    }
}
