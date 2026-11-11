use super::*;
use data_encoding::BASE64URL_NOPAD;

/// Version prefix of a payload line in config and caches
pub const BOOTSTRAP_PAYLOAD_VERSION: u8 = 2;

/// A payload with the operator's signatures, kept as the bytes that carry them
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBootstrapPayload {
    /// The packed SignedBootstrapPayload message exactly as signed or received
    bytes: Bytes,
    /// The payload message inside it, the bytes the signatures cover
    payload_message: Bytes,
    /// What those bytes say
    payload: BootstrapPayload,
    /// The operator's signatures over the payload message, one per crypto kind
    signatures: SignatureGroup,
}

impl SignedBootstrapPayload {
    /// Sign a payload with the bootstrap signing keypairs; none makes an unsigned payload
    pub fn try_new_signed(
        crypto: &Crypto,
        payload: BootstrapPayload,
        signing_key_pairs: &[KeyPair],
    ) -> VeilidAPIResult<Self> {
        let payload_message = payload.encode_message()?;
        let signatures = SignatureGroup::from(crypto.generate_signatures(
            &payload_message,
            signing_key_pairs,
            |_kp, sig| sig,
        )?);

        let mut message = ::capnp::message::Builder::new_default();
        let mut builder = message.init_root::<veilid_capnp::signed_bootstrap_payload::Builder>();
        builder.set_payload_message(&payload_message);
        let mut sigs_builder = builder.reborrow().init_signatures(
            signatures
                .len()
                .try_into()
                .map_err(RPCError::map_invalid_format("out of bound error"))?,
        );
        for (i, sig) in signatures.iter().enumerate() {
            encode_signature(
                sig,
                &mut sigs_builder.reborrow().get(
                    i.try_into()
                        .map_err(RPCError::map_invalid_format("out of bound error"))?,
                ),
            );
        }
        let bytes = canonical_message_builder_to_bytes_writer_packed(message, |size| {
            BytesWriter::with_capacity(size)
        })?
        .into_inner()
        .freeze();

        Ok(Self {
            bytes,
            payload_message,
            payload,
            signatures,
        })
    }

    /// Decode the wire or line form. Signatures are read, not checked: see `verify`
    pub fn try_new_from_bytes(bytes: Bytes) -> VeilidAPIResult<Self> {
        let mut cursor = std::io::Cursor::new(bytes.as_ref());
        let reader = capnp::serialize_packed::read_message(
            &mut cursor,
            capnp::message::ReaderOptions::new(),
        )
        .map_err(|e| {
            VeilidAPIError::parse_error(format!("bad signed bootstrap payload: {}", e), "")
        })?;
        let reader = reader
            .get_root::<veilid_capnp::signed_bootstrap_payload::Reader>()
            .map_err(VeilidAPIError::internal)?;

        let payload_message = Bytes::copy_from_slice(
            reader
                .get_payload_message()
                .map_err(VeilidAPIError::internal)?,
        );
        let payload = BootstrapPayload::decode_message(&payload_message)?;

        let sigs_reader = reader.get_signatures().map_err(VeilidAPIError::internal)?;
        if sigs_reader.len() as usize > MAX_CRYPTO_KINDS {
            apibail_parse_error!("too many bootstrap payload signatures", sigs_reader.len());
        }
        let mut signatures = SignatureGroup::new();
        for sig_reader in sigs_reader {
            let Some(sig) = decode_signature(&sig_reader).ignore_ok()? else {
                continue;
            };
            signatures.add(sig);
        }

        Ok(Self {
            bytes,
            payload_message,
            payload,
            signatures,
        })
    }

    /// The config and cache form: `2|<base64url of the packed message>`
    pub fn try_new_from_line(line: &str) -> VeilidAPIResult<Self> {
        let line = line.trim();
        let Some((version, encoded)) = line.split_once('|') else {
            apibail_parse_error!("not a bootstrap payload line", line);
        };
        if version.parse::<u8>().ok() != Some(BOOTSTRAP_PAYLOAD_VERSION) {
            apibail_parse_error!("not a version 2 bootstrap payload line", line);
        }
        let bytes = BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|e| VeilidAPIError::parse_error(format!("bad payload line: {}", e), line))?;
        Self::try_new_from_bytes(Bytes::from(bytes))
    }

    pub fn to_line(&self) -> String {
        format!(
            "{}|{}",
            BOOTSTRAP_PAYLOAD_VERSION,
            BASE64URL_NOPAD.encode(&self.bytes)
        )
    }

    /// Whether a line declares the payload version, whatever else is in it
    pub fn is_payload_line(line: &str) -> bool {
        line.trim()
            .split_once('|')
            .and_then(|x| x.0.parse::<u8>().ok())
            == Some(BOOTSTRAP_PAYLOAD_VERSION)
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn payload(&self) -> &BootstrapPayload {
        &self.payload
    }

    /// A payload is trusted when a configured key's signature over it verifies
    pub fn verify(&self, crypto: &Crypto, bootstrap_keys: &[PublicKey]) -> VeilidAPIResult<()> {
        for key in bootstrap_keys {
            let Some(sig) = self.signatures.get(key.kind()) else {
                continue;
            };
            if let Some(valid_keys) = crypto.verify_signatures(
                std::slice::from_ref(key),
                &self.payload_message,
                std::slice::from_ref(&sig),
            )? {
                if valid_keys.contains(key) {
                    return Ok(());
                }
            }
        }
        apibail_generic!("bootstrap payload is not signed by a trusted bootstrap key");
    }
}
