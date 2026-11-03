use super::*;

use super::super::certificate_manager::ManagedCertificate;
use futures_rustls::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        ring::default_provider, verify_tls12_signature, verify_tls13_signature, CryptoProvider,
    },
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use web_transport_quinn::quinn::{
    self,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use web_transport_quinn::{RecvStream, SendStream, Session, ALPN};

impl_veilid_log_facility!("net");

const STREAM_LEN_PREFIX: usize = size_of::<u32>();

const MIN_WTD_DATAGRAM_SIZE: usize = 256;

const WTD_MAX_FRAGMENTS: usize = 8;

const WT_UNBOUND_FLUSH_GRACE_MS: u32 = 1000;

const WT_DATAGRAM_FLUSH_POLL_INTERVAL_MS: u32 = 5;

/// Peer-initiated bidirectional QUIC streams a conforming WebTransport peer needs: the HTTP/3
/// CONNECT stream that carries the handshake, plus the one WebTransport stream a WTS session
/// runs on. A WTD session opens none of the latter.
const WT_PEER_BIDI_STREAMS_NEEDED: u32 = 2;

/// Peer-initiated unidirectional QUIC streams the HTTP/3 handshake needs: the peer's control
/// stream carrying SETTINGS, plus the QPACK encoder and decoder streams a browser opens
/// unconditionally even though this server never reads them.
const WT_PEER_UNI_STREAMS_NEEDED: u32 = 3;

/// Doubling the protocol need leaves room for a peer that opens a spare stream, which then
/// waits on stream flow control instead of failing the session.
const WT_PEER_STREAM_MARGIN: u32 = 2;

const WT_MAX_PEER_BIDI_STREAMS: u32 = WT_PEER_BIDI_STREAMS_NEEDED * WT_PEER_STREAM_MARGIN;
const WT_MAX_PEER_UNI_STREAMS: u32 = WT_PEER_UNI_STREAMS_NEEDED * WT_PEER_STREAM_MARGIN;

/// Per-stream receive window: enough whole veilid messages in flight that a reader pausing
/// between messages does not stall the sender.
const WT_STREAM_RECEIVE_WINDOW: u64 = 4 * MAX_MESSAGE_SIZE as u64;

/// Connection-level receive window, which quinn otherwise leaves at `VarInt::MAX`. Sized so
/// the two streams the protocol actually reads can each hold a full stream window, which
/// bounds what a peer can pin in streams the accept path never reads.
const WT_CONNECTION_RECEIVE_WINDOW: u64 =
    WT_PEER_BIDI_STREAMS_NEEDED as u64 * WT_STREAM_RECEIVE_WINDOW;

/// Bound what one WebTransport peer can pin, on both the sessions we accept and the ones we
/// dial. quinn's defaults allow 100 peer-initiated streams of each kind against an unbounded
/// connection receive window, and the accept path reads at most one stream per session.
fn webtransport_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(WT_MAX_PEER_BIDI_STREAMS.into())
        .max_concurrent_uni_streams(WT_MAX_PEER_UNI_STREAMS.into())
        .stream_receive_window(
            quinn::VarInt::from_u64(WT_STREAM_RECEIVE_WINDOW).unwrap_or(quinn::VarInt::MAX),
        )
        .receive_window(
            quinn::VarInt::from_u64(WT_CONNECTION_RECEIVE_WINDOW).unwrap_or(quinn::VarInt::MAX),
        );
    Arc::new(transport)
}

/// QUIC long-header form bit (RFC 9000 §17.2): Initial/Handshake/0-RTT/Retry.
const QUIC_LONG_HEADER_FORM_BIT: u8 = 0x80;
/// QUIC short-header fixed bit (RFC 9000 §17.3): always set on 1-RTT packets.
const QUIC_SHORT_HEADER_FIXED_BIT: u8 = 0x40;
const QUIC_HEADER_BITS: u8 = QUIC_LONG_HEADER_FORM_BIT | QUIC_SHORT_HEADER_FIXED_BIT;

pub(in crate::network_manager) const fn accepts_datagram(datagram: &[u8]) -> bool {
    match datagram.first() {
        Some(&first_byte) => first_byte & QUIC_HEADER_BITS != 0,
        None => false,
    }
}

#[derive(Debug)]
pub(in crate::network_manager) struct CertificateHashVerifier {
    allowed_hashes: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl CertificateHashVerifier {
    pub(in crate::network_manager) fn new(
        allowed_hashes: Vec<[u8; 32]>,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            allowed_hashes,
            provider,
        }
    }
}

struct WebTransportCertHashMismatch {
    pinned: usize,
}

impl fmt::Display for WebTransportCertHashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "webtransport certificate hash mismatch: presented certificate matches none of the {} pinned dial-info hash(es) (likely stale or rotated dial info)",
            self.pinned
        )
    }
}

impl fmt::Debug for WebTransportCertHashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for WebTransportCertHashMismatch {}

impl ServerCertVerifier for CertificateHashVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let digest = hasher.finalize();
        if self
            .allowed_hashes
            .iter()
            .any(|h| h.as_slice() == digest.as_slice())
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                    WebTransportCertHashMismatch {
                        pinned: self.allowed_hashes.len(),
                    },
                ))),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(in crate::network_manager) fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(default_provider())
}

/// `EndpointConfig` for WebTransport endpoints that share the UDP port with raw UDP.
/// Disables QUIC bit greasing (RFC 9287). With greasing on (quinn's default) a short-header
/// packet may clear the fixed `0x40` bit, landing in `0x00..=0x3F` and colliding with raw-UDP's
/// `0x01` framing byte. With it off we do not advertise the transport parameter, so peers keep
/// the bit set toward us and the single-port demux stays a first-byte check.
pub(in crate::network_manager) fn webtransport_endpoint_config() -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.grease_quic_bit(false);
    config
}

pub(in crate::network_manager) fn build_client_config(
    allowed_hashes: Vec<[u8; 32]>,
) -> io::Result<quinn::ClientConfig> {
    let provider = crypto_provider();
    let verifier = CertificateHashVerifier::new(allowed_hashes, provider.clone());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(to_io_error_other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

    let quic_crypto = QuicClientConfig::try_from(crypto).map_err(to_io_error_other)?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(webtransport_transport_config());
    Ok(config)
}

pub(in crate::network_manager) fn build_client_config_ca() -> io::Result<quinn::ClientConfig> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    build_client_config_with_root_store(root_store)
}

pub(in crate::network_manager) fn cached_client_config_ca() -> io::Result<quinn::ClientConfig> {
    static CA_CONFIG: std::sync::OnceLock<quinn::ClientConfig> = std::sync::OnceLock::new();
    if let Some(config) = CA_CONFIG.get() {
        return Ok(config.clone());
    }
    let config = build_client_config_ca()?;
    Ok(CA_CONFIG.get_or_init(|| config).clone())
}

pub(in crate::network_manager) fn build_client_config_with_root_store(
    root_store: RootCertStore,
) -> io::Result<quinn::ClientConfig> {
    let provider = crypto_provider();
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(to_io_error_other)?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

    let quic_crypto = QuicClientConfig::try_from(crypto).map_err(to_io_error_other)?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(webtransport_transport_config());
    Ok(config)
}

pub(in crate::network_manager) fn build_server_config_from_chain(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<quinn::ServerConfig> {
    let provider = crypto_provider();
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(to_io_error_other)?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(to_io_error_other)?;
    crypto.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

    let quic_crypto = QuicServerConfig::try_from(crypto).map_err(to_io_error_other)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    config.transport_config(webtransport_transport_config());
    Ok(config)
}

pub(in crate::network_manager) fn build_server_config(
    cert: &ManagedCertificate,
) -> io::Result<quinn::ServerConfig> {
    let cert_chain = vec![CertificateDer::from(cert.certificate_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.private_key_der.clone()));
    build_server_config_from_chain(cert_chain, key)
}

/// A rustls server-certificate resolver for CA-signed (bootstrap) WebTransport. It serves the
/// `hostname` certificate (from `network.tls`, with `DNS:` SANs) for SNI-bearing handshakes, and
/// a family-specific IP-SAN certificate (`ip`) for handshakes that carry no SNI. A browser forcing
/// an address family dials an IP literal (`https://203.0.113.5:5150/`), which sends no SNI per
/// RFC 6066, so the certificate it validates must carry an `IP:` SAN and the bound endpoint is
/// the only signal for which family to present: each bound (v4/v6) endpoint installs a resolver
/// holding that family's IP certificate. With no IP certificate configured the hostname
/// certificate is served instead, so by-hostname dials work and by-IP dials fail to validate.
#[derive(Debug)]
struct WebTransportCaCertResolver {
    hostname: Arc<CertifiedKey>,
    ip: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for WebTransportCaCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if client_hello.server_name().is_some() {
            Some(Arc::clone(&self.hostname))
        } else {
            self.ip
                .as_ref()
                .map(Arc::clone)
                .or_else(|| Some(Arc::clone(&self.hostname)))
        }
    }
}

pub(in crate::network_manager) fn certified_key_from_chain(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<Arc<CertifiedKey>> {
    let signing_key = crypto_provider()
        .key_provider
        .load_private_key(key)
        .map_err(to_io_error_other)?;
    Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
}

pub(in crate::network_manager) fn build_ca_server_config(
    hostname: Arc<CertifiedKey>,
    ip: Option<Arc<CertifiedKey>>,
) -> io::Result<quinn::ServerConfig> {
    let resolver = Arc::new(WebTransportCaCertResolver { hostname, ip });
    let provider = crypto_provider();
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(to_io_error_other)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    crypto.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

    let quic_crypto = QuicServerConfig::try_from(crypto).map_err(to_io_error_other)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    config.transport_config(webtransport_transport_config());
    Ok(config)
}

#[derive(Clone)]
enum WebTransportChannel {
    Stream {
        send: Arc<AsyncMutex<SendStream>>,
        recv: Arc<AsyncMutex<RecvStream>>,
    },
    Datagram {
        primed: Arc<AsyncMutex<Option<Bytes>>>,
        empty_send_buffer_space: usize,
        assembly: AssemblyBuffer,
    },
}

enum FlushWait {
    Stream(Arc<AsyncMutex<SendStream>>),
    Datagram(usize),
}

/// Clones share the session, so one can carry a send while another flushes it
#[derive(Clone)]
pub struct WebTransportNetworkConnection {
    registry: VeilidComponentRegistry,
    flow: Flow,
    direction: Direction,
    session: Session,
    channel: WebTransportChannel,
}

impl fmt::Debug for WebTransportNetworkConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportNetworkConnection")
            .field("flow", &self.flow)
            .field("direction", &self.direction)
            .field(
                "channel",
                &match self.channel {
                    WebTransportChannel::Stream { .. } => "stream",
                    WebTransportChannel::Datagram { .. } => "datagram",
                },
            )
            .finish()
    }
}

impl VeilidComponentRegistryAccessor for WebTransportNetworkConnection {
    fn registry(&self) -> VeilidComponentRegistry {
        self.registry.clone()
    }
}

impl WebTransportNetworkConnection {
    pub(in crate::network_manager) fn new_stream(
        registry: VeilidComponentRegistry,
        flow: Flow,
        direction: Direction,
        session: Session,
        send: SendStream,
        recv: RecvStream,
    ) -> Self {
        Self {
            registry,
            flow,
            direction,
            session,
            channel: WebTransportChannel::Stream {
                send: Arc::new(AsyncMutex::new(send)),
                recv: Arc::new(AsyncMutex::new(recv)),
            },
        }
    }

    fn new_datagram(
        registry: VeilidComponentRegistry,
        flow: Flow,
        direction: Direction,
        session: Session,
        primed: Option<Bytes>,
    ) -> Self {
        let empty_send_buffer_space = session.datagram_send_buffer_space();
        Self {
            registry,
            flow,
            direction,
            session,
            channel: WebTransportChannel::Datagram {
                primed: Arc::new(AsyncMutex::new(primed)),
                empty_send_buffer_space,
                assembly: AssemblyBuffer::new(),
            },
        }
    }

    pub fn flow(&self) -> Flow {
        self.flow
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", err, skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub fn close(&self) -> io::Result<NetworkResult<()>> {
        veilid_log!(self trace "WebTransport: close {:?}", self.flow);
        self.session.close(0u32, b"close");
        Ok(NetworkResult::value(()))
    }

    pub async fn flush_and_close(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let wait = match &self.channel {
            WebTransportChannel::Stream { send, .. } => {
                let _ = send.lock().await.finish();
                FlushWait::Stream(send.clone())
            }
            WebTransportChannel::Datagram {
                empty_send_buffer_space,
                ..
            } => FlushWait::Datagram(*empty_send_buffer_space),
        };
        let session = self.session.clone();
        async move {
            let flushed = async {
                match wait {
                    FlushWait::Stream(send) => {
                        let _ = send.lock().await.stopped().await;
                    }
                    FlushWait::Datagram(empty_space) => {
                        // quinn offers no wakeup for the outgoing datagram buffer, so poll it.
                        while session.close_reason().is_none()
                            && session.datagram_send_buffer_space() < empty_space
                        {
                            sleep(WT_DATAGRAM_FLUSH_POLL_INTERVAL_MS).await;
                        }
                    }
                }
            };
            let _ = timeout(WT_UNBOUND_FLUSH_GRACE_MS, flushed).await;
        }
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", err, skip(self, message), fields(__VEILID_LOG_KEY = self.log_key(), message.len = message.len()))
    )]
    pub async fn send(&self, message: Bytes) -> io::Result<NetworkResult<()>> {
        if message.len() > MAX_MESSAGE_SIZE {
            veilid_log!(self debug
                "WebTransport: refusing to send too large message ({} bytes) {:?}",
                message.len(), self.flow);
            bail_io_error_other!("sending too large WebTransport message");
        }
        match &self.channel {
            WebTransportChannel::Stream { send, .. } => {
                let len = message.len() as u32;
                let mut stream = send.lock().await;
                if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
                    veilid_log!(self debug
                        "WebTransport: stream length write failed {:?}: {}", self.flow, e);
                    return Ok(NetworkResult::NoConnection(to_io_error_other(e)));
                }
                if let Err(e) = stream.write_all(&message).await {
                    veilid_log!(self debug
                        "WebTransport: stream body write failed {:?}: {}", self.flow, e);
                    return Ok(NetworkResult::NoConnection(to_io_error_other(e)));
                }
                Ok(NetworkResult::value(()))
            }
            WebTransportChannel::Datagram { assembly, .. } => {
                let max = self.session.max_datagram_size();
                // A peer that does not accept datagrams reports a budget of 0.
                if max < MIN_WTD_DATAGRAM_SIZE {
                    veilid_log!(self debug
                        "WebTransport: datagram budget too small ({} < {}) {:?}",
                        max, MIN_WTD_DATAGRAM_SIZE, self.flow);
                    return Ok(NetworkResult::invalid_message(
                        "WebTransport datagram budget too small",
                    ));
                }
                let Some(fragment_len) = max.checked_sub(FRAME_HEADER_LEN) else {
                    veilid_log!(self debug
                        "WebTransport: datagram budget below the fragment header ({} < {}) {:?}",
                        max, FRAME_HEADER_LEN, self.flow);
                    return Ok(NetworkResult::invalid_message(
                        "WebTransport datagram budget too small",
                    ));
                };
                let wtd_message_cap = WTD_MAX_FRAGMENTS.saturating_mul(fragment_len);
                if message.len() > wtd_message_cap {
                    veilid_log!(self debug
                        "WebTransport: refusing oversize WTD message ({} bytes > cap {} = {} fragments) {:?}",
                        message.len(), wtd_message_cap, WTD_MAX_FRAGMENTS, self.flow);
                    return Ok(NetworkResult::invalid_message(format!(
                        "WebTransport datagram message too large for unreliable delivery: {} bytes exceeds the {}-fragment cap ({} bytes); use a reliable transport",
                        message.len(), WTD_MAX_FRAGMENTS, wtd_message_cap
                    )));
                }
                let remote_addr = self.flow.remote_address().socket_addr();
                let session = self.session.clone();
                let registry = self.registry.clone();
                let flow = self.flow;
                let sender = move |framed_chunk: Bytes, _remote_addr: SocketAddr| {
                    let session = session.clone();
                    let registry = registry.clone();
                    async move {
                        match session.send_datagram(framed_chunk) {
                            // quinn's `send_datagram` uses drop=true: when its 1 MB
                            // `datagram_send_buffer_size` overflows under backlog it silently
                            // evicts the oldest queued datagrams and still returns `Ok`.
                            Ok(()) => Ok(NetworkResult::value(())),
                            Err(web_transport_quinn::SessionError::SendDatagramError(
                                web_transport_quinn::quinn::SendDatagramError::ConnectionLost(e),
                            )) => {
                                veilid_log!(registry debug
                                    "WebTransport: datagram send failed, connection lost {:?}: {}", flow, e);
                                Ok(NetworkResult::NoConnection(to_io_error_other(e)))
                            }
                            Err(e) => {
                                veilid_log!(registry debug
                                    "WebTransport: datagram send dropped (recoverable) {:?}: {}", flow, e);
                                Ok(NetworkResult::invalid_message(format!(
                                    "WebTransport datagram send failed: {e}"
                                )))
                            }
                        }
                    }
                };
                assembly
                    .split_message(message, remote_addr, max, sender)
                    .await
            }
        }
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", err, skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn recv(&self) -> io::Result<NetworkResult<Bytes>> {
        match &self.channel {
            WebTransportChannel::Stream { recv, .. } => {
                let mut stream = recv.lock().await;
                let mut len_buf = [0u8; STREAM_LEN_PREFIX];
                if let Err(e) = stream.read_exact(&mut len_buf).await {
                    veilid_log!(self debug
                        "WebTransport: stream length read failed {:?}: {}", self.flow, e);
                    return Ok(NetworkResult::NoConnection(to_io_error_other(e)));
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_MESSAGE_SIZE {
                    veilid_log!(self debug
                        "WebTransport: received too large stream message ({} bytes) {:?}",
                        len, self.flow);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "too large WebTransport stream message",
                    ));
                }
                let mut buf = vec![0u8; len];
                if let Err(e) = stream.read_exact(&mut buf).await {
                    veilid_log!(self debug
                        "WebTransport: stream body read failed {:?}: {}", self.flow, e);
                    return Ok(NetworkResult::NoConnection(to_io_error_other(e)));
                }
                Ok(NetworkResult::Value(Bytes::from(buf)))
            }
            WebTransportChannel::Datagram {
                primed, assembly, ..
            } => {
                let remote_addr = self.flow.remote_address().socket_addr();
                loop {
                    let data = if let Some(data) = primed.lock().await.take() {
                        data
                    } else {
                        match self.session.read_datagram().await {
                            Ok(data) => data,
                            Err(e) => {
                                veilid_log!(self debug
                                    "WebTransport: datagram read failed {:?}: {}", self.flow, e);
                                return Ok(NetworkResult::NoConnection(to_io_error_other(e)));
                            }
                        }
                    };

                    match assembly.insert_frame(&data, remote_addr) {
                        NetworkResult::Value(Some(msg)) => {
                            if msg.len() > MAX_MESSAGE_SIZE {
                                veilid_log!(self debug
                                    "WebTransport: received too large datagram message ({} bytes) {:?}",
                                    msg.len(), self.flow);
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "too large WebTransport datagram message",
                                ));
                            }
                            return Ok(NetworkResult::Value(msg));
                        }
                        NetworkResult::Value(None) => continue,
                        NetworkResult::InvalidMessage(s) => {
                            veilid_log!(self debug
                                "WebTransport: dropping invalid WTD frame {:?}: {}", self.flow, s);
                            continue;
                        }
                        NetworkResult::Timeout => return Ok(NetworkResult::Timeout),
                        NetworkResult::ServiceUnavailable(s) => {
                            return Ok(NetworkResult::ServiceUnavailable(s))
                        }
                        NetworkResult::NoConnection(e) => {
                            return Ok(NetworkResult::NoConnection(e))
                        }
                        NetworkResult::AlreadyExists(e) => {
                            return Ok(NetworkResult::AlreadyExists(e))
                        }
                    }
                }
            }
        }
    }
}

fn server_name_for_url(url: &url::Url) -> String {
    match url.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => String::new(),
    }
}

fn one_shot_client_endpoint(addr: SocketAddr) -> io::Result<quinn::Endpoint> {
    super::super::webtransport_quinn_runtime::veilid_quinn_client_endpoint(addr)
}

/// Which trust the peer asks us to dial with; dial info carrying no certificate hashes is the
/// wire convention for a CA-signed peer.
enum WebTransportDialMode {
    PinnedSelfSigned(Vec<[u8; 32]>),
    CaSigned,
}

impl WebTransportDialMode {
    fn from_cert_hashes(cert_hashes: Vec<[u8; 32]>) -> Self {
        if cert_hashes.is_empty() {
            Self::CaSigned
        } else {
            Self::PinnedSelfSigned(cert_hashes)
        }
    }
}

pub async fn connect(
    registry: VeilidComponentRegistry,
    local_address: Option<SocketAddr>,
    dial_info: DialInfo,
    timeout_ms: u32,
    opt_client_endpoint: Option<quinn::Endpoint>,
) -> io::Result<NetworkResult<ProtocolNetworkConnection>> {
    Ok(connect_connection(
        registry.clone(),
        local_address,
        dial_info,
        timeout_ms,
        opt_client_endpoint,
    )
    .await?
    .map(|conn| {
        // QUIC sizes its own packets, so there is no segment size to report
        registry.network_manager().chaos().wrap_connection(
            Box::new(NativeProtocolNetworkConnection::WebTransport(Box::new(
                conn,
            ))),
            None,
        )
    }))
}

#[cfg_attr(
    feature = "instrument",
    instrument(level = "trace", target = "protocol", skip(registry), ret, err, fields(__VEILID_LOG_KEY = registry.log_key()))
)]
pub(in crate::network_manager) async fn connect_connection(
    registry: VeilidComponentRegistry,
    _local_address: Option<SocketAddr>,
    dial_info: DialInfo,
    timeout_ms: u32,
    opt_client_endpoint: Option<quinn::Endpoint>,
) -> io::Result<NetworkResult<WebTransportNetworkConnection>> {
    let (is_stream, dial_mode) = match &dial_info {
        DialInfo::WebTransportStream(di) => (
            true,
            WebTransportDialMode::from_cert_hashes(di.cert_hashes.clone()),
        ),
        DialInfo::WebTransportDatagram(di) => (
            false,
            WebTransportDialMode::from_cert_hashes(di.cert_hashes.clone()),
        ),
        _ => bail_io_error_other!("invalid dialinfo for webtransport protocol"),
    };

    let request = dial_info.request().unwrap_or_log();
    let url = url::Url::parse(&request).map_err(to_io_error_other)?;
    let remote = dial_info.to_socket_addr();

    let client_config = match dial_mode {
        WebTransportDialMode::CaSigned => cached_client_config_ca()?,
        WebTransportDialMode::PinnedSelfSigned(cert_hashes) => build_client_config(cert_hashes)?,
    };
    let endpoint = match opt_client_endpoint {
        Some(ep) => ep,
        None => one_shot_client_endpoint(compatible_unspecified_socket_addr(&remote))?,
    };
    let actual_local_addr = endpoint.local_addr()?;
    let server_name = server_name_for_url(&url);

    let connect_fut = async {
        let connecting = endpoint
            .connect_with(client_config, remote, &server_name)
            .map_err(to_io_error_other)?;
        let conn = connecting.await.map_err(to_io_error_other)?;
        let session = web_transport_quinn::Session::connect(conn, url)
            .await
            .map_err(to_io_error_other)?;
        io::Result::Ok(session)
    };
    let session = match timeout(timeout_ms, connect_fut).await {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => {
            veilid_log!(registry debug
                "WebTransport: connect to {} failed: {}", remote, e);
            return Ok(NetworkResult::NoConnection(e));
        }
        Err(_) => {
            veilid_log!(registry debug
                "WebTransport: connect to {} timed out after {}ms", remote, timeout_ms);
            return Ok(NetworkResult::timeout());
        }
    };

    let local_ip = routed_local_ip(&remote)
        .or_else(|| session.local_ip())
        .unwrap_or_else(|| actual_local_addr.ip());
    let local_socket_addr = SocketAddr::new(local_ip, actual_local_addr.port());
    let flow = Flow::new(
        dial_info.peer_address(),
        SocketAddress::from_socket_addr(local_socket_addr),
    );

    let conn = if is_stream {
        let (send, recv) = match session.open_bi().await {
            Ok(v) => v,
            Err(e) => return Ok(NetworkResult::NoConnection(to_io_error_other(e))),
        };
        WebTransportNetworkConnection::new_stream(
            registry,
            flow,
            Direction::Out,
            session,
            send,
            recv,
        )
    } else {
        WebTransportNetworkConnection::new_datagram(registry, flow, Direction::Out, session, None)
    };

    veilid_log!(conn trace "WebTransport::connect: {:?}", conn);

    Ok(NetworkResult::Value(conn))
}

#[cfg_attr(
    feature = "instrument",
    instrument(level = "trace", target = "protocol", skip(registry, endpoint), ret, err, fields(__VEILID_LOG_KEY = registry.log_key()))
)]
pub(in crate::network_manager) async fn connect_via_shared_endpoint(
    registry: VeilidComponentRegistry,
    endpoint: quinn::Endpoint,
    dial_info: DialInfo,
    timeout_ms: u32,
) -> io::Result<NetworkResult<ProtocolNetworkConnection>> {
    connect(registry, None, dial_info, timeout_ms, Some(endpoint)).await
}

fn accepted_flow(remote: SocketAddr, local_addr: SocketAddr, pt: ProtocolType) -> Flow {
    Flow::new(
        PeerAddress::new(SocketAddress::from_socket_addr(remote), pt),
        SocketAddress::from_socket_addr(local_addr),
    )
}

pub(in crate::network_manager) fn accepted_stream_connection(
    registry: VeilidComponentRegistry,
    flow: Flow,
    session: Session,
    send: SendStream,
    recv: RecvStream,
) -> WebTransportNetworkConnection {
    WebTransportNetworkConnection::new_stream(registry, flow, Direction::In, session, send, recv)
}

pub(in crate::network_manager) fn accepted_datagram_connection(
    registry: VeilidComponentRegistry,
    flow: Flow,
    session: Session,
    primed: Option<Bytes>,
) -> WebTransportNetworkConnection {
    WebTransportNetworkConnection::new_datagram(registry, flow, Direction::In, session, primed)
}

/// Classify an accepted session as WTS or WTD by which primitive the dialer emits first.
///
/// The dialer picks the mode from its dial info and emits exactly one primitive for it: the WTS
/// arm of `connect` opens a bidirectional stream and never sends a datagram, the WTD arm sends
/// datagrams and never opens a stream, and the wasm `connect` splits the same way. So the two
/// arms below are mutually exclusive for any conforming peer, and a peer that sends both is
/// choosing its own session's type.
///
/// The tie, if a peer does force one, goes to WTS: `futures_util::future::select` polls its
/// first argument first and returns `Either::Left` without polling the second when that one is
/// ready.
pub(in crate::network_manager) async fn accept_session_connection(
    registry: VeilidComponentRegistry,
    local_addr: SocketAddr,
    session: Session,
) -> Option<WebTransportNetworkConnection> {
    let remote = session.remote_address();
    let local_ip = session
        .local_ip()
        .or_else(|| routed_local_ip(&remote))
        .unwrap_or_else(|| local_addr.ip());
    let local = SocketAddr::new(local_ip, local_addr.port());
    let accept_bi = Box::pin(session.accept_bi());
    let read_datagram = Box::pin(session.read_datagram());
    match futures_util::future::select(accept_bi, read_datagram).await {
        futures_util::future::Either::Left((bi, _read_datagram)) => {
            let (send, recv) = bi.ok()?;
            let flow = accepted_flow(remote, local, ProtocolType::WTS);
            Some(accepted_stream_connection(
                registry,
                flow,
                session.clone(),
                send,
                recv,
            ))
        }
        futures_util::future::Either::Right((dg, _accept_bi)) => {
            let data = dg.ok()?;
            let flow = accepted_flow(remote, local, ProtocolType::WTD);
            Some(accepted_datagram_connection(
                registry,
                flow,
                session.clone(),
                Some(data),
            ))
        }
    }
}
