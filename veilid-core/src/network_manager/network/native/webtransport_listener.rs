use super::certificate_manager::{CertificateAdvertisement, CertificateManager};
use super::protocol::webtransport;
use super::udp_demux::DemuxerUdpSocket;
use super::webtransport_certificate_profile::{
    webtransport_certificate_profile, WEBTRANSPORT_CERT_DEFAULT_VALIDITY,
};
use super::webtransport_quinn_runtime::{veilid_quinn_runtime, VeilidQuinnUdpSocket};
use super::webtransport_state::DedicatedPunchSocket;
use super::*;
use futures_rustls::rustls::sign::CertifiedKey;
use web_transport_quinn::{quinn, Server};

/// Grace period after rejecting a CONNECT with a 404, during which the QUIC connection is
/// held open so the quinn driver can transmit the response. `Request::reject`
/// (`web_transport_quinn`) finishes the response stream without waiting for delivery, then
/// drops its own `Connection` handle; if that is the last live handle, quinn's `Drop` turns
/// it into an immediate implicit close that can abandon the still-buffered 404.
const WT_REJECT_FLUSH_GRACE_MS: u32 = 1000;

/// Assemble an advertised WebTransport URL from `base`, injecting `inject_port` and
/// `configured_path` only where `base` leaves them out.
///
/// A dialing peer takes its CONNECT path from this URL as the `url` crate parses it, so the
/// URL is assembled with that crate rather than with `SplitUrl`, whose path percent-encoding
/// disagrees on ';', '[' and ']'.
pub(in crate::network_manager) fn webtransport_request_url(
    base: &str,
    inject_port: Option<u16>,
    configured_path: &str,
) -> EyreResult<String> {
    let mut advertised = url::Url::parse(base).wrap_err("couldn't parse webtransport url")?;
    if let Some(port) = inject_port {
        advertised
            .set_port(Some(port))
            .map_err(|_| eyre!("couldn't set the bound port on the webtransport url"))?;
    }
    if advertised.path().trim_matches('/').is_empty() && !configured_path.is_empty() {
        advertised.set_path(configured_path);
    }
    Ok(advertised.to_string())
}

/// Assemble the advertised WebTransport URL for one of our own socket addresses.
pub(in crate::network_manager) fn webtransport_socket_request_url(
    socket_addr: SocketAddr,
    configured_path: &str,
) -> EyreResult<String> {
    webtransport_request_url(&format!("https://{}", socket_addr), None, configured_path)
}

pub(in crate::network_manager) fn webtransport_path_matches(
    request_path: &str,
    expected: &str,
) -> bool {
    request_path.len() <= MAX_WEBTRANSPORT_PATH_LENGTH
        && request_path.trim_matches('/') == expected.trim_matches('/')
}

/// Both address families' server configs, built together so neither can go missing.
#[derive(Clone)]
pub(in crate::network_manager) struct WebTransportServerConfigs {
    v4: quinn::ServerConfig,
    v6: quinn::ServerConfig,
}

impl WebTransportServerConfigs {
    pub(super) fn for_addr(&self, addr: &SocketAddr) -> quinn::ServerConfig {
        if addr.is_ipv4() {
            self.v4.clone()
        } else {
            self.v6.clone()
        }
    }
}

pub(in crate::network_manager) enum WebTransportBindPlan {
    Off,
    Shared(WebTransportServerConfigs),
    Dedicated(NetworkBindSet, WebTransportServerConfigs),
}

/// How a dialer is expected to trust this node's WebTransport certificate.
pub(super) enum WebTransportCertMode {
    /// A rolling certificate this node generates, pinned by hash in the advertised dial info.
    SelfSigned,
    /// A CA-signed certificate for the carried URL, loaded from the `network.tls` files.
    CaSigned(String),
}

/// CA mode has no certificate advertisement in hand, so the hashes and expiration are carried
/// as separate fields rather than as one advertisement.
struct WtDialInfoPair {
    socket_address: SocketAddress,
    request_url: String,
    cert_hashes: Vec<[u8; 32]>,
    expiration: Option<Timestamp>,
    is_static: bool,
    label: &'static str,
}

/// Rebuild the WebTransport entries of `dial_info_details` with `advertisement`'s certificate
/// hashes and expiration, keeping each entry's class, socket address, and request URL.
///
/// A node behind NAT gets its WebTransport dial info from dial info confirmation, at a mapped
/// address that no local interface knows about, so the entries are restamped in place rather
/// than rebuilt from the addresses this node binds.
pub(in crate::network_manager) fn restamp_webtransport_dial_info(
    dial_info_details: &[DialInfoDetail],
    advertisement: &CertificateAdvertisement,
) -> Vec<DialInfoDetail> {
    let mut restamped = Vec::new();
    for did in dial_info_details {
        let rebuilt = match &did.dial_info {
            DialInfo::WebTransportStream(di) => DialInfo::try_webtransport_stream(
                di.socket_address,
                di.request.clone(),
                advertisement.cert_hashes.clone(),
                advertisement.expiration,
            ),
            DialInfo::WebTransportDatagram(di) => DialInfo::try_webtransport_datagram(
                di.socket_address,
                di.request.clone(),
                advertisement.cert_hashes.clone(),
                advertisement.expiration,
            ),
            _ => continue,
        };
        match rebuilt {
            Ok(dial_info) => restamped.push(DialInfoDetail {
                dial_info,
                class: did.class,
            }),
            Err(e) => {
                tracing::debug!(target: "net",
                    "keeping the existing WebTransport dial info {}, restamping it failed: {}",
                    did.dial_info, e);
                restamped.push(did.clone());
            }
        }
    }
    restamped
}

pub(in crate::network_manager) fn same_bind_target(a: &NetworkBindSet, b: &NetworkBindSet) -> bool {
    if a.port != b.port {
        return false;
    }
    let a_addrs: BTreeSet<IpAddr> = a.addrs.iter().copied().collect();
    let b_addrs: BTreeSet<IpAddr> = b.addrs.iter().copied().collect();
    a_addrs == b_addrs
}

impl NativeNetwork {
    pub(super) fn webtransport_cert_mode(&self) -> WebTransportCertMode {
        let cfg = self.config();
        let Some(url) = cfg.network.protocol.webtransport.url.clone() else {
            return WebTransportCertMode::SelfSigned;
        };
        if url.is_empty()
            || cfg.network.tls.certificate_path.is_empty()
            || cfg.network.tls.private_key_path.is_empty()
        {
            return WebTransportCertMode::SelfSigned;
        }
        WebTransportCertMode::CaSigned(url)
    }

    pub(in crate::network_manager) async fn startup_certificate_manager(&self) -> EyreResult<()> {
        if !self.config().network.protocol.webtransport.listen {
            return Ok(());
        }
        let WebTransportCertMode::SelfSigned = self.webtransport_cert_mode() else {
            return Ok(());
        };
        let cert_manager = Arc::new(CertificateManager::new(
            self.registry(),
            webtransport_certificate_profile(WEBTRANSPORT_CERT_DEFAULT_VALIDITY),
        ));
        cert_manager
            .load_or_generate(Timestamp::now())
            .await
            .map_err(|e| eyre!("failed to initialize webtransport certificates: {}", e))?;
        self.inner.lock().webtransport.certificate_manager = Some(cert_manager);
        Ok(())
    }

    /// Build the per-family quinn server configs to serve on the shared WebTransport
    /// endpoints, or none if WebTransport listening is disabled or no certificate is
    /// available (the caller then binds raw UDP only).
    ///
    /// In CA-signed (bootstrap) mode the hostname chain/key come from `network.tls` and are
    /// served for SNI handshakes. Each family additionally serves its own IP-SAN certificate
    /// (`ipv4.crt`/`ipv6.crt` sibling files, when present) for SNI-less IP-literal dials,
    /// which lets a browser bootstrap over WebTransport by IP (forcing an address family)
    /// without WSS. In self-signed mode both families share the rolling self-signed
    /// certificate, validated by hash, so the family is irrelevant.
    pub(super) fn webtransport_server_configs(
        &self,
    ) -> EyreResult<Option<WebTransportServerConfigs>> {
        if !self.config().network.protocol.webtransport.listen {
            return Ok(None);
        }
        let limit_v4 =
            webtransport::QuicMtuLimit::for_address_type(&self.registry(), AddressType::IPV4);
        let limit_v6 =
            webtransport::QuicMtuLimit::for_address_type(&self.registry(), AddressType::IPV6);
        if let WebTransportCertMode::CaSigned(_) = self.webtransport_cert_mode() {
            let cfg = self.config();
            let certs = Self::load_certs(std::path::Path::new(&cfg.network.tls.certificate_path))
                .wrap_err("failed to load webtransport TLS certificate")?;
            if certs.is_empty() {
                bail!("webtransport TLS certificate is empty");
            }
            let mut keys = Self::load_keys(std::path::Path::new(&cfg.network.tls.private_key_path))
                .wrap_err("failed to load webtransport TLS private key")?;
            if keys.is_empty() {
                bail!("webtransport TLS private key is empty");
            }
            let hostname_ck = certified_key_from_chain(certs, keys.remove(0))
                .wrap_err("failed to build CA-signed webtransport hostname certificate")?;

            let v4_ip = self.load_webtransport_ip_certified_key("ipv4");
            let v6_ip = self.load_webtransport_ip_certified_key("ipv6");
            let v4 = webtransport::build_ca_server_config(hostname_ck.clone(), v4_ip, limit_v4)
                .wrap_err("failed to build CA-signed webtransport server config (ipv4)")?;
            let v6 = webtransport::build_ca_server_config(hostname_ck, v6_ip, limit_v6)
                .wrap_err("failed to build CA-signed webtransport server config (ipv6)")?;
            return Ok(Some(WebTransportServerConfigs { v4, v6 }));
        }
        let cert = {
            let cm = self.inner.lock().webtransport.certificate_manager.clone();
            cm.and_then(|cm| cm.current_certificate(Timestamp::now()))
        };
        let Some(cert) = cert else {
            return Ok(None);
        };
        // One certificate, but each family discovers up to its own limit
        let v4 = webtransport::build_server_config(&cert, limit_v4)
            .wrap_err("failed to build self-signed webtransport server config (ipv4)")?;
        let v6 = webtransport::build_server_config(&cert, limit_v6)
            .wrap_err("failed to build self-signed webtransport server config (ipv6)")?;
        Ok(Some(WebTransportServerConfigs { v4, v6 }))
    }

    /// `udp_bind_set` is None when RawUDP is off, which leaves only a dedicated bind
    pub(in crate::network_manager) fn webtransport_bind_plan(
        &self,
        udp_bind_set: Option<&NetworkBindSet>,
    ) -> EyreResult<WebTransportBindPlan> {
        let server_configs = match self.webtransport_server_configs() {
            Ok(server_configs) => server_configs,
            Err(e) => {
                veilid_log!(self warn
                    "WebTransport server config unavailable; binding without inbound WebTransport (degraded mode): {}", e);
                None
            }
        };
        let Some(server_configs) = server_configs else {
            return Ok(WebTransportBindPlan::Off);
        };

        let listen_address = self
            .config()
            .network
            .protocol
            .webtransport
            .listen_address
            .clone();
        let wt_bind_set = self.make_bind_set(&listen_address)?;
        if udp_bind_set.is_some_and(|udp_bind_set| same_bind_target(&wt_bind_set, udp_bind_set)) {
            return Ok(WebTransportBindPlan::Shared(server_configs));
        }
        Ok(WebTransportBindPlan::Dedicated(wt_bind_set, server_configs))
    }

    /// The server configs to serve on newly bound outbound source handlers, built once for the
    /// whole batch, and only in shared bind mode where WebTransport rides the raw UDP sockets.
    pub(super) fn webtransport_source_handler_server_configs(
        &self,
        wanted: &BTreeSet<SocketAddr>,
    ) -> Option<WebTransportServerConfigs> {
        if wanted.is_empty() || !self.inner.lock().webtransport.shared_bind_mode {
            return None;
        }
        match self.webtransport_server_configs() {
            Ok(server_configs) => server_configs,
            Err(e) => {
                veilid_log!(self debug "webtransport server config unavailable for source handlers: {}", e);
                None
            }
        }
    }

    fn load_webtransport_ip_certified_key(&self, family_stem: &str) -> Option<Arc<CertifiedKey>> {
        let (cert_path, key_path) =
            sibling_ip_cert_key_paths(&self.config().network.tls, family_stem)?;
        let certs = Self::load_certs(std::path::Path::new(&cert_path)).ok()?;
        if certs.is_empty() {
            return None;
        }
        let mut keys = Self::load_keys(std::path::Path::new(&key_path)).ok()?;
        if keys.is_empty() {
            return None;
        }
        match certified_key_from_chain(certs, keys.remove(0)) {
            Ok(ck) => {
                veilid_log!(self debug "serving WebTransport {} IP-SAN certificate for SNI-less (IP-literal) dials from {}", family_stem, cert_path);
                Some(ck)
            }
            Err(e) => {
                veilid_log!(self debug "WebTransport {} IP-SAN certificate unavailable ({}); SNI-less dials of that family will fall back to the hostname certificate", family_stem, e);
                None
            }
        }
    }

    fn webtransport_ip_cert_available(&self, family_stem: &str) -> bool {
        let Some((cert_path, key_path)) =
            sibling_ip_cert_key_paths(&self.config().network.tls, family_stem)
        else {
            return false;
        };
        Self::load_certs(std::path::Path::new(&cert_path))
            .map(|c| !c.is_empty())
            .unwrap_or(false)
            && Self::load_keys(std::path::Path::new(&key_path))
                .map(|k| !k.is_empty())
                .unwrap_or(false)
    }

    pub(super) fn webtransport_current_advertisement(&self) -> CertificateAdvertisement {
        self.inner
            .lock()
            .webtransport
            .certificate_manager
            .as_ref()
            .map(|cm| cm.current_advertisement())
            .unwrap_or_default()
    }

    /// Replace the certificate served by every live WebTransport endpoint, without rebinding
    /// the socket. quinn applies the new `ServerConfig` to subsequent handshakes only, so
    /// in-flight sessions are unaffected. Each endpoint gets the config for its own bound
    /// address family, keeping per-family IP-SAN certificates matched to their endpoint.
    pub(super) fn swap_webtransport_server_configs(&self, configs: WebTransportServerConfigs) {
        let endpoints = self.inner.lock().webtransport.endpoints.clone();
        for endpoint in &endpoints {
            let server_config = match endpoint.local_addr() {
                Ok(addr) => configs.for_addr(&addr),
                Err(_) => configs.v4.clone(),
            };
            endpoint.set_server_config(Some(server_config));
        }
    }

    pub(super) fn seed_webtransport_tls_mtimes(&self) {
        let WebTransportCertMode::CaSigned(_) = self.webtransport_cert_mode() else {
            return;
        };
        let files = tls_certificate_files(&self.config().network.tls);
        self.inner.lock().webtransport.tls_mtimes = read_tls_mtimes(&files);
    }

    pub(super) fn maybe_reload_webtransport_ca_certificate(&self) -> EyreResult<()> {
        let WebTransportCertMode::CaSigned(_) = self.webtransport_cert_mode() else {
            return Ok(());
        };
        let files = tls_certificate_files(&self.config().network.tls);
        let Some(current) = read_tls_mtimes(&files) else {
            return Ok(());
        };
        if self.inner.lock().webtransport.tls_mtimes.as_ref() == Some(&current) {
            return Ok(());
        }

        match self.webtransport_server_configs() {
            Ok(Some(configs)) => {
                self.swap_webtransport_server_configs(configs);
                self.inner.lock().webtransport.tls_mtimes = Some(current);
                veilid_log!(self info "reloaded CA-signed WebTransport certificates from updated TLS files");
            }
            Ok(None) => {}
            Err(e) => {
                veilid_log!(self debug "deferring WebTransport CA certificate reload (rebuild failed, will retry): {}", e);
            }
        }
        Ok(())
    }

    pub(super) fn webtransport_advertised_path(&self) -> String {
        self.config()
            .network
            .protocol
            .webtransport
            .path
            .trim_matches('/')
            .to_string()
    }

    fn collect_interface_addrs(
        bound_addresses: &[SocketAddr],
        network_state: &NetworkState,
    ) -> BTreeSet<SocketAddr> {
        let mut interface_addrs = BTreeSet::new();
        for socket_addr in bound_addresses.iter().copied() {
            for idi_addr in network_state
                .translate_unspecified_socket_addr(socket_addr)
                .into_iter()
            {
                interface_addrs.insert(idi_addr);
            }
        }
        interface_addrs
    }

    fn add_wt_dial_info_pair(&self, network_state: &mut NetworkState, wt: WtDialInfoPair) {
        let built = [
            DialInfo::try_webtransport_stream(
                wt.socket_address,
                wt.request_url.clone(),
                wt.cert_hashes.clone(),
                wt.expiration,
            ),
            DialInfo::try_webtransport_datagram(
                wt.socket_address,
                wt.request_url,
                wt.cert_hashes,
                wt.expiration,
            ),
        ];
        for did in built {
            match did {
                Ok(dial_info) => {
                    let detail = DialInfoDetail {
                        dial_info,
                        class: DialInfoClass::Direct,
                    };
                    let res = if wt.is_static {
                        network_state.add_static_dial_info_detail(detail)
                    } else {
                        network_state.add_interface_dial_info_detail(detail)
                    };
                    if let Err(e) = res {
                        veilid_log!(self error "Failed to add {} dial info detail: {}", wt.label, e);
                    }
                }
                Err(e) => {
                    veilid_log!(self error "Failed to build {} dial info: {}", wt.label, e)
                }
            }
        }
    }

    pub(super) fn add_wt_interface_dial_info(
        &self,
        bound_addresses: &[SocketAddr],
        network_state: &mut NetworkState,
    ) -> EyreResult<()> {
        let advertisement = self.webtransport_current_advertisement();
        if advertisement.cert_hashes.is_empty() {
            veilid_log!(self debug "no webtransport certificate hashes to advertise; skipping dial info");
            return Ok(());
        }
        let path = self.webtransport_advertised_path();

        for interface_addr in Self::collect_interface_addrs(bound_addresses, network_state) {
            let sa = SocketAddress::from_socket_addr(interface_addr);
            let url = match webtransport_socket_request_url(interface_addr, &path) {
                Ok(url) => url,
                Err(e) => {
                    veilid_log!(self error "Failed to build webtransport interface url for {}: {}", interface_addr, e);
                    continue;
                }
            };
            self.add_wt_dial_info_pair(
                network_state,
                WtDialInfoPair {
                    socket_address: sa,
                    request_url: url,
                    cert_hashes: advertisement.cert_hashes.clone(),
                    expiration: advertisement.expiration,
                    is_static: false,
                    label: "webtransport interface",
                },
            );
        }

        Ok(())
    }

    pub(super) fn add_wt_url_dial_info(
        &self,
        bound_addresses: &[SocketAddr],
        network_state: &mut NetworkState,
    ) -> EyreResult<()> {
        let WebTransportCertMode::CaSigned(url) = self.webtransport_cert_mode() else {
            return Ok(());
        };

        let mut split_url = SplitUrl::from_str(&url).wrap_err("couldn't split webtransport url")?;
        if !split_url.scheme.eq_ignore_ascii_case("https") {
            bail!("WebTransport URL must use the 'https://' scheme");
        }
        "https".clone_into(&mut split_url.scheme);

        let default_port = bound_addresses.first().map(|a| a.port()).unwrap_or(443);
        let static_addrs = split_url
            .host_port(default_port)
            .to_socket_addrs()
            .wrap_err("failed to resolve webtransport url")?
            .collect::<BTreeSet<_>>();

        let request_url = webtransport_request_url(
            &url,
            split_url.port.is_none().then_some(default_port),
            &self.webtransport_advertised_path(),
        )?;

        for static_addr in static_addrs.iter().copied() {
            let sa = SocketAddress::from_socket_addr(static_addr);
            self.add_wt_dial_info_pair(
                network_state,
                WtDialInfoPair {
                    socket_address: sa,
                    request_url: request_url.clone(),
                    cert_hashes: vec![],
                    expiration: None,
                    is_static: true,
                    label: "CA webtransport static",
                },
            );
        }

        Ok(())
    }

    /// Add CA-signed (bootstrap) mode WebTransport dial info, preferring IP-literal
    /// advertisement over the configured hostname URL.
    ///
    /// For each address family whose per-family IP-SAN certificate is served (the
    /// `ipv4`/`ipv6` sibling of `network.tls`), advertise this node's own interface
    /// address(es) of that family as IP-literal WebTransport URLs: `https://<ip>:<port>/`,
    /// or `.../{path}` when `network.protocol.webtransport.path` is non-default, with no cert
    /// hashes, validated against the system roots via the IP-SAN cert. A node that learns the
    /// bootstrap from its signed node-info then dials the IP directly, instead of re-resolving
    /// the configured hostname to a frequently UDP-blackholed IPv6 address and stalling. Only
    /// an IP-literal URL also keeps a browser from re-resolving the host and undoing the
    /// IPv4-first contact method ordering (`pick_contact_method`).
    ///
    /// Interface addresses rather than the resolved hostname: the configured URL may be a
    /// round-robin name fronting several hosts, so each backend must advertise only its own
    /// IPs, which are the ones its IP-SAN cert covers. The TXT bootstrap record stays
    /// single-hostname regardless, because `to_short` derives the WTS hostname by PTR of the
    /// socket address (matching udp/tcp).
    ///
    /// Falls back to the hostname URL ([`add_wt_url_dial_info`]) when no per-family IP-SAN
    /// cert is present.
    pub(super) fn add_wt_ca_dial_info(
        &self,
        bound_addresses: &[SocketAddr],
        network_state: &mut NetworkState,
    ) -> EyreResult<()> {
        let v4_ip_cert = self.webtransport_ip_cert_available("ipv4");
        let v6_ip_cert = self.webtransport_ip_cert_available("ipv6");

        if !v4_ip_cert && !v6_ip_cert {
            let example_sibling = sibling_ip_cert_key_paths(&self.config().network.tls, "ipv4")
                .map(|(cert, _key)| cert)
                .unwrap_or_else(|| "<network.tls certificate_path unset>".to_string());
            veilid_log!(self info "WebTransport CA mode: no per-family IP-SAN certificate found (expected as the ipv4/ipv6 sibling of network.tls, e.g. {}); advertising the configured hostname URL instead of IP-literal dial info", example_sibling);
            return self.add_wt_url_dial_info(bound_addresses, network_state);
        }
        let path = self.webtransport_advertised_path();

        for interface_addr in Self::collect_interface_addrs(bound_addresses, network_state) {
            let has_cert = if interface_addr.is_ipv4() {
                v4_ip_cert
            } else {
                v6_ip_cert
            };
            if !has_cert {
                continue;
            }
            let sa = SocketAddress::from_socket_addr(interface_addr);
            let request_url = match webtransport_socket_request_url(interface_addr, &path) {
                Ok(url) => url,
                Err(e) => {
                    veilid_log!(self error "Failed to build CA IP-literal webtransport url for {}: {}", interface_addr, e);
                    continue;
                }
            };
            self.add_wt_dial_info_pair(
                network_state,
                WtDialInfoPair {
                    socket_address: sa,
                    request_url,
                    cert_hashes: vec![],
                    expiration: None,
                    is_static: false,
                    label: "CA IP-literal webtransport",
                },
            );
        }

        Ok(())
    }

    pub(super) fn create_inbound_webtransport_udp_handlers(
        &self,
        bind_set: NetworkBindSet,
        server_configs: WebTransportServerConfigs,
    ) -> EyreResult<bool> {
        self.search_and_bind(&bind_set, "shared webtransport udp", |addr| {
            let server_config = server_configs.for_addr(&addr);

            if self.inner.lock().udp_protocol_handlers.contains_key(&addr) {
                return Ok(TryBindOutcome::TryNextPort);
            }
            if self
                .clone()
                .create_demuxed_udp_handler(addr, &server_config)?
                .is_none()
            {
                return Ok(TryBindOutcome::TryNextPort);
            }
            self.record_bound_address_for_protocols(
                addr,
                &[ProtocolType::UDP, ProtocolType::WTS, ProtocolType::WTD],
            );
            Ok(TryBindOutcome::Bound)
        })
    }

    /// Whether a dedicated WebTransport bind at `addr` would silently conflict with one of the
    /// already-bound raw UDP addresses in `bound_raw_udp_addrs`. Because sockets are bound with
    /// `SO_REUSEADDR`/`SO_REUSEPORT`, binding a second socket at a colliding address
    /// succeeds (the `bind()` syscall does not error) and the kernel then load-balances
    /// inbound datagrams between the two sockets. A QUIC handshake can land on the raw socket
    /// and be dropped there, while a raw veilid datagram can land on the dedicated QUIC socket
    /// and also be dropped. The collision must therefore be checked against the already-bound
    /// raw UDP handlers, since there is no bind failure to observe.
    ///
    /// True if any of those addresses shares `addr`'s address family and port, and either
    /// shares its IP or either side's IP is unspecified (a wildcard bind would receive that
    /// traffic too).
    pub(in crate::network_manager) fn webtransport_udp_delivery_conflict(
        bound_raw_udp_addrs: &BTreeSet<SocketAddr>,
        addr: SocketAddr,
    ) -> bool {
        bound_raw_udp_addrs.iter().any(|bound| {
            bound.is_ipv4() == addr.is_ipv4()
                && bound.port() == addr.port()
                && (bound.ip() == addr.ip()
                    || bound.ip().is_unspecified()
                    || addr.ip().is_unspecified())
        })
    }

    pub(super) fn create_inbound_webtransport_dedicated_handlers(
        &self,
        bind_set: NetworkBindSet,
        server_configs: WebTransportServerConfigs,
        bound_raw_udp_addrs: &BTreeSet<SocketAddr>,
    ) -> EyreResult<bool> {
        for ip_addr in bind_set.addrs {
            let mut port = bind_set.port;
            let server_config = server_configs.for_addr(&SocketAddr::new(ip_addr, 0));
            loop {
                let addr = SocketAddr::new(ip_addr, port);

                if !Self::webtransport_udp_delivery_conflict(bound_raw_udp_addrs, addr)
                    && self.create_dedicated_webtransport_endpoint(addr, &server_config)?
                {
                    self.record_bound_address_for_protocols(
                        addr,
                        &[ProtocolType::WTS, ProtocolType::WTD],
                    );
                    veilid_log!(self debug "WebTransport dedicated bind on {}", addr);
                    break;
                }

                if !bind_set.search {
                    veilid_log!(self debug "unable to bind to dedicated webtransport udp {}", addr);
                    return Ok(false);
                }
                if port == 65535u16 {
                    port = 1024;
                } else {
                    port += 1;
                }
                if port == bind_set.port {
                    bail!(
                        "unable to find a free port for dedicated webtransport udp {}",
                        ip_addr
                    );
                }
            }
        }
        Ok(true)
    }

    pub(super) fn create_dedicated_webtransport_endpoint(
        &self,
        addr: SocketAddr,
        server_config: &quinn::ServerConfig,
    ) -> EyreResult<bool> {
        veilid_log!(self debug "create_dedicated_webtransport_endpoint on {:?}", &addr);

        let Some(udp_socket) = bind_udp_socket_io_probed(addr)? else {
            return Ok(false);
        };
        let socket = Arc::new(udp_socket);
        let quinn_socket = VeilidQuinnUdpSocket::try_from_io(socket.clone())
            .wrap_err("failed to wrap dedicated webtransport socket")?;

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            webtransport::webtransport_endpoint_config(),
            Some(server_config.clone()),
            Arc::new(quinn_socket),
            veilid_quinn_runtime(),
        )
        .wrap_err("failed to create dedicated webtransport endpoint")?;

        {
            let mut inner = self.inner.lock();
            inner.webtransport.endpoints.push(endpoint.clone());
            inner.webtransport.punch_sockets.insert(
                addr,
                DedicatedPunchSocket {
                    ttl_sender: Arc::new(UdpTtlSender::new()),
                    socket,
                },
            );
        }

        self.spawn_webtransport_accept_loop(endpoint, addr);
        Ok(true)
    }

    pub(super) fn create_demuxed_udp_handler(
        &self,
        addr: SocketAddr,
        server_config: &quinn::ServerConfig,
    ) -> EyreResult<Option<RawUdpProtocolHandler>> {
        veilid_log!(self debug "create_demuxed_udp_handler (shared webtransport) on {:?}", &addr);

        let Some(udp_socket) = bind_udp_socket_io_probed(addr)? else {
            return Ok(None);
        };
        let socket_arc = Arc::new(udp_socket);

        // Only a wildcard socket gets the twin; without one quinn stays at its initial MTU here
        let df_sender = match UdpDfSender::try_new(&socket_arc) {
            Ok(df_sender) => df_sender,
            Err(e) => {
                veilid_log!(self debug "WebTransport: no DF twin beside {}, path MTU discovery stays off there: {}", addr, e);
                None
            }
        };
        veilid_log!(self debug "WebTransport: DF twin beside {}: {}", addr, df_sender.is_some());
        let (demux, raw_rx) = DemuxerUdpSocket::try_new(socket_arc.clone(), df_sender)
            .wrap_err("failed to create demux socket")?;

        let server_config = server_config.clone();
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            webtransport::webtransport_endpoint_config(),
            Some(server_config),
            demux,
            veilid_quinn_runtime(),
        )
        .wrap_err("failed to create webtransport endpoint")?;

        let handler =
            RawUdpProtocolHandler::new_demuxed(self.registry(), socket_arc, raw_rx, self.timings());

        {
            let mut inner = self.inner.lock();
            inner.udp_protocol_handlers.insert(addr, handler.clone());
            inner.webtransport.endpoints.push(endpoint.clone());
        }

        self.spawn_webtransport_accept_loop(endpoint, addr);
        Ok(Some(handler))
    }

    pub(super) fn remove_webtransport_endpoint_at(&self, addr: SocketAddr) {
        let mut inner = self.inner.lock();
        let mut kept = Vec::with_capacity(inner.webtransport.endpoints.len());
        for endpoint in inner.webtransport.endpoints.drain(..) {
            if endpoint.local_addr().map(|a| a == addr).unwrap_or(false) {
                endpoint.close(0u32.into(), b"source address gone");
            } else {
                kept.push(endpoint);
            }
        }
        inner.webtransport.endpoints = kept;
        inner.webtransport.punch_sockets.remove(&addr);
    }

    fn record_bound_address_for_protocols(&self, addr: SocketAddr, pts: &[ProtocolType]) {
        let mut inner = self.inner.lock();
        for &pt in pts {
            inner
                .bound_address_per_protocol
                .entry(pt)
                .or_default()
                .push(addr);
            Self::set_preferred_local_address(
                &mut inner,
                PeerAddress::new(SocketAddress::from_socket_addr(addr), pt),
            );
        }
    }

    fn spawn_webtransport_accept_loop(&self, endpoint: quinn::Endpoint, local_addr: SocketAddr) {
        let stop_token = self.inner.lock().stop_source.as_ref().map(|ss| ss.token());
        let this = self.clone();
        let connection_initial_timeout_ms = self
            .registry()
            .config()
            .internal()
            .network
            .connection_initial_timeout_ms;
        let expected_path = self.webtransport_advertised_path();

        let jh = spawn(
            &format!("WebTransport listener {}", local_addr),
            async move {
                veilid_log!(this trace "WebTransport listener task spawned on {}", local_addr);
                let mut server = Server::new(endpoint);
                loop {
                    let request = match &stop_token {
                        Some(st) => match server.accept().timeout_at(st.clone()).await {
                            Ok(r) => r,
                            Err(_) => break,
                        },
                        None => server.accept().await,
                    };
                    let Some(request) = request else {
                        break;
                    };

                    let registry = this.registry();
                    let log = this.clone();
                    let connection_manager = this.network_manager().connection_manager();
                    let expected_path = expected_path.clone();
                    spawn_detached("WebTransport session", async move {
                        let request_path: String = request
                            .url
                            .path()
                            .chars()
                            .take(MAX_WEBTRANSPORT_PATH_LENGTH + 1)
                            .collect();
                        if !webtransport_path_matches(&request_path, &expected_path) {
                            let peer_addr = request.conn().remote_address();
                            veilid_log!(log debug
                            "WebTransport: rejecting CONNECT with path {:?} from {} (expected {:?})",
                            request_path, peer_addr, expected_path);
                            let conn = request.conn().clone();
                            let _ = request
                                .reject(web_transport_quinn::http::StatusCode::NOT_FOUND)
                                .await;
                            let _ = timeout(WT_REJECT_FLUSH_GRACE_MS, conn.closed()).await;
                            return;
                        }
                        let session = match request.ok().await {
                            Ok(s) => s,
                            Err(e) => {
                                veilid_log!(log debug "WebTransport session handshake failed: {}", e);
                                return;
                            }
                        };
                        let peer_addr = session.remote_address();
                        if log
                            .network_manager()
                            .address_filter()
                            .is_ip_addr_punished(peer_addr.ip())
                        {
                            veilid_log!(log debug "WebTransport: rejecting session from punished address {}", peer_addr);
                            return;
                        }
                        let Some(address_lock_guard) = connection_manager
                            .acquire_inbound_address_lock(peer_addr)
                            .await
                        else {
                            veilid_log!(log debug "timed out acquiring inbound address lock for {}", peer_addr);
                            return;
                        };
                        let session_close = session.clone();
                        let conn = match timeout(
                            connection_initial_timeout_ms,
                            webtransport::accept_session_connection(registry, local_addr, session),
                        )
                        .await
                        {
                            Ok(Some(conn)) => conn,
                            Ok(None) => {
                                veilid_log!(log debug "WebTransport: inbound session from {} could not be classified as a stream or datagram session; closing", peer_addr);
                                session_close.close(0u32, b"session not classified");
                                let _ =
                                    timeout(WT_REJECT_FLUSH_GRACE_MS, session_close.closed()).await;
                                return;
                            }
                            Err(_) => {
                                veilid_log!(log debug "WebTransport: inbound session from {} sent no stream or datagram within {}ms; closing", peer_addr, connection_initial_timeout_ms);
                                // Closing with a capsule resolves a browser peer's `session.closed()`
                                // promptly, rather than leaving it on quinn's implicit close-on-drop.
                                // `Session::close` delivers the capsule from a spawned task, so the
                                // session is held until `closed()` confirms it went out.
                                session_close.close(0u32, b"no stream or datagram");
                                let _ =
                                    timeout(WT_REJECT_FLUSH_GRACE_MS, session_close.closed()).await;
                                return;
                            }
                        };
                        veilid_log!(log debug
                            "WebTransport: {} session from {} path mtu {} datagram budget {}",
                            conn.flow().protocol_type(), peer_addr, conn.path_mtu(), conn.datagram_budget());
                        // QUIC sizes its own packets; chaos reads the session's path MTU
                        let prot_conn = log.network_manager().chaos().wrap_connection(
                            Box::new(NativeProtocolNetworkConnection::WebTransport(Box::new(
                                conn,
                            ))),
                            None,
                        );
                        if let Err(e) = connection_manager
                            .on_accepted_protocol_network_connection(prot_conn, address_lock_guard)
                            .await
                        {
                            veilid_log!(log debug "failed to register inbound WebTransport connection: {}", e);
                        }
                    });
                }
                veilid_log!(this trace "WebTransport listener task stopped on {}", local_addr);
            },
        );

        self.add_to_join_handles(jh);
    }
}
