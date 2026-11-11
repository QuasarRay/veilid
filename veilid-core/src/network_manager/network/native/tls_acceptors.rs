//! The WSS acceptors: one per address family, so a dial by address is served that family's
//! IP-SAN certificate

use super::*;
use std::time::SystemTime;

#[derive(Clone)]
pub(in crate::network_manager) struct TlsAcceptors {
    /// Served on IPv4 listeners
    v4: Arc<ServerConfig>,
    /// Served on IPv6 listeners
    v6: Arc<ServerConfig>,
    /// Whether each family's IP-SAN certificate loaded, IPv4 then IPv6
    ip_certificates: (bool, bool),
    /// The certificate files, each with whether it must exist
    files: Vec<(String, bool)>,
    /// Modification times of `files` when these were built
    mtimes: Vec<Option<SystemTime>>,
}

impl TlsAcceptors {
    /// Build both acceptors from the `network.tls` files and whichever IP siblings load
    pub fn try_new(tls: &VeilidConfigTLS) -> io::Result<Self> {
        let files = tls_certificate_files(tls);
        // Read before loading, so a file replaced during the load still reads as changed
        let Some(mtimes) = read_tls_mtimes(&files) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "TLS certificate {} or private key {} is missing",
                    tls.certificate_path, tls.private_key_path
                ),
            ));
        };
        let hostname = load_certified_key(&tls.certificate_path, &tls.private_key_path)?;
        let load_ip = |family_stem: &str| {
            let (cert, key) = sibling_ip_cert_key_paths(tls, family_stem)?;
            load_certified_key(&cert, &key).ok()
        };
        let (ipv4, ipv6) = (load_ip("ipv4"), load_ip("ipv6"));
        Ok(Self {
            ip_certificates: (ipv4.is_some(), ipv6.is_some()),
            v4: Arc::new(tls_server_config(hostname.clone(), ipv4)?),
            v6: Arc::new(tls_server_config(hostname, ipv6)?),
            files,
            mtimes,
        })
    }

    pub fn server_config_for(&self, addr: &SocketAddr) -> Arc<ServerConfig> {
        if addr.is_ipv4() {
            self.v4.clone()
        } else {
            self.v6.clone()
        }
    }

    pub fn for_addr(&self, addr: &SocketAddr) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config_for(addr))
    }

    /// True when a certificate file has changed since these were built
    #[cfg_attr(not(feature = "enable-protocol-wss"), expect(dead_code))]
    pub fn is_stale(&self) -> bool {
        read_tls_mtimes(&self.files).is_some_and(|current| current != self.mtimes)
    }
}

impl NativeNetwork {
    pub(super) fn load_tls_acceptors(&self) -> EyreResult<TlsAcceptors> {
        let acceptors = TlsAcceptors::try_new(&self.config().network.tls)
            .wrap_err("Couldn't create TLS configuration")?;
        let (ipv4, ipv6) = acceptors.ip_certificates;
        veilid_log!(self debug "loaded TLS certificates (IP certificates: ipv4 {}, ipv6 {})", ipv4, ipv6);
        Ok(acceptors)
    }

    /// The acceptor for a listener bound to `addr`, building the set on first use
    pub(super) fn get_or_create_tls_acceptor(&self, addr: &SocketAddr) -> EyreResult<TlsAcceptor> {
        if let Some(acceptors) = self.inner.lock().tls_acceptors.as_ref() {
            return Ok(acceptors.for_addr(addr));
        }
        let acceptors = self.load_tls_acceptors()?;
        let acceptor = acceptors.for_addr(addr);
        self.inner.lock().tls_acceptors = Some(acceptors);
        Ok(acceptor)
    }
}
