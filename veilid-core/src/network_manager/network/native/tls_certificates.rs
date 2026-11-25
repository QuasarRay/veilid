//! Server certificates from `network.tls`: the hostname certificate and its optional per-family
//! IP-SAN siblings (`ipv4.*` and `ipv6.*` beside the configured files), shared by the WSS
//! acceptors and CA-signed WebTransport

use super::*;
use futures_rustls::rustls::{
    crypto::ring::default_provider,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    Error as TlsError, InconsistentKeys,
};
use std::time::SystemTime;

/// Serves the hostname certificate when the client sends SNI, else the listener family's IP-SAN
/// certificate (a dial by address sends none, RFC 6066), else the hostname one
#[derive(Debug)]
pub(in crate::network_manager) struct TlsServerCertResolver {
    hostname: Arc<CertifiedKey>,
    ip: Option<Arc<CertifiedKey>>,
}

impl TlsServerCertResolver {
    pub fn new(hostname: Arc<CertifiedKey>, ip: Option<Arc<CertifiedKey>>) -> Self {
        Self { hostname, ip }
    }
}

impl ResolvesServerCert for TlsServerCertResolver {
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

/// A certificate chain with its signing key. A key that does not match the leaf is an error,
/// which a renewal that has replaced only one of the two files produces
pub(in crate::network_manager) fn certified_key_from_chain(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<Arc<CertifiedKey>> {
    let signing_key = default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(to_io_error_other)?;
    let certified_key = CertifiedKey::new(cert_chain, signing_key);
    match certified_key.keys_match() {
        Ok(()) | Err(TlsError::InconsistentKeys(InconsistentKeys::Unknown)) => {}
        Err(e) => return Err(to_io_error_other(e)),
    }
    Ok(Arc::new(certified_key))
}

/// The PEM certificate chain at `cert_path` with the PEM key at `key_path`
pub(in crate::network_manager) fn load_certified_key(
    cert_path: &str,
    key_path: &str,
) -> io::Result<Arc<CertifiedKey>> {
    let certs = NativeNetwork::load_certs(Path::new(cert_path))?;
    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Certificates at {} could not be loaded.\nEnsure it is in PEM format, beginning with '-----BEGIN CERTIFICATE-----'", cert_path)));
    }
    let mut keys = NativeNetwork::load_keys(Path::new(key_path))?;
    if keys.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Private key at {} could not be loaded.\nEnsure it is unencrypted and in RSA or PKCS8 format, beginning with '-----BEGIN RSA PRIVATE KEY-----' or '-----BEGIN PRIVATE KEY-----'", key_path)));
    }
    certified_key_from_chain(certs, keys.remove(0))
}

/// `base` with its file stem replaced by `family_stem`, keeping the directory and extension
pub(in crate::network_manager) fn sibling_ip_path(base: &str, family_stem: &str) -> Option<String> {
    if base.is_empty() {
        return None;
    }
    let p = Path::new(base);
    let new_name = match p.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{family_stem}.{ext}"),
        None => family_stem.to_owned(),
    };
    p.with_file_name(new_name)
        .to_str()
        .map(std::borrow::ToOwned::to_owned)
}

/// Where `family_stem`'s IP-SAN certificate and key live, beside the `network.tls` files
pub(in crate::network_manager) fn sibling_ip_cert_key_paths(
    tls: &VeilidConfigTLS,
    family_stem: &str,
) -> Option<(String, String)> {
    let cert = sibling_ip_path(&tls.certificate_path, family_stem)?;
    let key = sibling_ip_path(&tls.private_key_path, family_stem)?;
    Some((cert, key))
}

/// The files a server certificate set is built from, each with whether it must exist: the
/// `network.tls` pair, then each family's IP siblings
pub(in crate::network_manager) fn tls_certificate_files(
    tls: &VeilidConfigTLS,
) -> Vec<(String, bool)> {
    let mut files = vec![
        (tls.certificate_path.clone(), true),
        (tls.private_key_path.clone(), true),
    ];
    for family_stem in ["ipv4", "ipv6"] {
        if let Some((cert, key)) = sibling_ip_cert_key_paths(tls, family_stem) {
            files.push((cert, false));
            files.push((key, false));
        }
    }
    files
}

/// Modification times of `files`, or `None` when a required one cannot be read
pub(in crate::network_manager) fn read_tls_mtimes(
    files: &[(String, bool)],
) -> Option<Vec<Option<SystemTime>>> {
    let mut out = Vec::with_capacity(files.len());
    for (path, required) in files {
        let mtime = std::fs::metadata(path)
            .ok()
            .and_then(|md| md.modified().ok());
        if *required && mtime.is_none() {
            return None;
        }
        out.push(mtime);
    }
    Some(out)
}

/// A TLS server config that picks its certificate with a [`TlsServerCertResolver`]
pub(in crate::network_manager) fn tls_server_config(
    hostname: Arc<CertifiedKey>,
    ip: Option<Arc<CertifiedKey>>,
) -> io::Result<ServerConfig> {
    Ok(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(to_io_error_other)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(TlsServerCertResolver::new(hostname, ip))),
    )
}
