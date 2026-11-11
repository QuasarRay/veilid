use super::*;
use crate::network_manager::network::native::protocol::ws::wss_server_name;
use crate::network_manager::network::native::tls_acceptors::TlsAcceptors;
use data_encoding::BASE64;
use futures_rustls::rustls::{
    crypto::ring::default_provider,
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConnection,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType,
    PKCS_ECDSA_P256_SHA256,
};
use std::path::{Path, PathBuf};

const TEST_HOSTNAME: &str = "bootstrap.test";

fn der_to_pem(label: &str, der: &[u8]) -> String {
    let b64 = BASE64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn hostname_san() -> SanType {
    SanType::DnsName(TEST_HOSTNAME.try_into().expect("dns san"))
}

struct TestCa {
    cert: Certificate,
    key: KeyPair,
}

impl TestCa {
    fn new() -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).expect("ca self-signed");
        Self { cert, key }
    }

    /// Write a leaf carrying `san` and its key as PEM, returning the leaf's DER
    fn write_leaf(&self, san: SanType, cert_path: &Path, key_path: &Path) -> Vec<u8> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san];
        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .expect("leaf signed");
        let chain_pem = format!(
            "{}{}",
            der_to_pem("CERTIFICATE", leaf.der()),
            der_to_pem("CERTIFICATE", self.cert.der())
        );
        std::fs::write(cert_path, chain_pem).expect("write certificate");
        std::fs::write(
            key_path,
            der_to_pem("PRIVATE KEY", &leaf_key.serialize_der()),
        )
        .expect("write key");
        leaf.der().to_vec()
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.cert.der().to_vec()))
            .expect("ca root");
        roots
    }
}

/// A scratch `network.tls` directory, removed when the test ends
struct TlsDir(PathBuf);

impl TlsDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("veilid_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create tls dir");
        Self(dir)
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }

    fn tls(&self) -> VeilidConfigTLS {
        VeilidConfigTLS {
            certificate_path: self.path("server.crt").to_string_lossy().into_owned(),
            private_key_path: self.path("server.key").to_string_lossy().into_owned(),
            connection_initial_timeout_ms: 2000,
        }
    }
}

impl Drop for TlsDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Move a file's modification time forward, as a renewal some time later would
fn touch_later(path: &Path) {
    let modified = std::fs::metadata(path)
        .and_then(|md| md.modified())
        .expect("mtime");
    std::fs::File::options()
        .write(true)
        .open(path)
        .and_then(|f| f.set_modified(modified + std::time::Duration::from_secs(60)))
        .expect("set mtime");
}

/// Handshake in memory with the acceptor of a listener bound to `listener`, dialing `name`,
/// and return the leaf certificate the dialer accepted
fn served_leaf(
    acceptors: &TlsAcceptors,
    listener: SocketAddr,
    roots: &RootCertStore,
    name: &str,
) -> Result<Vec<u8>, String> {
    let client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let server_name = ServerName::try_from(name.to_owned()).map_err(|e| e.to_string())?;
    let mut client =
        ClientConnection::new(Arc::new(client_config), server_name).map_err(|e| e.to_string())?;
    let mut server =
        ServerConnection::new(acceptors.server_config_for(&listener)).map_err(|e| e.to_string())?;

    while client.is_handshaking() || server.is_handshaking() {
        let mut to_server = Vec::new();
        while client.wants_write() {
            client
                .write_tls(&mut to_server)
                .map_err(|e| e.to_string())?;
        }
        let mut reader = to_server.as_slice();
        while !reader.is_empty() {
            server.read_tls(&mut reader).map_err(|e| e.to_string())?;
            server.process_new_packets().map_err(|e| e.to_string())?;
        }

        let mut to_client = Vec::new();
        while server.wants_write() {
            server
                .write_tls(&mut to_client)
                .map_err(|e| e.to_string())?;
        }
        let mut reader = to_client.as_slice();
        while !reader.is_empty() {
            client.read_tls(&mut reader).map_err(|e| e.to_string())?;
            client.process_new_packets().map_err(|e| e.to_string())?;
        }

        if to_server.is_empty() && to_client.is_empty() {
            return Err("handshake stalled".to_owned());
        }
    }

    client
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.to_vec())
        .ok_or_else(|| "no peer certificate".to_owned())
}

pub fn test_serve_ip_certificate_by_family() {
    let ca = TestCa::new();
    let dir = TlsDir::new("tls_acceptors_family");
    assert!(
        TlsAcceptors::try_new(&dir.tls()).is_err(),
        "the hostname certificate is required"
    );

    let hostname_leaf = ca.write_leaf(
        hostname_san(),
        &dir.path("server.crt"),
        &dir.path("server.key"),
    );
    let ipv4_leaf = ca.write_leaf(
        SanType::IpAddress(Ipv4Addr::LOCALHOST.into()),
        &dir.path("ipv4.crt"),
        &dir.path("ipv4.key"),
    );
    let acceptors = TlsAcceptors::try_new(&dir.tls()).expect("acceptors");
    let roots = ca.roots();
    let v4 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 5150);
    let v6 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 5150);

    // By name, either family serves the hostname certificate
    assert_eq!(
        served_leaf(&acceptors, v4, &roots, TEST_HOSTNAME),
        Ok(hostname_leaf.clone())
    );
    assert_eq!(
        served_leaf(&acceptors, v6, &roots, TEST_HOSTNAME),
        Ok(hostname_leaf)
    );
    // By address, the family holding an IP certificate serves it
    assert_eq!(
        served_leaf(&acceptors, v4, &roots, "127.0.0.1"),
        Ok(ipv4_leaf)
    );
    // The family without one serves the hostname certificate, which a dial by address rejects
    assert!(served_leaf(&acceptors, v6, &roots, "::1").is_err());
}

pub fn test_reload_after_renewal() {
    let ca = TestCa::new();
    let dir = TlsDir::new("tls_acceptors_renewal");
    let (cert_path, key_path) = (dir.path("server.crt"), dir.path("server.key"));
    let first_leaf = ca.write_leaf(hostname_san(), &cert_path, &key_path);
    let acceptors = TlsAcceptors::try_new(&dir.tls()).expect("acceptors");
    let roots = ca.roots();
    let v4 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 5150);
    assert!(!acceptors.is_stale());

    // A renewal that has replaced only the certificate does not load
    let first_key = std::fs::read(&key_path).expect("read key");
    let renewed_leaf = ca.write_leaf(hostname_san(), &cert_path, &key_path);
    let renewed_key = std::fs::read(&key_path).expect("read key");
    std::fs::write(&key_path, &first_key).expect("write key");
    touch_later(&cert_path);
    assert!(acceptors.is_stale());
    assert!(TlsAcceptors::try_new(&dir.tls()).is_err());

    // With both files in place the rebuilt set serves the renewed certificate
    std::fs::write(&key_path, &renewed_key).expect("write key");
    touch_later(&key_path);
    let reloaded = TlsAcceptors::try_new(&dir.tls()).expect("reloaded acceptors");
    assert!(!reloaded.is_stale());
    assert_eq!(
        served_leaf(&reloaded, v4, &roots, TEST_HOSTNAME),
        Ok(renewed_leaf)
    );
    // The set built before the renewal still serves what it loaded
    assert_eq!(
        served_leaf(&acceptors, v4, &roots, TEST_HOSTNAME),
        Ok(first_leaf)
    );
}

pub fn test_wss_server_name_for_ip_literal() {
    for (host, by_address) in [(TEST_HOSTNAME, false), ("127.0.0.1", true), ("[::1]", true)] {
        let host = SplitUrlHost::from_str(host).expect("host");
        let server_name = wss_server_name(&host).expect("server name");
        assert_eq!(
            matches!(server_name, ServerName::IpAddress(_)),
            by_address,
            "{host}"
        );
    }
}
