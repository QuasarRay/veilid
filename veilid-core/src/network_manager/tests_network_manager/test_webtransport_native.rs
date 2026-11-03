use super::*;
use crate::network_manager::network::native::certificate_manager::{
    CertificateManager, ManagedCertificate,
};
use crate::network_manager::network::native::protocol::webtransport::*;
use crate::network_manager::network::native::webtransport_certificate_profile::*;
use crate::network_manager::network::native::webtransport_quinn_runtime::{
    veilid_quinn_client_endpoint, veilid_quinn_runtime,
};
use crate::network_manager::network::native::NativeNetwork;
use crate::tests::*;

use futures_rustls::rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    RootCertStore,
};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use web_transport_quinn::quinn;

pub fn test_cert_hash_mismatch_is_distinct_from_ca_failure() {
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");
    let cert_der = CertificateDer::from(cert.certificate_der.clone());
    let server_name = ServerName::try_from("veilid.invalid").expect("server name");
    let now = UnixTime::since_unix_epoch(core::time::Duration::from_secs(0));

    let mismatch = CertificateHashVerifier::new(vec![[0u8; 32]], crypto_provider());
    let msg = mismatch
        .verify_server_cert(&cert_der, &[], &server_name, &[], now)
        .expect_err("mismatched hash must be rejected")
        .to_string();
    assert!(
        msg.contains("hash mismatch"),
        "expected a distinct hash-mismatch message, got: {msg}"
    );
    assert!(
        !msg.contains("UnknownIssuer"),
        "a hash mismatch must not masquerade as a CA-trust failure: {msg}"
    );

    let ok = CertificateHashVerifier::new(vec![cert.hash], crypto_provider());
    ok.verify_server_cert(&cert_der, &[], &server_name, &[], now)
        .expect("matching hash must verify");
}

/// The shared-socket first-byte demux is correct only while QUIC bit greasing (RFC 9287) is
/// off. With it on, a short-header QUIC packet may clear the `0x40` fixed bit and land in
/// `0x00..=0x3F`, colliding with raw-UDP's framing byte. `webtransport_endpoint_config` is the
/// one place greasing is disabled. quinn exposes no getter for the flag, but its `Debug` impl
/// prints it.
pub fn test_webtransport_endpoint_config_disables_quic_bit_greasing() {
    let config = webtransport_endpoint_config();
    let dbg = format!("{config:?}");
    assert!(
        dbg.contains("grease_quic_bit: false"),
        "shared-socket demux requires QUIC-bit greasing OFF; endpoint config was: {dbg}"
    );
}

/// Bind an inbound quinn endpoint at `addr` serving `server_config`, on veilid's quinn
/// runtime. Stands in for `quinn::Endpoint::server`, which reaches for quinn's own ambient
/// runtime.
fn test_server_endpoint(
    server_config: quinn::ServerConfig,
    addr: SocketAddr,
) -> io::Result<quinn::Endpoint> {
    let socket = std::net::UdpSocket::bind(addr)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        veilid_quinn_runtime(),
    )
}

fn echo_flow(remote: SocketAddr, local: SocketAddr, pt: ProtocolType) -> Flow {
    Flow::new(
        PeerAddress::new(SocketAddress::from_socket_addr(remote), pt),
        SocketAddress::from_socket_addr(local),
    )
}

fn spawn_echo_server(
    registry: VeilidComponentRegistry,
    cert: &ManagedCertificate,
) -> io::Result<(SocketAddr, quinn::Endpoint)> {
    let server_config = build_server_config(cert)?;
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )?;
    let local_addr = endpoint.local_addr()?;

    let accept_ep = endpoint.clone();
    spawn_detached("wt test echo accept", async move {
        while let Some(incoming) = accept_ep.accept().await {
            let registry = registry.clone();
            let local_addr = local_addr;
            spawn_detached("wt test echo session", async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                let Ok(request) = web_transport_quinn::Request::accept(conn).await else {
                    return;
                };
                let Ok(session) = request.ok().await else {
                    return;
                };
                let remote = session.remote_address();

                {
                    let session = session.clone();
                    let registry = registry.clone();
                    spawn_detached("wt test echo stream", async move {
                        if let Ok((send, recv)) = session.accept_bi().await {
                            let flow = echo_flow(remote, local_addr, ProtocolType::WTS);
                            let conn = accepted_stream_connection(
                                registry,
                                flow,
                                session.clone(),
                                send,
                                recv,
                            );
                            while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                                if conn.send(b).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }

                let flow = echo_flow(remote, local_addr, ProtocolType::WTD);
                let dconn = accepted_datagram_connection(registry, flow, session, None);
                while let Ok(NetworkResult::Value(b)) = dconn.recv().await {
                    if dconn.send(b).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    Ok((local_addr, endpoint))
}

#[cfg(test)]
pub async fn serve_wt_echo_for_browser() {
    let port: u16 = std::env::var("WT_BROWSER_PORT")
        .expect("WT_BROWSER_PORT must be set")
        .parse()
        .expect("WT_BROWSER_PORT must be a u16");
    let hash_file =
        std::env::var("WT_BROWSER_HASH_FILE").expect("WT_BROWSER_HASH_FILE must be set");

    let registry = mock_registry::init("wt_browser_echo").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let server_config = build_server_config(&cert).expect("server config");
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
    )
    .expect("bind endpoint");
    let local_addr = endpoint.local_addr().expect("local addr");

    std::fs::write(&hash_file, hex::encode(cert.hash)).expect("write hash file");
    eprintln!(
        "WT browser echo server listening on {} (cert hash {})",
        local_addr,
        hex::encode(cert.hash)
    );

    let mut server = web_transport_quinn::Server::new(endpoint);
    while let Some(request) = server.accept().await {
        let registry = registry.clone();
        spawn_detached("wt browser echo session", async move {
            let Ok(session) = request.ok().await else {
                return;
            };
            let Some(conn) = accept_session_connection(registry, local_addr, session).await else {
                return;
            };
            while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                if conn.send(b).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[cfg(test)]
async fn read_framed(recv: &mut web_transport_quinn::RecvStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return None;
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

#[cfg(test)]
async fn write_framed(
    send: &mut web_transport_quinn::SendStream,
    msg: &[u8],
) -> Result<(), web_transport_quinn::WriteError> {
    send.write_all(&(msg.len() as u32).to_be_bytes()).await?;
    send.write_all(msg).await
}

/// The browser spec subtracts this from the latency it measures for a read that outlives the
/// peer's close, so it is published in the handshake rather than mirrored on the spec side.
#[cfg(test)]
const STRESS_CLOSE_DELAY_MS: u32 = 500;

#[cfg(test)]
const STRESS_LINGER_MS: u32 = 500;

#[cfg(test)]
pub async fn serve_wt_stress_for_browser() {
    let port: u16 = std::env::var("WT_STRESS_PORT")
        .expect("WT_STRESS_PORT must be set")
        .parse()
        .expect("WT_STRESS_PORT must be a u16");
    let handshake_file =
        std::env::var("WT_STRESS_HANDSHAKE_FILE").expect("WT_STRESS_HANDSHAKE_FILE must be set");

    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let server_config = build_server_config(&cert).expect("server config");
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
    )
    .expect("bind endpoint");
    let local_addr = endpoint.local_addr().expect("local addr");

    let handshake = serde_json::json!({
        "cert_hash": hex::encode(cert.hash),
        "close_delay_ms": STRESS_CLOSE_DELAY_MS,
    })
    .to_string();
    std::fs::write(&handshake_file, &handshake).expect("write handshake file");
    eprintln!("WT browser stress server listening on {local_addr} ({handshake})");

    let mut server = web_transport_quinn::Server::new(endpoint);
    while let Some(request) = server.accept().await {
        let path = request.url.path().to_string();
        spawn_detached("wt browser stress session", async move {
            let Ok(session) = request.ok().await else {
                return;
            };
            eprintln!("WT stress session {path}");
            match path.as_str() {
                "/park" => {
                    let _ = timeout(120_000, session.closed()).await;
                }
                "/close-on-first-byte" => {
                    if let Ok((_send, mut recv)) = session.accept_bi().await {
                        let mut trigger = [0u8; 1];
                        let _ = recv.read_exact(&mut trigger).await;
                    }
                    session.close(7, b"stress: remote close");
                }
                "/close-mid-read" => {
                    if let Ok((mut send, mut recv)) = session.accept_bi().await {
                        if let Some(msg) = read_framed(&mut recv).await {
                            let _ = write_framed(&mut send, &msg).await;
                        }
                        sleep(STRESS_CLOSE_DELAY_MS).await;
                        session.close(9, b"stress: close mid read");
                        sleep(STRESS_LINGER_MS).await;
                        drop((send, recv));
                    }
                }
                _ => {
                    if let Ok((mut send, mut recv)) = session.accept_bi().await {
                        while let Some(msg) = read_framed(&mut recv).await {
                            if write_framed(&mut send, &msg).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
    }
}

pub async fn test_webtransport_loopback() {
    let registry = mock_registry::init("webtransport_loopback").await;

    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("should generate cert");

    let (server_addr, _endpoint) =
        spawn_echo_server(registry.clone(), &cert).expect("should start echo server");
    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);

    let di = DialInfo::try_webtransport_stream(socket_address, url.clone(), vec![cert.hash], None)
        .expect("wts dialinfo");
    let conn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wts connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTS connect failed: {:?}", other),
    };
    let msg = Bytes::from_static(b"hello webtransport stream");
    assert!(matches!(
        conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("wts send io"),
        NetworkResult::Value(())
    ));
    match conn.recv().await.expect("wts recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, msg),
        other => panic!("WTS recv failed: {:?}", other),
    }

    let di =
        DialInfo::try_webtransport_datagram(socket_address, url.clone(), vec![cert.hash], None)
            .expect("wtd dialinfo");
    let dconn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wtd connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTD connect failed: {:?}", other),
    };
    let dmsg = Bytes::from_static(b"hello webtransport datagram");
    assert!(matches!(
        dconn
            .send(dmsg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("wtd send io"),
        NetworkResult::Value(())
    ));
    match dconn.recv().await.expect("wtd recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, dmsg),
        other => panic!("WTD recv failed: {:?}", other),
    }

    let di = DialInfo::try_webtransport_stream(socket_address, url, vec![[0xABu8; 32]], None)
        .expect("bad-hash dialinfo");
    let result = connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("bad-hash connect io");
    assert!(
        !matches!(result, NetworkResult::Value(_)),
        "connect with an unlisted cert hash must fail, got {:?}",
        result
    );

    mock_registry::terminate(registry).await;
}

fn xorshift_fill(len: usize, seed: u32) -> Bytes {
    let mut state = seed | 1;
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        buf.push((state & 0xFF) as u8);
    }
    Bytes::from(buf)
}

pub async fn test_webtransport_datagram_fragmentation() {
    let registry = mock_registry::init("webtransport_datagram_fragmentation").await;

    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("should generate cert");

    let (server_addr, _endpoint) =
        spawn_echo_server(registry.clone(), &cert).expect("should start echo server");
    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);

    let di = DialInfo::try_webtransport_datagram(socket_address, url, vec![cert.hash], None)
        .expect("wtd dialinfo");
    let dconn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wtd connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTD connect failed: {:?}", other),
    };

    let small = Bytes::from_static(b"hello webtransport datagram");
    assert!(matches!(
        dconn
            .send(small.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("small send io"),
        NetworkResult::Value(())
    ));
    match dconn.recv().await.expect("small recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, small),
        other => panic!("small WTD recv failed: {:?}", other),
    }

    let medium = xorshift_fill(4096, 0xC0FF_EE01);
    assert!(matches!(
        dconn
            .send(medium.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("medium send io"),
        NetworkResult::Value(())
    ));
    match dconn.recv().await.expect("medium recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, medium),
        other => panic!("medium WTD recv failed: {:?}", other),
    }

    let large = xorshift_fill(MAX_MESSAGE_SIZE, 0xDEAD_BEEF);
    match dconn
        .send(large, SAFE_TRANSPORT_MTU)
        .await
        .expect("large send io")
    {
        NetworkResult::InvalidMessage(s) => assert!(
            s.contains("too large"),
            "expected the WTD oversize-cap InvalidMessage, got: {s}"
        ),
        other => panic!(
            "MAX_MESSAGE_SIZE WTD send must be refused by the fragment cap, got: {:?}",
            other
        ),
    }

    let inter_a = xorshift_fill(4096, 0xFEED_FACE);
    let inter_b = xorshift_fill(2500, 0x1234_5678);
    assert!(matches!(
        dconn
            .send(inter_a.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("inter_a send io"),
        NetworkResult::Value(())
    ));
    assert!(matches!(
        dconn
            .send(inter_b.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("inter_b send io"),
        NetworkResult::Value(())
    ));

    let first = match dconn.recv().await.expect("interleave recv 1 io") {
        NetworkResult::Value(b) => b,
        other => panic!("interleave recv 1 failed: {:?}", other),
    };
    let second = match dconn.recv().await.expect("interleave recv 2 io") {
        NetworkResult::Value(b) => b,
        other => panic!("interleave recv 2 failed: {:?}", other),
    };

    let (got_a, got_b) = match (first.len(), second.len()) {
        (4096, _) => (first, second),
        (_, 4096) => (second, first),
        (a, b) => panic!(
            "neither interleaved receive was the 4096-byte message: got {} and {}",
            a, b
        ),
    };
    assert_eq!(
        got_a, inter_a,
        "interleaved message A must round-trip byte-for-byte"
    );
    assert_eq!(
        got_b, inter_b,
        "interleaved message B must round-trip byte-for-byte"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_wtd_oversize_message_returns_invalid_message() {
    let registry = mock_registry::init("wtd_oversize_cap").await;

    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("should generate cert");

    let (server_addr, _endpoint) =
        spawn_echo_server(registry.clone(), &cert).expect("should start echo server");
    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);

    let di = DialInfo::try_webtransport_datagram(socket_address, url, vec![cert.hash], None)
        .expect("wtd dialinfo");
    let dconn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wtd connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTD connect failed: {:?}", other),
    };

    let oversize = xorshift_fill(MAX_MESSAGE_SIZE, 0x0BAD_F00D);
    match dconn
        .send(oversize, SAFE_TRANSPORT_MTU)
        .await
        .expect("oversize send io")
    {
        NetworkResult::InvalidMessage(s) => assert!(
            s.contains("too large"),
            "expected the WTD oversize-cap InvalidMessage, got: {s}"
        ),
        NetworkResult::Value(()) => panic!(
            "REGRESSION: oversize WTD message was accepted/fragmented (Value) instead of \
             refused by the fragment cap"
        ),
        NetworkResult::NoConnection(e) => panic!(
            "oversize WTD message tore the connection down (NoConnection) instead of \
             dropping-and-keeping via InvalidMessage: {e}"
        ),
        other => panic!("expected InvalidMessage from the WTD cap, got: {:?}", other),
    }

    let small = Bytes::from_static(b"still alive after the cap refusal");
    assert!(matches!(
        dconn
            .send(small.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("small send io"),
        NetworkResult::Value(())
    ));
    match dconn.recv().await.expect("small recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, small),
        other => panic!("small WTD recv after cap refusal failed: {:?}", other),
    }

    mock_registry::terminate(registry).await;
}

pub async fn test_shared_port_demux_coexistence() {
    use crate::network_manager::network::native::udp_demux::DemuxerUdpSocket;

    let registry = mock_registry::init("wt_demux_coexistence").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let std_sock =
        std::net::UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap();
    let shared = Arc::new(UdpSocketIo::from_std(std_sock).unwrap());
    let server_addr = shared.local_addr().unwrap();
    let (demux, raw_rx) = DemuxerUdpSocket::try_new(shared).expect("demux socket");

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        webtransport_endpoint_config(),
        Some(build_server_config(&cert).unwrap()),
        demux,
        veilid_quinn_runtime(),
    )
    .expect("endpoint on demux socket");

    let mut server = web_transport_quinn::Server::new(endpoint);
    let echo_registry = registry.clone();
    spawn_detached("wt test demux accept", async move {
        while let Some(request) = server.accept().await {
            let registry = echo_registry.clone();
            spawn_detached("wt test demux session", async move {
                let Ok(session) = request.ok().await else {
                    return;
                };
                if let Ok((send, recv)) = session.accept_bi().await {
                    let flow = echo_flow(session.remote_address(), server_addr, ProtocolType::WTS);
                    let conn =
                        accepted_stream_connection(registry, flow, session.clone(), send, recv);
                    while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                        if conn.send(b).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });

    let di = DialInfo::try_webtransport_stream(
        SocketAddress::from_socket_addr(server_addr),
        format!("https://{}/", server_addr),
        vec![cert.hash],
        None,
    )
    .expect("wts dialinfo");
    let conn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wts connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTS connect through demux failed: {:?}", other),
    };
    let msg = Bytes::from_static(b"quic through the demux");
    assert!(matches!(
        conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("send io"),
        NetworkResult::Value(())
    ));
    match conn.recv().await.expect("recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, msg),
        other => panic!("WTS echo through demux failed: {:?}", other),
    }

    let raw_client = bind_udp_socket_io(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .unwrap()
        .unwrap();
    let raw_payload: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
    raw_client.send_to(raw_payload, server_addr).await.unwrap();

    let forwarded = timeout(5_000, raw_rx.recv_async())
        .await
        .expect("raw datagram should be forwarded, not swallowed by quinn")
        .expect("raw channel open");
    assert_eq!(forwarded.0, raw_client.local_addr().unwrap());
    assert_eq!(forwarded.1, raw_payload);

    mock_registry::terminate(registry).await;
}

pub async fn test_accept_session_classifies_and_roundtrips() {
    let registry = mock_registry::init("wt_accept_session").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let server_config = build_server_config(&cert).unwrap();
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    let mut server = web_transport_quinn::Server::new(endpoint);
    let echo_registry = registry.clone();
    spawn_detached("wt test classify accept", async move {
        while let Some(request) = server.accept().await {
            let registry = echo_registry.clone();
            spawn_detached("wt test classify session", async move {
                let Ok(session) = request.ok().await else {
                    return;
                };
                let Some(conn) = accept_session_connection(registry, server_addr, session).await
                else {
                    return;
                };
                while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                    if conn.send(b).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);

    let di = DialInfo::try_webtransport_stream(socket_address, url.clone(), vec![cert.hash], None)
        .expect("wts dialinfo");
    let conn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wts connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTS connect failed: {:?}", other),
    };
    let msg = Bytes::from_static(b"accepted stream roundtrip");
    assert!(matches!(
        conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("send io"),
        NetworkResult::Value(())
    ));
    match conn.recv().await.expect("recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, msg),
        other => panic!("WTS echo failed (misclassified?): {:?}", other),
    }

    let di =
        DialInfo::try_webtransport_datagram(socket_address, url.clone(), vec![cert.hash], None)
            .expect("wtd dialinfo");
    let dconn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wtd connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTD connect failed: {:?}", other),
    };
    let dmsg = Bytes::from_static(b"accepted datagram roundtrip");
    assert!(matches!(
        dconn
            .send(dmsg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("wtd send io"),
        NetworkResult::Value(())
    ));
    match dconn.recv().await.expect("wtd recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, dmsg),
        other => panic!("WTD echo failed (primed datagram lost?): {:?}", other),
    }

    mock_registry::terminate(registry).await;
}

/// A conforming dialer emits one primitive, so this pins the tie-break for the case the
/// protocol says cannot happen: with a datagram queued first and a stream queued after,
/// `accept_session_connection` still classifies the session as WTS.
pub async fn test_accept_session_prefers_stream_over_queued_datagram() {
    let registry = mock_registry::init("wt_accept_tie_break").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let server_config = build_server_config(&cert).unwrap();
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    let classified: std::sync::Arc<std::sync::Mutex<Option<ProtocolType>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let server_classified = classified.clone();
    let server_registry = registry.clone();
    spawn_detached("wt test tie-break server", async move {
        let mut server = web_transport_quinn::Server::new(endpoint);
        let Some(request) = server.accept().await else {
            return;
        };
        let Ok(session) = request.ok().await else {
            return;
        };
        // Both primitives must be queued before the classification races them.
        sleep(1_000).await;
        let Some(conn) = accept_session_connection(server_registry, server_addr, session).await
        else {
            return;
        };
        *server_classified.lock().unwrap() = Some(conn.flow().protocol_type());
    });

    let client_config = build_client_config(vec![cert.hash]).expect("client config");
    let client_ep = veilid_quinn_client_endpoint(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("client endpoint");
    let client = web_transport_quinn::Client::new(client_ep, client_config);
    let url = url::Url::parse(&format!("https://{}/", server_addr)).expect("url");
    let session = match timeout(10_000, client.connect(url)).await {
        Ok(Ok(s)) => s,
        other => panic!("WebTransport handshake failed: {:?}", other),
    };

    session
        .send_datagram(Bytes::from_static(b"datagram queued first"))
        .expect("send datagram");
    let (mut send, _recv) = session.open_bi().await.expect("open_bi");
    let payload: &[u8] = b"stream queued second";
    send.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .expect("stream length write");
    send.write_all(payload).await.expect("stream body write");

    let mut got = None;
    for _ in 0..60 {
        if let Some(pt) = *classified.lock().unwrap() {
            got = Some(pt);
            break;
        }
        sleep(50).await;
    }
    assert_eq!(
        got,
        Some(ProtocolType::WTS),
        "with a stream and a datagram both queued, classification must break the tie toward WTS"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_connect_reuses_supplied_client_endpoint() {
    let registry = mock_registry::init("wt_connect_reuse").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let server_config = build_server_config(&cert).unwrap();
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    let mut server = web_transport_quinn::Server::new(endpoint);
    let echo_registry = registry.clone();
    spawn_detached("wt test reuse accept", async move {
        while let Some(request) = server.accept().await {
            let registry = echo_registry.clone();
            spawn_detached("wt test reuse session", async move {
                let Ok(session) = request.ok().await else {
                    return;
                };
                let Some(conn) = accept_session_connection(registry, server_addr, session).await
                else {
                    return;
                };
                while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                    if conn.send(b).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let client_endpoint =
        veilid_quinn_client_endpoint(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap();
    let client_port = client_endpoint.local_addr().unwrap().port();

    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);

    for attempt in 0..2 {
        let di =
            DialInfo::try_webtransport_stream(socket_address, url.clone(), vec![cert.hash], None)
                .expect("wts dialinfo");
        let conn = match connect(
            registry.clone(),
            None,
            di,
            10_000,
            Some(client_endpoint.clone()),
        )
        .await
        .expect("wts connect io")
        {
            NetworkResult::Value(c) => c,
            other => panic!("attempt {attempt}: WTS connect failed: {:?}", other),
        };

        let local = conn
            .flow()
            .local()
            .expect("outbound flow must have a local address");
        assert_eq!(
            local.socket_addr().port(),
            client_port,
            "attempt {attempt}: connect must reuse the supplied client endpoint"
        );

        let msg = Bytes::from_static(b"reused endpoint roundtrip");
        assert!(matches!(
            conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
                .await
                .expect("send io"),
            NetworkResult::Value(())
        ));
        match conn.recv().await.expect("recv io") {
            NetworkResult::Value(echo) => assert_eq!(echo, msg),
            other => panic!("attempt {attempt}: echo failed: {:?}", other),
        }
        drop(conn);
    }

    mock_registry::terminate(registry).await;
}

pub async fn test_accept_wildcard_bind_resolves_local_ip() {
    let registry = mock_registry::init("wt_accept_wildcard").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let server_config = build_server_config(&cert).unwrap();
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
    )
    .unwrap();
    let bind_addr = endpoint.local_addr().unwrap();
    assert!(
        bind_addr.ip().is_unspecified(),
        "test precondition: server must be bound to the wildcard address"
    );
    let port = bind_addr.port();

    let captured_flow: std::sync::Arc<std::sync::Mutex<Option<Flow>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));

    let mut server = web_transport_quinn::Server::new(endpoint);
    let echo_registry = registry.clone();
    let flow_slot = captured_flow.clone();
    spawn_detached("wt test wildcard accept", async move {
        while let Some(request) = server.accept().await {
            let registry = echo_registry.clone();
            let flow_slot = flow_slot.clone();
            spawn_detached("wt test wildcard session", async move {
                let Ok(session) = request.ok().await else {
                    return;
                };
                let Some(conn) = accept_session_connection(registry, bind_addr, session).await
                else {
                    return;
                };
                *flow_slot.lock().unwrap() = Some(conn.flow());
                while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                    if conn.send(b).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let socket_address = SocketAddress::from_socket_addr(connect_addr);
    let url = format!("https://{}/", connect_addr);
    let di = DialInfo::try_webtransport_stream(socket_address, url, vec![cert.hash], None)
        .expect("wts dialinfo");
    let conn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wts connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTS connect to wildcard-bound server failed: {:?}", other),
    };
    let msg = Bytes::from_static(b"wildcard accept roundtrip");
    assert!(matches!(
        conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("send io"),
        NetworkResult::Value(())
    ));
    match conn.recv().await.expect("recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, msg),
        other => panic!("WTS echo over wildcard bind failed: {:?}", other),
    }

    let flow = captured_flow
        .lock()
        .unwrap()
        .take()
        .expect("server should have captured an accepted flow");
    let local = flow
        .local()
        .expect("accepted flow must have a local address");
    assert!(
        !local.socket_addr().ip().is_unspecified(),
        "accepted WTS flow local address must be specified, got {}",
        local.socket_addr()
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_flush_and_close_delivers_before_drop() {
    let registry = mock_registry::init("wt_unbound_flush").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let server_config = build_server_config(&cert).unwrap();
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    let received: std::sync::Arc<std::sync::Mutex<Option<Bytes>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let server_received = received.clone();
    let server_registry = registry.clone();
    spawn_detached("wt test unbound server", async move {
        let mut server = web_transport_quinn::Server::new(endpoint);
        if let Some(request) = server.accept().await {
            if let Ok(session) = request.ok().await {
                if let Some(conn) =
                    accept_session_connection(server_registry, server_addr, session).await
                {
                    if let Ok(NetworkResult::Value(b)) = conn.recv().await {
                        *server_received.lock().unwrap() = Some(b);
                    }
                }
            }
        }
    });

    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);
    let di = DialInfo::try_webtransport_stream(socket_address, url, vec![cert.hash], None)
        .expect("wts dialinfo");
    let msg = Bytes::from_static(b"unbound flush must deliver this");
    {
        let conn = match connect_connection(registry.clone(), None, di, 10_000, None)
            .await
            .expect("connect io")
        {
            NetworkResult::Value(c) => c,
            other => panic!("WTS connect failed: {:?}", other),
        };
        assert!(matches!(
            conn.send(msg.clone()).await.expect("send io"),
            NetworkResult::Value(())
        ));
        let flush = conn.flush_and_close().await;
        drop(conn);
        flush.await;
    }

    let mut got = None;
    for _ in 0..60 {
        if let Some(b) = received.lock().unwrap().clone() {
            got = Some(b);
            break;
        }
        sleep(50).await;
    }
    assert_eq!(
        got.as_deref(),
        Some(msg.as_ref()),
        "unbound WTS send must be flushed/delivered before the connection drops"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_webtransport_ca_signed_roundtrip() {
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType,
        PKCS_ECDSA_P256_SHA256,
    };

    let registry = mock_registry::init("webtransport_ca_signed").await;

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-signed");

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf signed by ca");

    let cert_chain = vec![
        CertificateDer::from(leaf_cert.der().to_vec()),
        CertificateDer::from(ca_cert.der().to_vec()),
    ];
    let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let server_config =
        build_server_config_from_chain(cert_chain, leaf_key_der).expect("server config");

    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .expect("server endpoint");
    let server_addr = endpoint.local_addr().expect("server addr");

    let echo_registry = registry.clone();
    spawn_detached("wt test ca accept", async move {
        let mut server = web_transport_quinn::Server::new(endpoint);
        while let Some(request) = server.accept().await {
            let registry = echo_registry.clone();
            spawn_detached("wt test ca session", async move {
                let Ok(session) = request.ok().await else {
                    return;
                };
                let Some(conn) = accept_session_connection(registry, server_addr, session).await
                else {
                    return;
                };
                while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                    if conn.send(b).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(ca_cert.der().to_vec()))
        .expect("add ca root");
    let client_config = build_client_config_with_root_store(root_store).expect("ca client config");

    let client_ep = veilid_quinn_client_endpoint(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("client endpoint");
    let client = web_transport_quinn::Client::new(client_ep, client_config);
    let url = url::Url::parse(&format!("https://127.0.0.1:{}/", server_addr.port())).expect("url");
    let session = match timeout(10_000, client.connect(url)).await {
        Ok(Ok(s)) => s,
        other => panic!("CA-signed WebTransport handshake failed: {:?}", other),
    };

    let flow = Flow::new(
        PeerAddress::new(
            SocketAddress::from_socket_addr(server_addr),
            ProtocolType::WTS,
        ),
        SocketAddress::from_socket_addr(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)),
    );
    let (send, recv) = session.open_bi().await.expect("open_bi");
    let conn = WebTransportNetworkConnection::new_stream(
        registry.clone(),
        flow,
        Direction::Out,
        session,
        send,
        recv,
    );
    let msg = Bytes::from_static(b"hello ca webtransport");
    assert!(matches!(
        conn.send(msg.clone()).await.expect("send io"),
        NetworkResult::Value(())
    ));
    match conn.recv().await.expect("recv io") {
        NetworkResult::Value(echo) => assert_eq!(echo, msg),
        other => panic!("CA-signed WTS echo failed: {:?}", other),
    }

    mock_registry::terminate(registry).await;
}

pub async fn test_webtransport_ca_resolver_serves_ip_cert_for_ip_literal() {
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType,
        PKCS_ECDSA_P256_SHA256,
    };

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-signed");
    let ca_root = CertificateDer::from(ca_cert.der().to_vec());

    // A CA-signed leaf carrying `sans`, as a CertifiedKey (leaf + CA chain).
    let make_ck = |sans: Vec<SanType>| {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut leaf_params = CertificateParams::default();
        leaf_params.subject_alt_names = sans;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf signed by ca");
        let chain = vec![
            CertificateDer::from(leaf_cert.der().to_vec()),
            CertificateDer::from(ca_cert.der().to_vec()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        certified_key_from_chain(chain, key).expect("certified key")
    };

    let hostname_ck = make_ck(vec![SanType::DnsName(
        "bootstrap.test".try_into().expect("dns san"),
    )]);
    let ip_ck = make_ck(vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())]);

    let connect_ip_literal = |server_config: quinn::ServerConfig| {
        let ca_root = ca_root.clone();
        async move {
            let endpoint = test_server_endpoint(
                server_config,
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            )
            .expect("server endpoint");
            let server_addr = endpoint.local_addr().expect("server addr");
            spawn_detached("wt test ip literal accept", async move {
                let mut server = web_transport_quinn::Server::new(endpoint);
                while let Some(request) = server.accept().await {
                    spawn_detached("wt test ip literal session", async move {
                        let _ = request.ok().await;
                    });
                }
            });

            let mut root_store = RootCertStore::empty();
            root_store.add(ca_root).expect("add ca root");
            let client_config =
                build_client_config_with_root_store(root_store).expect("ca client config");
            let client_ep =
                veilid_quinn_client_endpoint(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                    .expect("client endpoint");
            let client = web_transport_quinn::Client::new(client_ep, client_config);
            let url = url::Url::parse(&format!("https://127.0.0.1:{}/", server_addr.port()))
                .expect("url");
            matches!(timeout(10_000, client.connect(url)).await, Ok(Ok(_)))
        }
    };

    let with_ip = build_ca_server_config(hostname_ck.clone(), Some(ip_ck)).expect("config with ip");
    assert!(
        connect_ip_literal(with_ip).await,
        "IP-literal handshake should succeed when the IP-SAN cert is served for no-SNI"
    );

    let without_ip = build_ca_server_config(hostname_ck, None).expect("config hostname only");
    assert!(
        !connect_ip_literal(without_ip).await,
        "IP-literal handshake should fail when only the DNS-SAN hostname cert is served"
    );
}

pub async fn test_webtransport_live_cert_swap() {
    let registry = mock_registry::init("wt_live_swap").await;
    let validity = TimestampDuration::new_secs(12 * 24 * 60 * 60);
    let cert_a = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(validity),
        Timestamp::now(),
    )
    .expect("cert A");

    let (server_addr, endpoint) =
        spawn_echo_server(registry.clone(), &cert_a).expect("echo server");
    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);

    let di_a =
        DialInfo::try_webtransport_stream(socket_address, url.clone(), vec![cert_a.hash], None)
            .expect("wts dialinfo A");
    let conn = match connect(registry.clone(), None, di_a, 10_000, None)
        .await
        .expect("A connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("connect with cert A failed: {:?}", other),
    };
    let msg = Bytes::from_static(b"before swap");
    assert!(matches!(
        conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("send io"),
        NetworkResult::Value(())
    ));
    assert!(matches!(conn.recv().await.expect("recv io"), NetworkResult::Value(e) if e == msg));

    let cert_b = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(validity),
        Timestamp::now(),
    )
    .expect("cert B");
    assert_ne!(cert_a.hash, cert_b.hash, "test needs distinct certs");
    endpoint.set_server_config(Some(build_server_config(&cert_b).expect("server config B")));

    let di_b =
        DialInfo::try_webtransport_stream(socket_address, url.clone(), vec![cert_b.hash], None)
            .expect("wts dialinfo B");
    let conn_b = match connect(registry.clone(), None, di_b, 10_000, None)
        .await
        .expect("B connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("connect with cert B failed after swap: {:?}", other),
    };
    let msg_b = Bytes::from_static(b"after swap");
    assert!(matches!(
        conn_b
            .send(msg_b.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("send io"),
        NetworkResult::Value(())
    ));
    assert!(matches!(conn_b.recv().await.expect("recv io"), NetworkResult::Value(e) if e == msg_b));

    let di_stale = DialInfo::try_webtransport_stream(socket_address, url, vec![cert_a.hash], None)
        .expect("wts dialinfo stale");
    let result = connect(registry.clone(), None, di_stale, 5_000, None)
        .await
        .expect("stale connect io");
    assert!(
        !matches!(result, NetworkResult::Value(_)),
        "client pinning the pre-swap hash must fail after the swap, got {:?}",
        result
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_webtransport_ca_cert_file_reload() {
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType,
        PKCS_ECDSA_P256_SHA256,
    };
    use std::io::Write;

    // Encode DER as a PEM block (rcgen's own `.pem()` needs its `pem` feature, which
    // we don't enable, so build it from the DER directly).
    fn der_to_pem(label: &str, der: &[u8]) -> String {
        let b64 = data_encoding::BASE64.encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    }

    fn make_ca_chain() -> (Vec<u8>, String, String) {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-signed");
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut leaf_params = CertificateParams::default();
        leaf_params.subject_alt_names = vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf signed");
        let chain_pem = format!(
            "{}{}",
            der_to_pem("CERTIFICATE", leaf_cert.der()),
            der_to_pem("CERTIFICATE", ca_cert.der())
        );
        let key_pem = der_to_pem("PRIVATE KEY", &leaf_key.serialize_der());
        (ca_cert.der().to_vec(), chain_pem, key_pem)
    }

    fn server_config_from_files(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> quinn::ServerConfig {
        let cert_chain = NativeNetwork::load_certs(cert_path).expect("read cert chain");
        let mut keys = NativeNetwork::load_keys(key_path).expect("read keys");
        assert!(!keys.is_empty(), "no private key in {}", key_path.display());
        build_server_config_from_chain(cert_chain, keys.remove(0))
            .expect("server config from files")
    }

    let registry = mock_registry::init("wt_ca_reload").await;

    let dir = std::env::temp_dir().join(format!("veilid_wt_ca_reload_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let (ca1_der, chain1, key1) = make_ca_chain();
    std::fs::File::create(&cert_path)
        .unwrap()
        .write_all(chain1.as_bytes())
        .unwrap();
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key1.as_bytes())
        .unwrap();

    let endpoint = test_server_endpoint(
        server_config_from_files(&cert_path, &key_path),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .expect("server endpoint");
    let server_addr = endpoint.local_addr().unwrap();

    let accept_ep = endpoint.clone();
    let echo_registry = registry.clone();
    spawn_detached("wt test ca reload accept", async move {
        let mut server = web_transport_quinn::Server::new(accept_ep);
        while let Some(request) = server.accept().await {
            let registry = echo_registry.clone();
            spawn_detached("wt test ca reload session", async move {
                let Ok(session) = request.ok().await else {
                    return;
                };
                let Some(conn) = accept_session_connection(registry, server_addr, session).await
                else {
                    return;
                };
                while let Ok(NetworkResult::Value(b)) = conn.recv().await {
                    if conn.send(b).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    async fn try_connect(ca_der: &[u8], port: u16) -> bool {
        let mut root_store = RootCertStore::empty();
        if root_store
            .add(CertificateDer::from(ca_der.to_vec()))
            .is_err()
        {
            return false;
        }
        let Ok(client_config) = build_client_config_with_root_store(root_store) else {
            return false;
        };
        let Ok(client_ep) =
            veilid_quinn_client_endpoint(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        else {
            return false;
        };
        let client = web_transport_quinn::Client::new(client_ep, client_config);
        let url = url::Url::parse(&format!("https://127.0.0.1:{}/", port)).unwrap();
        matches!(timeout(8_000, client.connect(url)).await, Ok(Ok(_)))
    }

    assert!(
        try_connect(&ca1_der, server_addr.port()).await,
        "CA #1 should connect initially"
    );

    let (ca2_der, chain2, key2) = make_ca_chain();
    std::fs::File::create(&cert_path)
        .unwrap()
        .write_all(chain2.as_bytes())
        .unwrap();
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key2.as_bytes())
        .unwrap();
    endpoint.set_server_config(Some(server_config_from_files(&cert_path, &key_path)));

    assert!(
        try_connect(&ca2_der, server_addr.port()).await,
        "CA #2 should connect after reload"
    );
    assert!(
        !try_connect(&ca1_der, server_addr.port()).await,
        "CA #1 must be rejected after reload"
    );

    let _ = std::fs::remove_dir_all(&dir);
    mock_registry::terminate(registry).await;
}

pub async fn test_webtransport_connect_via_shared_endpoint() {
    let registry = mock_registry::init("wt_shared_connect").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(12 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("cert");
    let (server_addr, _server_endpoint) =
        spawn_echo_server(registry.clone(), &cert).expect("echo server");

    let shared = veilid_quinn_client_endpoint(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("shared endpoint");
    let _shared_keepalive = shared.clone();

    let di = DialInfo::try_webtransport_stream(
        SocketAddress::from_socket_addr(server_addr),
        format!("https://{}/", server_addr),
        vec![cert.hash],
        None,
    )
    .expect("wts dialinfo");
    let conn = match connect_via_shared_endpoint(registry.clone(), shared, di, 10_000)
        .await
        .expect("connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("connect_via_shared_endpoint failed: {:?}", other),
    };
    let msg = Bytes::from_static(b"shared endpoint connect");
    assert!(matches!(
        conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("send io"),
        NetworkResult::Value(())
    ));
    assert!(matches!(conn.recv().await.expect("recv io"), NetworkResult::Value(e) if e == msg));

    mock_registry::terminate(registry).await;
}

pub async fn test_webtransport_shared_server_endpoint_connects_out() {
    let registry = mock_registry::init("wt_shared_server_connect").await;
    let validity = TimestampDuration::new_secs(12 * 24 * 60 * 60);

    let cert_b = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(validity),
        Timestamp::now(),
    )
    .expect("cert B");
    let (b_addr, _b_endpoint) =
        spawn_echo_server(registry.clone(), &cert_b).expect("echo server B");

    let cert_a = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(validity),
        Timestamp::now(),
    )
    .expect("cert A");
    let a_endpoint = test_server_endpoint(
        build_server_config(&cert_a).expect("server config A"),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .expect("server endpoint A");
    let _a_keepalive = a_endpoint.clone();

    let di = DialInfo::try_webtransport_stream(
        SocketAddress::from_socket_addr(b_addr),
        format!("https://{}/", b_addr),
        vec![cert_b.hash],
        None,
    )
    .expect("wts dialinfo");
    let conn = match connect_via_shared_endpoint(registry.clone(), a_endpoint, di, 10_000)
        .await
        .expect("connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!(
            "server-configured endpoint failed to connect out: {:?}",
            other
        ),
    };
    let msg = Bytes::from_static(b"shared server endpoint connects out");
    assert!(matches!(
        conn.send(msg.clone(), SAFE_TRANSPORT_MTU)
            .await
            .expect("send io"),
        NetworkResult::Value(())
    ));
    assert!(matches!(conn.recv().await.expect("recv io"), NetworkResult::Value(e) if e == msg));

    mock_registry::terminate(registry).await;
}

fn spawn_parking_server(
    cert: &ManagedCertificate,
    transport: quinn::TransportConfig,
) -> io::Result<SocketAddr> {
    let mut server_config = build_server_config(cert)?;
    server_config.transport_config(Arc::new(transport));
    let endpoint = test_server_endpoint(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )?;
    let server_addr = endpoint.local_addr()?;
    spawn_detached("wt test parking accept", async move {
        let mut server = web_transport_quinn::Server::new(endpoint);
        while let Some(request) = server.accept().await {
            spawn_detached("wt test parking session", async move {
                if let Ok(session) = request.ok().await {
                    let _ = timeout(30_000, session.closed()).await;
                }
            });
        }
    });
    Ok(server_addr)
}

pub async fn test_wtd_send_budget_collapse_returns_invalid_message() {
    let registry = mock_registry::init("wtd_budget_collapse").await;

    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("should generate cert");

    // Server that advertises a tiny max_datagram_frame_size. quinn derives the advertised
    // frame size from `datagram_receive_buffer_size` (min(x, u16::MAX)); a small value
    // makes the client's `session.max_datagram_size()` collapse below
    // MIN_WTD_DATAGRAM_SIZE while keeping datagrams enabled (Some, non-zero) so the
    // WebTransport session still handshakes over its CONNECT stream.
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(200));
    let server_addr =
        spawn_parking_server(&cert, transport).expect("parking server (tiny datagram budget)");

    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);
    let di = DialInfo::try_webtransport_datagram(socket_address, url, vec![cert.hash], None)
        .expect("wtd dialinfo");
    let dconn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wtd connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTD connect failed: {:?}", other),
    };

    let result = dconn
        .send(
            Bytes::from_static(b"transient-budget-collapse"),
            SAFE_TRANSPORT_MTU,
        )
        .await
        .expect("wtd send io");

    match result {
        NetworkResult::InvalidMessage(s) => {
            assert!(
                s.contains("budget too small"),
                "expected the datagram-budget-collapse InvalidMessage, got a different \
                 InvalidMessage: {s}"
            );
        }
        NetworkResult::NoConnection(e) => panic!(
            "REGRESSION: WTD budget collapse returned NoConnection (tears the connection \
             down) instead of InvalidMessage (keep-alive): {e}"
        ),
        other => panic!(
            "expected InvalidMessage from datagram budget collapse, got: {:?}",
            other
        ),
    }

    mock_registry::terminate(registry).await;
}

pub async fn test_wtd_max_datagram_size_no_panic_when_peer_disables_datagrams() {
    let registry = mock_registry::init("wt_datagram_disabled_no_panic").await;
    let cert = CertificateManager::generate_certificate(
        &webtransport_certificate_profile(TimestampDuration::new_secs(7 * 24 * 60 * 60)),
        Timestamp::now(),
    )
    .expect("generate cert");

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(None);
    let server_addr =
        spawn_parking_server(&cert, transport).expect("parking server (datagrams disabled)");

    let socket_address = SocketAddress::from_socket_addr(server_addr);
    let url = format!("https://{}/", server_addr);
    let di = DialInfo::try_webtransport_datagram(socket_address, url, vec![cert.hash], None)
        .expect("wtd dialinfo");
    let dconn = match connect(registry.clone(), None, di, 10_000, None)
        .await
        .expect("wtd connect io")
    {
        NetworkResult::Value(c) => c,
        other => panic!(
            "REFUTE/PARTIAL: WTD connect failed against a datagram-disabled peer, so \
             send()/max_datagram_size() are never reached: {:?}",
            other
        ),
    };

    let result = dconn
        .send(
            Bytes::from_static(b"peer-disabled-datagrams"),
            SAFE_TRANSPORT_MTU,
        )
        .await
        .expect("wtd send io");
    match result {
        NetworkResult::InvalidMessage(_) => {}
        other => panic!(
            "expected InvalidMessage from a datagram-disabled peer, got: {:?}",
            other
        ),
    }

    let (ok_addr, _ok_endpoint) =
        spawn_echo_server(registry.clone(), &cert).expect("echo server (datagrams enabled)");
    let ok_socket = SocketAddress::from_socket_addr(ok_addr);
    let ok_url = format!("https://{}/", ok_addr);
    let ok_di = DialInfo::try_webtransport_datagram(ok_socket, ok_url, vec![cert.hash], None)
        .expect("wtd dialinfo (enabled)");
    let ok_dconn = match connect(registry.clone(), None, ok_di, 10_000, None)
        .await
        .expect("wtd connect io (enabled)")
    {
        NetworkResult::Value(c) => c,
        other => panic!("WTD connect (datagram-enabled control) failed: {:?}", other),
    };
    let ok_result = ok_dconn
        .send(
            Bytes::from_static(b"peer-enabled-datagrams"),
            SAFE_TRANSPORT_MTU,
        )
        .await
        .expect("wtd send io (enabled)");
    assert!(
        matches!(ok_result, NetworkResult::Value(())),
        "control: a datagram-enabled peer must accept the send, got: {:?}",
        ok_result
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_all() {
    test_cert_hash_mismatch_is_distinct_from_ca_failure();
    test_webtransport_endpoint_config_disables_quic_bit_greasing();
    Box::pin(test_webtransport_loopback()).await;
    Box::pin(test_webtransport_datagram_fragmentation()).await;
    Box::pin(test_wtd_oversize_message_returns_invalid_message()).await;
    Box::pin(test_shared_port_demux_coexistence()).await;
    Box::pin(test_accept_session_classifies_and_roundtrips()).await;
    Box::pin(test_accept_session_prefers_stream_over_queued_datagram()).await;
    Box::pin(test_connect_reuses_supplied_client_endpoint()).await;
    Box::pin(test_accept_wildcard_bind_resolves_local_ip()).await;
    Box::pin(test_flush_and_close_delivers_before_drop()).await;
    Box::pin(test_webtransport_ca_signed_roundtrip()).await;
    Box::pin(test_webtransport_ca_resolver_serves_ip_cert_for_ip_literal()).await;
    Box::pin(test_webtransport_live_cert_swap()).await;
    Box::pin(test_webtransport_ca_cert_file_reload()).await;
    Box::pin(test_webtransport_connect_via_shared_endpoint()).await;
    Box::pin(test_webtransport_shared_server_endpoint_connects_out()).await;
    Box::pin(test_wtd_send_budget_collapse_returns_invalid_message()).await;
    Box::pin(test_wtd_max_datagram_size_no_panic_when_peer_disables_datagrams()).await;
}
