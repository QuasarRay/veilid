//! One DNS exchange with one nameserver over UDP or TCP, bounded by a timeout.

use super::*;
use futures_util::{AsyncReadExt, AsyncWriteExt};
use std::io;

/// Wire transport for a single exchange
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

/// Datagrams that fail to match the query before the attempt is abandoned
const MAX_UNMATCHED_DATAGRAMS: usize = 64;

/// Send `query` to `server` and return the matching reply, or `DnsError::Timeout` after `timeout_ms`
pub(crate) async fn exchange(
    server: SocketAddr,
    transport: Transport,
    query: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    timeout_ms: u32,
) -> Result<Response, DnsError> {
    let attempt: PinBoxFuture<'_, Result<Response, DnsError>> = match transport {
        Transport::Udp => Box::pin(exchange_udp(server, query, id, name, qtype)),
        Transport::Tcp => Box::pin(exchange_tcp(server, query, id, name, qtype)),
    };
    timeout(timeout_ms, attempt)
        .await
        .map_err(|_| DnsError::Timeout)?
}

async fn exchange_udp(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
) -> Result<Response, DnsError> {
    let socket = bind_ephemeral_udp(server)?;
    // Connected so the kernel filters the source and reports ICMP unreachable as an error
    socket.connect(server).await?;
    if socket.send(query).await? != query.len() {
        return Err(DnsError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "short send",
        )));
    }
    let mut buf = vec![0u8; MAX_UDP_MESSAGE_LEN];
    for _ in 0..MAX_UNMATCHED_DATAGRAMS {
        let n = socket.recv(&mut buf).await?;
        if let Ok(resp) = parse_response(&buf[..n]) {
            if resp.matches(id, name, qtype) {
                return Ok(resp);
            }
        }
    }
    Err(DnsError::Malformed("unmatched datagrams"))
}

async fn exchange_tcp(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
) -> Result<Response, DnsError> {
    let stream = TcpStream::connect(server).await?;
    #[cfg(feature = "rt-tokio")]
    let mut stream = stream.compat();
    #[cfg(feature = "rt-async-std")]
    let mut stream = stream;

    // Length prefix and query in one write so they share a segment
    let len = u16::try_from(query.len()).map_err(|_| DnsError::Malformed("query too long"))?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len < HEADER_LEN {
        return Err(DnsError::Malformed("short tcp message"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let resp = parse_response(&buf)?;
    if !resp.matches(id, name, qtype) {
        return Err(DnsError::Malformed("tcp response mismatch"));
    }
    Ok(resp)
}

/// An unshared socket on an ephemeral port in the server's address family
fn bind_ephemeral_udp(server: SocketAddr) -> io::Result<UdpSocket> {
    let std_socket = std::net::UdpSocket::bind(compatible_unspecified_socket_addr(&server))?;
    cfg_if! {
        if #[cfg(feature="rt-async-std")] {
            Ok(UdpSocket::from(std_socket))
        } else if #[cfg(feature="rt-tokio")] {
            std_socket.set_nonblocking(true)?;
            UdpSocket::from_std(std_socket)
        } else {
            compile_error!("needs executor implementation");
        }
    }
}
