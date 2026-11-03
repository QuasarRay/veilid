use crate::*;

use std::io;

fn bind_loopback() -> UdpSocketIo {
    bind_udp_socket_io(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("bind should not error")
        .expect("loopback ephemeral port should bind")
}

/// The boxed future quinn's `UdpPoller` holds, which is `Sync` as well as `Send`.
type BoxedWritable = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

fn writable_shared(socket: Arc<UdpSocketIo>) -> BoxedWritable {
    Box::pin(async move { socket.writable().await })
}

fn raw_recv(socket: &UdpSocketIo, buf: &mut [u8]) -> io::Result<usize> {
    socket2_operation(socket, |mut s| {
        use std::io::Read;
        s.read(buf)
    })
}

pub async fn test_send_recv_roundtrip() {
    let a = bind_loopback();
    let b = bind_loopback();
    let a_addr = a.local_addr().expect("local_addr");
    let b_addr = b.local_addr().expect("local_addr");

    assert_eq!(a.send_to(b"ping", b_addr).await.expect("send_to"), 4);
    let mut buf = [0u8; 16];
    let (n, from) = b.recv_from(&mut buf).await.expect("recv_from");
    assert_eq!(&buf[..n], b"ping");
    assert_eq!(from, a_addr);

    assert_eq!(b.send_to(b"pong", a_addr).await.expect("send_to"), 4);
    let (n, from) = a.recv_from(&mut buf).await.expect("recv_from");
    assert_eq!(&buf[..n], b"pong");
    assert_eq!(from, b_addr);
}

pub async fn test_readiness_and_try_io() {
    let a = Arc::new(bind_loopback());
    let b = bind_loopback();
    let a_addr = a.local_addr().expect("local_addr");
    let b_addr = b.local_addr().expect("local_addr");

    assert!(
        timeout(200, std::future::poll_fn(|cx| a.poll_recv_ready(cx)))
            .await
            .is_err(),
        "poll_recv_ready must stay pending while the socket is empty"
    );

    let mut buf = [0u8; 16];
    let err = a
        .try_io(Interest::READABLE, || raw_recv(&a, &mut buf))
        .expect_err("an empty socket must not yield a datagram");
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

    b.send_to(b"ready", a_addr).await.expect("send_to");

    timeout(10_000, std::future::poll_fn(|cx| a.poll_recv_ready(cx)))
        .await
        .expect("readiness should arrive well inside the timeout")
        .expect("poll_recv_ready");
    let n = a
        .try_io(Interest::READABLE, || raw_recv(&a, &mut buf))
        .expect("a readable socket must yield the datagram");
    assert_eq!(&buf[..n], b"ready");

    timeout(10_000, writable_shared(a.clone()))
        .await
        .expect("a fresh socket should be writable")
        .expect("writable");

    a.send_to(b"back", b_addr).await.expect("send_to");
    let (n, from) = b.recv_from(&mut buf).await.expect("recv_from");
    assert_eq!(&buf[..n], b"back");
    assert_eq!(from, a_addr);
}

pub async fn test_into_std_roundtrip() {
    let a = bind_loopback();
    let a_addr = a.local_addr().expect("local_addr");

    let std_socket = a.into_std().expect("into_std");
    assert_eq!(std_socket.local_addr().expect("local_addr"), a_addr);

    let a = UdpSocketIo::from_std(std_socket).expect("from_std");
    assert_eq!(a.local_addr().expect("local_addr"), a_addr);

    let b = bind_loopback();
    b.send_to(b"again", a_addr).await.expect("send_to");
    let mut buf = [0u8; 16];
    let (n, _from) = a.recv_from(&mut buf).await.expect("recv_from");
    assert_eq!(&buf[..n], b"again");
}

pub fn test_probed_bind_refuses_an_occupied_port() {
    let held = std::net::UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("probe target should bind");
    let addr = held.local_addr().expect("local_addr");

    assert!(
        bind_udp_socket_io_probed(addr)
            .expect("probed bind should not error")
            .is_none(),
        "an occupied port must fail the probe instead of reuse-binding"
    );
}

pub async fn test_all() {
    test_send_recv_roundtrip().await;
    test_readiness_and_try_io().await;
    test_into_std_roundtrip().await;
    test_probed_bind_refuses_an_occupied_port();
}
