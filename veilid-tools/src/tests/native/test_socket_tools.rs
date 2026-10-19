use crate::*;

cfg_if! {
    if #[cfg(feature="rt-async-std")] {
        use async_std::net::{TcpListener, TcpStream};
    } else if #[cfg(feature="rt-tokio")] {
        use tokio::net::{TcpListener, TcpStream};
    }
}

/// Linger and other option changes reach the socket through a borrowed view that never
/// closes it, so the stream stays usable afterwards
pub async fn test_borrowed_socket_operations() {
    info!("-- test_borrowed_socket_operations");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("local addr");
    let (client, server) =
        futures_util::future::join(TcpStream::connect(addr), listener.accept()).await;
    let client = client.expect("connect");
    let (_server, _) = server.expect("accept");

    set_tcp_stream_linger(&client, Some(core::time::Duration::from_secs(0))).expect("linger on");
    let linger = socket2_operation(&client, |s| s.linger()).expect("read linger");
    assert_eq!(linger, Some(core::time::Duration::from_secs(0)));
    set_tcp_stream_linger(&client, None).expect("linger off");
    assert_eq!(
        socket2_operation(&client, |s| s.linger()).expect("read linger"),
        None
    );

    // The stream still works, so nothing above closed its descriptor
    assert!(client.local_addr().is_ok());
    assert!(client.peer_addr().is_ok());
}

/// A port unreachable for one of our sends stays out of the next receive, as on other platforms
#[cfg(windows)]
pub async fn test_udp_icmp_errors_stay_out_of_recv() {
    info!("-- test_udp_icmp_errors_stay_out_of_recv");
    let socket = bind_async_udp_socket(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind should not error")
        .expect("bind should succeed");
    // A loopback port nobody listens on
    let closed = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("probe bind")
        .local_addr()
        .expect("probe addr");
    socket.send_to(b"x", closed).await.expect("send");
    let mut buf = [0u8; 16];
    let res = timeout(500, socket.recv_from(&mut buf)).await;
    assert!(res.is_err(), "receive should wait, not fail: {:?}", res);
}

pub async fn test_all() {
    test_borrowed_socket_operations().await;
    #[cfg(windows)]
    test_udp_icmp_errors_stay_out_of_recv().await;
}
