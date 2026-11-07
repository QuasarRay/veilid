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

/// A loopback connection, both ends, made with `mss` on the listener, the connect and the accepted
/// stream
async fn mss_pair(mss: Option<u32>) -> (TcpStream, TcpStream) {
    let any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let listener = bind_async_tcp_listener(any, mss)
        .expect("bind should not error")
        .expect("bind should succeed");
    let addr = listener.local_addr().expect("local addr");
    let (client, server) = futures_util::future::join(
        connect_async_tcp_stream(None, addr, 1000, mss),
        listener.accept(),
    )
    .await;
    let TimeoutOr::Value(client) = client.expect("connect") else {
        panic!("connect timed out");
    };
    let (server, _) = server.expect("accept");
    if let Some(mss) = mss {
        limit_tcp_stream_mss(&server, mss).expect("limit accepted stream");
    }
    (client, server)
}

/// A clamp keeps both ends' segments within it, where loopback alone would carry far larger ones
pub async fn test_tcp_mss_clamp() {
    info!("-- test_tcp_mss_clamp");
    let (client, server) = mss_pair(None).await;
    let plain = tcp_stream_mss(&client).expect("client mss");
    assert!(plain > 1200, "loopback segments of {}", plain);
    drop((client, server));

    let (client, server) = mss_pair(Some(1200)).await;
    for (end, stream) in [("client", &client), ("server", &server)] {
        let mss = tcp_stream_mss(stream).expect("mss");
        assert!(mss <= 1200, "{} sends segments of {}", end, mss);
    }
}

/// A lowered segment limit cuts a large write into pieces that arrive whole and in order
pub async fn test_segment_limited_stream() {
    info!("-- test_segment_limited_stream");
    use futures_util::{AsyncReadExt, AsyncWriteExt};

    let (client, server) = mss_pair(None).await;
    let (mut client, segment_limit) = SegmentLimitedTcpStream::new(client);
    assert_eq!(segment_limit.get(), None);
    segment_limit.lower(1200);
    segment_limit.lower(1400);
    assert_eq!(segment_limit.get(), Some(1200), "a limit only ever lowers");

    let message: Vec<u8> = (0..65536u32).map(|n| n as u8).collect();
    let (mut server, _) = SegmentLimitedTcpStream::new(server);
    // Read exactly the message: async-std's close does not shut the stream down
    let (write_res, read_res) = futures_util::future::join(
        async {
            client.write_all(&message).await?;
            client.flush().await
        },
        async {
            let mut received = vec![0u8; message.len()];
            server.read_exact(&mut received).await.map(|_| received)
        },
    )
    .await;
    write_res.expect("write");
    assert_eq!(read_res.expect("read"), message);
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

/// IPv4 datagrams leave without DF, so a router on a smaller-MTU path fragments them
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn test_udp_ipv4_fragmentation_allowed() {
    use std::os::fd::AsRawFd;

    info!("-- test_udp_ipv4_fragmentation_allowed");
    let socket = bind_async_udp_socket(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind should not error")
        .expect("bind should succeed");
    let mut value: libc::c_int = -1;
    let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the socket is open, and `value` and `len` outlive this synchronous call
    let res = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    assert_eq!(res, 0, "getsockopt: {}", std::io::Error::last_os_error());
    assert_eq!(value, libc::IP_PMTUDISC_DONT);
}

pub fn test_routed_local_ip_resolves_v4_loopback() {
    let remote = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9);
    let ip = routed_local_ip(&remote).expect("loopback route should resolve a source ip");
    assert!(ip.is_ipv4(), "source family must match the v4 destination");
    assert!(!ip.is_unspecified(), "a routed source ip must be specified");
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
))]
mod df_sender {
    use super::*;

    /// The shared socket and its twin, or None where the host has no route for the twin's
    /// steering address, as in a container without one
    fn shared_with_twin() -> Option<(UdpSocketIo, UdpDfSender)> {
        let shared =
            bind_udp_socket_io(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
                .expect("bind should not error")
                .expect("bind should succeed");
        match UdpDfSender::try_new(&shared) {
            Ok(Some(twin)) => Some((shared, twin)),
            Ok(None) => panic!("a wildcard-bound socket gets a twin on this platform"),
            Err(e) if e.kind() == std::io::ErrorKind::NetworkUnreachable => {
                info!("skipped, no route for the twin's steering address: {}", e);
                None
            }
            Err(e) => panic!("twin: {}", e),
        }
    }

    #[cfg(unix)]
    fn int_option(socket: &UdpSocketIo, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        use std::os::fd::AsRawFd;

        let mut value: libc::c_int = -1;
        let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: the socket is open, and `value` and `len` outlive this synchronous call
        let res = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(res, 0, "getsockopt: {}", std::io::Error::last_os_error());
        value
    }

    #[cfg(windows)]
    fn int_option(socket: &UdpSocketIo, level: i32, name: i32) -> i32 {
        use std::os::windows::io::AsRawSocket;
        use winapi::um::winsock2::{getsockopt, SOCKET, SOCKET_ERROR};

        let mut value: i32 = -1;
        let mut len = core::mem::size_of::<i32>() as i32;
        // SAFETY: the socket is open, and `value` and `len` outlive this synchronous call
        let res = unsafe {
            getsockopt(
                socket.as_raw_socket() as SOCKET,
                level,
                name,
                (&mut value as *mut i32).cast(),
                &mut len,
            )
        };
        assert_ne!(
            res,
            SOCKET_ERROR,
            "getsockopt: {}",
            std::io::Error::last_os_error()
        );
        value
    }

    /// Every datagram to the port reaches the shared socket, none the twin, from many source
    /// ports so a hash-spread group would show
    pub async fn test_udp_df_sender_keeps_receives_on_the_main_socket() {
        info!("-- test_udp_df_sender_keeps_receives_on_the_main_socket");
        let Some((shared, twin)) = shared_with_twin() else {
            return;
        };
        let port = shared.local_addr().expect("local addr").port();
        // The twin's own address too, where connecting pinned one, so the specific slot is tried
        let mut targets = vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)];
        if let Ok(twin_addr) = twin.io().local_addr() {
            if !twin_addr.ip().is_unspecified() {
                targets.push(SocketAddr::new(twin_addr.ip(), port));
            }
        }
        const SENDERS: usize = 40;
        const PER_SENDER: usize = 5;
        let mut senders = Vec::with_capacity(SENDERS);
        for _ in 0..SENDERS {
            senders.push(
                bind_udp_socket_io(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                    .expect("sender bind should not error")
                    .expect("sender bind should succeed"),
            );
        }
        for (i, sender) in senders.iter().enumerate() {
            for _ in 0..PER_SENDER {
                sender
                    .send_to(b"df", targets[i % targets.len()])
                    .await
                    .expect("send");
            }
        }
        let expected = SENDERS * PER_SENDER;
        let mut received = 0;
        let mut buf = [0u8; 16];
        while received < expected {
            match timeout(2000, shared.recv_from(&mut buf)).await {
                Ok(Ok(_)) => received += 1,
                Ok(Err(e)) => panic!("recv: {}", e),
                Err(_) => break,
            }
        }
        assert_eq!(
            received, expected,
            "the shared socket must receive every datagram, the twin none"
        );
    }

    /// A datagram sent through the twin carries the shared port as its source port
    pub async fn test_udp_df_sender_sends_with_the_shared_port() {
        info!("-- test_udp_df_sender_sends_with_the_shared_port");
        let Some((shared, twin)) = shared_with_twin() else {
            return;
        };
        let port = shared.local_addr().expect("local addr").port();
        let receiver =
            bind_udp_socket_io(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("receiver bind should not error")
                .expect("receiver bind should succeed");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        twin.io().send_to(b"df", receiver_addr).await.expect("send");
        let mut buf = [0u8; 16];
        let (n, from) = timeout(2000, receiver.recv_from(&mut buf))
            .await
            .expect("the twin's datagram must arrive")
            .expect("recv");
        assert_eq!(&buf[..n], b"df");
        assert_eq!(from.port(), port, "the twin sends from the shared port");
    }

    /// DF is set on the twin and left as the builder chose on the shared socket
    pub fn test_udp_df_sender_sets_df_only_on_the_twin() {
        info!("-- test_udp_df_sender_sets_df_only_on_the_twin");
        let Some((shared, twin)) = shared_with_twin() else {
            return;
        };
        cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                assert_eq!(int_option(&shared, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER), libc::IP_PMTUDISC_DONT);
                assert_eq!(int_option(twin.io(), libc::IPPROTO_IP, libc::IP_MTU_DISCOVER), libc::IP_PMTUDISC_PROBE);
            } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                assert_eq!(int_option(&shared, libc::IPPROTO_IP, libc::IP_DONTFRAG), 0);
                assert_eq!(int_option(twin.io(), libc::IPPROTO_IP, libc::IP_DONTFRAG), 1);
            } else if #[cfg(windows)] {
                use winapi::shared::ws2def::IPPROTO_IP;
                use winapi::shared::ws2ipdef::IP_DONTFRAGMENT;
                assert_eq!(int_option(&shared, IPPROTO_IP, IP_DONTFRAGMENT), 0);
                assert_eq!(int_option(twin.io(), IPPROTO_IP, IP_DONTFRAGMENT), 1);
            }
        }
    }
}

pub async fn test_all() {
    test_borrowed_socket_operations().await;
    test_tcp_mss_clamp().await;
    test_segment_limited_stream().await;
    #[cfg(windows)]
    test_udp_icmp_errors_stay_out_of_recv().await;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    test_udp_ipv4_fragmentation_allowed();
    test_routed_local_ip_resolves_v4_loopback();
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        windows
    ))]
    {
        df_sender::test_udp_df_sender_keeps_receives_on_the_main_socket().await;
        df_sender::test_udp_df_sender_sends_with_the_shared_port().await;
        df_sender::test_udp_df_sender_sets_df_only_on_the_twin();
    }
}
