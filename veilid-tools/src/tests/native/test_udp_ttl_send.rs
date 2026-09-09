use crate::*;

async fn test_send_with_ttl(local: SocketAddr) {
    info!("-- test_send_with_ttl {}", local);

    let receiver = bind_async_udp_socket(local)
        .expect("receiver bind should not error")
        .expect("receiver bind should succeed");
    let recv_addr = receiver.local_addr().expect("should have local addr");
    let sender = bind_async_udp_socket(local)
        .expect("sender bind should not error")
        .expect("sender bind should succeed");

    let read_ttl = || {
        socket2_operation(&sender, |s| {
            if recv_addr.is_ipv6() {
                s.unicast_hops_v6()
            } else {
                s.ttl_v4()
            }
        })
        .expect("should get ttl")
    };

    let ttl_before = read_ttl();

    let sent =
        send_udp_datagram_with_ttl(&sender, &[], recv_addr, 3).expect("zero-length send with ttl");
    assert_eq!(sent, 0);
    let sent =
        send_udp_datagram_with_ttl(&sender, b"punch", recv_addr, 3).expect("payload send with ttl");
    assert_eq!(sent, 5);

    // Receive both datagrams; delivery order is not guaranteed
    let mut lens = Vec::new();
    let mut buf = [0u8; 64];
    for _ in 0..2 {
        let (n, _) = timeout(5000, receiver.recv_from(&mut buf))
            .await
            .expect("should not time out")
            .expect("should receive");
        if n == 5 {
            assert_eq!(&buf[..5], b"punch");
        }
        lens.push(n);
    }
    lens.sort();
    assert_eq!(lens, vec![0, 5]);

    let ttl_after = read_ttl();
    assert_eq!(ttl_before, ttl_after);

    // Out-of-range TTLs are refused before any syscall, on both address families
    for bad in [0u32, 256, u32::MAX] {
        let err = send_udp_datagram_with_ttl(&sender, b"x", recv_addr, bad)
            .expect_err("ttl out of range should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
    let sent = send_udp_datagram_with_ttl(&sender, b"max", recv_addr, 255).expect("ttl 255");
    assert_eq!(sent, 3);
    let (n, _) = timeout(5000, receiver.recv_from(&mut buf))
        .await
        .expect("should not time out")
        .expect("should receive");
    assert_eq!(&buf[..n], b"max");
}

/// An IPv6 destination on an IPv4 socket fails inside sendmsg, not before it
fn test_send_family_mismatch() {
    info!("-- test_send_family_mismatch");
    let sender = bind_async_udp_socket(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind should not error")
        .expect("bind should succeed");
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5150, 0, 0));
    assert!(send_udp_datagram_with_ttl(&sender, b"x", v6, 3).is_err());
}

pub async fn test_all() {
    test_send_family_mismatch();
    test_send_with_ttl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).await;
    test_send_with_ttl(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        0,
        0,
        0,
    )))
    .await;
}
