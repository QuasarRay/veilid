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
}

pub async fn test_all() {
    test_send_with_ttl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).await;
    test_send_with_ttl(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        0,
        0,
        0,
    )))
    .await;
}
