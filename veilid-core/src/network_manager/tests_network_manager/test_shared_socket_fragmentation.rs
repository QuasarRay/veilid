use super::*;

use crate::network_manager::network::native::udp_demux::DemuxerUdpSocket;
use std::os::fd::AsRawFd;
use web_transport_quinn::quinn::{udp::UdpSocketState, AsyncUdpSocket};

fn int_option(socket: &UdpSocketIo, level: libc::c_int, name: libc::c_int) -> libc::c_int {
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

/// The shared socket keeps the builder's raw UDP fragmentation policy through the quinn-udp wrap,
/// and tells quinn that its datagrams may fragment
pub fn test_shared_socket_keeps_fragmentation_policy() {
    info!("-- test_shared_socket_keeps_fragmentation_policy");
    let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

    // The wrap alone forbids fragmentation, which is what the demux socket has to undo
    let plain = bind_udp_socket_io(v4).unwrap().unwrap();
    UdpSocketState::new((&plain).into()).unwrap();
    assert_eq!(
        int_option(&plain, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
        libc::IP_PMTUDISC_PROBE
    );

    let shared = Arc::new(bind_udp_socket_io(v4).unwrap().unwrap());
    let (demux, _raw_rx) = DemuxerUdpSocket::try_new(shared.clone()).unwrap();
    assert_eq!(
        int_option(&shared, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
        libc::IP_PMTUDISC_DONT
    );
    assert!(demux.may_fragment());

    // The builder sets nothing on IPv6, so a wrapped socket reads like one never wrapped
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
    let Ok(Some(unwrapped)) = bind_udp_socket_io(v6) else {
        info!("no IPv6 loopback, skipping the IPv6 half");
        return;
    };
    let shared = Arc::new(bind_udp_socket_io(v6).unwrap().unwrap());
    let (demux, _raw_rx) = DemuxerUdpSocket::try_new(shared.clone()).unwrap();
    for (level, name) in [
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
        (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
        (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
    ] {
        assert_eq!(
            int_option(&shared, level, name),
            int_option(&unwrapped, level, name),
            "option {level}/{name}"
        );
    }
    assert_eq!(
        int_option(&shared, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
        0
    );
    assert!(demux.may_fragment());
}
