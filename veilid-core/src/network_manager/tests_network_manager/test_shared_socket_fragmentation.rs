use super::*;

use crate::network_manager::network::native::udp_demux::DemuxerUdpSocket;
use web_transport_quinn::quinn::{udp::UdpSocketState, AsyncUdpSocket};

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

// The platform's IPv4 don't-fragment option and its value after the builder, then after a
// plain quinn-udp wrap; the options a quinn-udp wrap sets on an IPv6 socket that decide
// fragmentation, and IPv6's don't-fragment option
cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        const DF_OPTION: (libc::c_int, libc::c_int) = (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER);
        const DF_BUILDER: libc::c_int = libc::IP_PMTUDISC_DONT;
        const DF_WRAPPED: libc::c_int = libc::IP_PMTUDISC_PROBE;
        const V6_OPTIONS: &[(libc::c_int, libc::c_int)] = &[
            (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
            (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
            (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
        ];
        const V6_DF_OPTION: (libc::c_int, libc::c_int) = (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG);
    } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {
        const DF_OPTION: (libc::c_int, libc::c_int) = (libc::IPPROTO_IP, libc::IP_DONTFRAG);
        const DF_BUILDER: libc::c_int = 0;
        const DF_WRAPPED: libc::c_int = 1;
        const V6_OPTIONS: &[(libc::c_int, libc::c_int)] = &[V6_DF_OPTION];
        const V6_DF_OPTION: (libc::c_int, libc::c_int) = (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG);
    } else if #[cfg(windows)] {
        const DF_OPTION: (i32, i32) = (
            winapi::shared::ws2def::IPPROTO_IP,
            winapi::shared::ws2ipdef::IP_DONTFRAGMENT,
        );
        const DF_BUILDER: i32 = 0;
        const DF_WRAPPED: i32 = 1;
        const V6_OPTIONS: &[(i32, i32)] = &[V6_DF_OPTION];
        const V6_DF_OPTION: (i32, i32) = (
            winapi::shared::ws2def::IPPROTO_IPV6 as i32,
            winapi::shared::ws2ipdef::IPV6_DONTFRAG,
        );
    }
}

/// The shared socket keeps the builder's raw UDP fragmentation policy through the quinn-udp wrap;
/// without a twin it tells quinn that its datagrams may fragment, with one quinn hears the twin
pub fn test_shared_socket_keeps_fragmentation_policy() {
    info!("-- test_shared_socket_keeps_fragmentation_policy");
    let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

    // The wrap alone forbids fragmentation, which is what the demux socket has to undo
    let plain = bind_udp_socket_io(v4).unwrap().unwrap();
    UdpSocketState::new((&plain).into()).unwrap();
    assert_eq!(int_option(&plain, DF_OPTION.0, DF_OPTION.1), DF_WRAPPED);

    let shared = Arc::new(bind_udp_socket_io(v4).unwrap().unwrap());
    let (demux, _raw_rx) = DemuxerUdpSocket::try_new(shared.clone(), None).unwrap();
    assert_eq!(int_option(&shared, DF_OPTION.0, DF_OPTION.1), DF_BUILDER);
    assert!(demux.may_fragment());

    // A wildcard socket gets the twin, and quinn then hears that its packets never fragment
    let wildcard = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let shared = Arc::new(bind_udp_socket_io(wildcard).unwrap().unwrap());
    match UdpDfSender::try_new(&shared) {
        Ok(Some(twin)) => {
            let (demux, _raw_rx) = DemuxerUdpSocket::try_new(shared.clone(), Some(twin)).unwrap();
            assert_eq!(int_option(&shared, DF_OPTION.0, DF_OPTION.1), DF_BUILDER);
            assert!(!demux.may_fragment());
        }
        Ok(None) => panic!("a wildcard-bound socket gets a twin on this platform"),
        // No route for the twin's steering address, as in a container without one
        Err(e) if e.kind() == std::io::ErrorKind::NetworkUnreachable => {
            info!("no route for the twin, skipping the twin half: {}", e);
        }
        Err(e) => panic!("twin: {}", e),
    }

    // The builder sets nothing on IPv6, so a wrapped socket reads like one never wrapped
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
    let Ok(Some(unwrapped)) = bind_udp_socket_io(v6) else {
        info!("no IPv6 loopback, skipping the IPv6 half");
        return;
    };
    let shared = Arc::new(bind_udp_socket_io(v6).unwrap().unwrap());
    let (demux, _raw_rx) = DemuxerUdpSocket::try_new(shared.clone(), None).unwrap();
    for &(level, name) in V6_OPTIONS {
        assert_eq!(
            int_option(&shared, level, name),
            int_option(&unwrapped, level, name),
            "option {level}/{name}"
        );
    }
    assert_eq!(int_option(&shared, V6_DF_OPTION.0, V6_DF_OPTION.1), 0);
    assert!(demux.may_fragment());

    let wildcard = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
    let shared = Arc::new(bind_udp_socket_io(wildcard).unwrap().unwrap());
    match UdpDfSender::try_new(&shared) {
        Ok(Some(twin)) => {
            let (demux, _raw_rx) = DemuxerUdpSocket::try_new(shared.clone(), Some(twin)).unwrap();
            assert_eq!(int_option(&shared, V6_DF_OPTION.0, V6_DF_OPTION.1), 0);
            assert!(!demux.may_fragment());
        }
        Ok(None) => panic!("a wildcard-bound socket gets a twin on this platform"),
        Err(e) if e.kind() == std::io::ErrorKind::NetworkUnreachable => {
            info!("no IPv6 route for the twin, skipping its half: {}", e);
        }
        Err(e) => panic!("twin: {}", e),
    }
}
