use super::*;
#[cfg(feature = "rt-async-std")]
use async_io::Async;
use std::io;

cfg_if! {
    if #[cfg(feature="rt-async-std")] {
        pub use async_std::net::{TcpStream, TcpListener, UdpSocket};
    } else if #[cfg(feature="rt-tokio")] {
        pub use tokio::net::{TcpStream, TcpListener, UdpSocket};
        pub use tokio_util::compat::*;
    } else {
        compile_error!("needs executor implementation");
    }
}

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

//////////////////////////////////////////////////////////////////////////////////////////

/// Bind a UDP socket to `local_address` with `SO_REUSEADDR`/`SO_REUSEPORT` set.
///
/// Returns `Ok(None)` if the address could not be bound (a bind failure is not an error).
/// Errors only on socket creation or option failures (`Socket::new`, reuse-address/port, and the tokio non-blocking conversion).
pub fn bind_async_udp_socket(local_address: SocketAddr) -> io::Result<Option<UdpSocket>> {
    let Some(socket) = new_bound_shared_socket2_udp(local_address)? else {
        return Ok(None);
    };

    // Make an async UdpSocket from the socket2 socket
    let std_udp_socket: std::net::UdpSocket = socket.into();
    cfg_if! {
        if #[cfg(feature="rt-async-std")] {
            let udp_socket = UdpSocket::from(std_udp_socket);
        } else if #[cfg(feature="rt-tokio")] {
            std_udp_socket.set_nonblocking(true)?;
            let udp_socket = UdpSocket::from_std(std_udp_socket)?;
        } else {
            compile_error!("needs executor implementation");
        }
    }
    Ok(Some(udp_socket))
}

/// Bind a UDP socket to `local_address`, probing the port with a non-shared
/// socket first so an occupied port fails instead of silently reuse-binding
/// alongside another process (which starves both of inbound packets). Use for
/// inbound listeners found by port search; use [`bind_async_udp_socket`] for
/// sockets that intentionally share the listener's port.
///
/// Returns `Ok(None)` if the address could not be bound (a bind failure is not an error).
/// Errors only on socket creation or option failures.
pub fn bind_async_udp_socket_probed(local_address: SocketAddr) -> io::Result<Option<UdpSocket>> {
    // Create a default non-shared socket and bind it to assert the port is free
    let Some(socket) = new_bound_default_socket2_udp(local_address)? else {
        return Ok(None);
    };

    // Drop the probe so we can make a shared socket in its place
    drop(socket);

    // The shared socket keeps outbound source binding on this port possible
    bind_async_udp_socket(local_address)
}

/// Bind a TCP listener to `local_address`.
///
/// Probes the port with a non-shared socket first, then binds a shared
/// (`SO_REUSEADDR`/`SO_REUSEPORT`) socket once the port is known free.
/// Returns `Ok(None)` if the address could not be bound or listened on (these are not errors).
/// Errors only on socket creation or option failures (`Socket::new`, linger, nodelay, reuse-address/port, and the tokio non-blocking conversion).
pub fn bind_async_tcp_listener(local_address: SocketAddr) -> io::Result<Option<TcpListener>> {
    // Create a default non-shared socket and bind it
    let Some(socket) = new_bound_default_socket2_tcp(local_address)? else {
        return Ok(None);
    };

    // Drop the socket so we can make another shared socket in its place
    drop(socket);

    // Create a shared socket and bind it now we have determined the port is free
    let Some(socket) = new_bound_shared_socket2_tcp(local_address)? else {
        return Ok(None);
    };

    // Listen on the socket
    if socket.listen(128).is_err() {
        return Ok(None);
    }

    // Make an async tcplistener from the socket2 socket
    let std_listener: std::net::TcpListener = socket.into();
    cfg_if! {
        if #[cfg(feature="rt-async-std")] {
            let listener = TcpListener::from(std_listener);
        } else if #[cfg(feature="rt-tokio")] {
            std_listener.set_nonblocking(true)?;
            let listener = TcpListener::from_std(std_listener)?;
        } else {
            compile_error!("needs executor implementation");
        }
    }
    Ok(Some(listener))
}

/// Connect a TCP stream to `remote_address`, optionally bound to `local_address`.
///
/// When `local_address` is given the connecting socket is shared
/// (`SO_REUSEADDR`/`SO_REUSEPORT`); otherwise a default socket is used. The
/// connect is non-blocking and bounded by `timeout_ms`.
///
/// A timeout yields `Ok(TimeoutOr::timeout())`, not an error. Errors with `AddrInUse` when `local_address` cannot be bound, and propagates the connect failure (e.g. `ConnectionRefused`, `HostUnreachable`) along with any socket creation or option io error.
pub async fn connect_async_tcp_stream(
    local_address: Option<SocketAddr>,
    remote_address: SocketAddr,
    timeout_ms: u32,
) -> io::Result<TimeoutOr<TcpStream>> {
    let socket = match local_address {
        Some(a) => {
            new_bound_shared_socket2_tcp(a)?.ok_or(io::Error::from(io::ErrorKind::AddrInUse))?
        }
        None => new_default_socket2_tcp(domain_for_address(remote_address))?,
    };

    // Non-blocking connect to remote address
    nonblocking_connect(socket, remote_address, timeout_ms).await
}

/// Set the `SO_LINGER` option on a TCP stream.
///
/// Works around runtimes that do not expose linger directly by reaching the
/// underlying socket via the raw fd/handle.
///
/// Errors with the io error from the underlying `setsockopt`.
pub fn set_tcp_stream_linger(
    tcp_stream: &TcpStream,
    linger: Option<core::time::Duration>,
) -> io::Result<()> {
    #[cfg(all(feature = "rt-async-std", unix))]
    {
        // async-std does not directly support linger on TcpStream yet
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
        unsafe {
            let s = socket2::Socket::from_raw_fd(tcp_stream.as_raw_fd());
            let res = s.set_linger(linger);
            let _ = s.into_raw_fd();
            res
        }
    }
    #[cfg(all(feature = "rt-async-std", windows))]
    {
        // async-std does not directly support linger on TcpStream yet
        use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};
        unsafe {
            let s = socket2::Socket::from_raw_socket(tcp_stream.as_raw_socket());
            let res = s.set_linger(linger);
            let _ = s.into_raw_socket();
            res
        }
    }
    #[cfg(not(feature = "rt-async-std"))]
    socket2::SockRef::from(tcp_stream).set_linger(linger)
}

cfg_if! {
    if #[cfg(feature="rt-async-std")] {
        /// Owned read half of a split [`TcpStream`].
        pub type ReadHalf = futures_util::io::ReadHalf<TcpStream>;
        /// Owned write half of a split [`TcpStream`].
        pub type WriteHalf = futures_util::io::WriteHalf<TcpStream>;
    } else if #[cfg(feature="rt-tokio")] {
        /// Owned read half of a split [`TcpStream`].
        pub type ReadHalf = tokio::net::tcp::OwnedReadHalf;
        /// Owned write half of a split [`TcpStream`].
        pub type WriteHalf = tokio::net::tcp::OwnedWriteHalf;
    } else {
        compile_error!("needs executor implementation");
    }
}

/// Wrap a [`TcpListener`] as a stream of accepted [`TcpStream`] connections.
#[must_use]
pub fn async_tcp_listener_incoming(
    tcp_listener: TcpListener,
) -> Pin<Box<impl futures_util::stream::Stream<Item = std::io::Result<TcpStream>> + Send>> {
    cfg_if! {
        if #[cfg(feature="rt-async-std")] {
            Box::pin(tcp_listener.into_incoming())
        } else if #[cfg(feature="rt-tokio")] {
            Box::pin(tokio_stream::wrappers::TcpListenerStream::new(tcp_listener))
        } else {
            compile_error!("needs executor implementation");
        }
    }
}

/// Split a [`TcpStream`] into owned read and write halves.
#[must_use]
pub fn split_async_tcp_stream(tcp_stream: TcpStream) -> (ReadHalf, WriteHalf) {
    cfg_if! {
        if #[cfg(feature="rt-async-std")] {
            use futures_util::AsyncReadExt;
            tcp_stream.split()
        } else if #[cfg(feature="rt-tokio")] {
            tcp_stream.into_split()
        } else {
            compile_error!("needs executor implementation");
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////////////

fn new_shared_socket2_udp(domain: core::ffi::c_int) -> io::Result<Socket> {
    let domain = Domain::from(domain);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    // SO_REUSEADDR + SO_REUSEPORT so a wildcard listener and a specific-source
    // handler can coexist on the same port (used for outbound source binding)
    socket.set_reuse_address(true)?;
    cfg_if! {
        if #[cfg(unix)] {
            socket.set_reuse_port(true)?;
        }
    }
    Ok(socket)
}

fn new_bound_shared_socket2_udp(local_address: SocketAddr) -> io::Result<Option<Socket>> {
    let domain = domain_for_address(local_address);
    let socket = new_shared_socket2_udp(domain)?;
    let socket2_addr = SockAddr::from(local_address);

    if socket.bind(&socket2_addr).is_err() {
        return Ok(None);
    }

    Ok(Some(socket))
}

fn new_default_socket2_udp(domain: core::ffi::c_int) -> io::Result<Socket> {
    let domain = Domain::from(domain);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    Ok(socket)
}

fn new_bound_default_socket2_udp(local_address: SocketAddr) -> io::Result<Option<Socket>> {
    let domain = domain_for_address(local_address);
    let socket = new_default_socket2_udp(domain)?;
    let socket2_addr = SockAddr::from(local_address);
    if socket.bind(&socket2_addr).is_err() {
        return Ok(None);
    }

    Ok(Some(socket))
}

/// Create a non-shared TCP [`Socket`] for `domain` with zero linger and `TCP_NODELAY` set.
///
/// Errors with the io error from socket creation or any of the option calls (linger, nodelay, IPv6-only).
pub fn new_default_socket2_tcp(domain: core::ffi::c_int) -> io::Result<Socket> {
    let domain = Domain::from(domain);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_linger(Some(core::time::Duration::from_secs(0)))?;
    socket.set_tcp_nodelay(true)?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    Ok(socket)
}

fn new_shared_socket2_tcp(domain: core::ffi::c_int) -> io::Result<Socket> {
    let domain = Domain::from(domain);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_linger(Some(core::time::Duration::from_secs(0)))?;
    socket.set_tcp_nodelay(true)?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    cfg_if! {
        if #[cfg(unix)] {
            socket.set_reuse_port(true)?;
        }
    }

    Ok(socket)
}

fn new_bound_default_socket2_tcp(local_address: SocketAddr) -> io::Result<Option<Socket>> {
    let domain = domain_for_address(local_address);
    let socket = new_default_socket2_tcp(domain)?;
    let socket2_addr = SockAddr::from(local_address);
    if socket.bind(&socket2_addr).is_err() {
        return Ok(None);
    }

    Ok(Some(socket))
}

fn new_bound_shared_socket2_tcp(local_address: SocketAddr) -> io::Result<Option<Socket>> {
    // Create the reuseaddr/reuseport socket now that we've asserted the port is free
    let domain = domain_for_address(local_address);
    let socket = new_shared_socket2_tcp(domain)?;
    let socket2_addr = SockAddr::from(local_address);
    if socket.bind(&socket2_addr).is_err() {
        return Ok(None);
    }

    Ok(Some(socket))
}

// Non-blocking connect is tricky when you want to start with a prepared socket
// Errors should not be logged as they are valid conditions for this function
async fn nonblocking_connect(
    socket: Socket,
    addr: SocketAddr,
    timeout_ms: u32,
) -> io::Result<TimeoutOr<TcpStream>> {
    // Set for non blocking connect
    socket.set_nonblocking(true)?;

    // Make socket2 SockAddr
    let socket2_addr = socket2::SockAddr::from(addr);

    // Connect to the remote address (non-blocking; completion signaled by writability)
    match socket.connect(&socket2_addr) {
        Ok(()) => Ok(()),
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e),
    }?;
    let std_stream = std::net::TcpStream::from(socket);

    // Wait for writability (connect complete) on the executor's own reactor. async-io's reactor
    // is never driven under tokio, so its wait and timeout would hang forever there.
    cfg_if! {
        if #[cfg(feature="rt-async-std")] {
            let async_stream = Async::new(std_stream)?;
            timeout_or_try!(timeout(timeout_ms, async_stream.writable())
                .await
                .into_timeout_or()
                .into_result()?);
            if let Some(err) = async_stream.get_ref().take_error()? {
                return Err(err);
            }
            Ok(TimeoutOr::value(TcpStream::from(async_stream.into_inner()?)))
        } else if #[cfg(feature="rt-tokio")] {
            let stream = TcpStream::from_std(std_stream)?;
            timeout_or_try!(timeout(timeout_ms, stream.writable())
                .await
                .into_timeout_or()
                .into_result()?);
            if let Some(err) = stream.take_error()? {
                return Err(err);
            }
            Ok(TimeoutOr::value(stream))
        } else {
            compile_error!("needs executor implementation");
        }
    }
}

/// The socket address family (`AF_INET`/`AF_INET6`) for `address`.
#[must_use]
pub fn domain_for_address(address: SocketAddr) -> core::ffi::c_int {
    socket2::Domain::for_address(address).into()
}

/// Local IPv4 the kernel would pick as the source for outbound traffic.
///
/// UDP-connects to an unallocated probe; no packets are sent. `None` if no
/// default IPv4 route exists.
#[must_use]
pub fn primary_source_ipv4() -> Option<Ipv4Addr> {
    let ipv4addr = "1.2.3.4".parse::<Ipv4Addr>().unwrap();
    let sockaddrv4 = SocketAddr::V4(SocketAddrV4::new(ipv4addr, 5155));
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(sockaddrv4).ok()?;
    if let Ok(SocketAddr::V4(local)) = socket.local_addr() {
        Some(*local.ip())
    } else {
        None
    }
}

/// Local IPv6 the kernel would pick as the source for outbound traffic.
///
/// UDP-connects to an unallocated probe; no packets are sent. `None` if no
/// default IPv6 route exists.
#[must_use]
pub fn primary_source_ipv6() -> Option<Ipv6Addr> {
    let ipv6addr = "2222::1".parse::<Ipv6Addr>().unwrap();
    let sockaddrv6 = SocketAddr::V6(SocketAddrV6::new(ipv6addr, 5155, 0, 0));
    let socket = std::net::UdpSocket::bind("[::]:0").ok()?;
    socket.connect(sockaddrv6).ok()?;
    if let Ok(SocketAddr::V6(local)) = socket.local_addr() {
        Some(*local.ip())
    } else {
        None
    }
}

// Send a single UDP datagram with a per-packet TTL override
cfg_if! {
    if #[cfg(unix)] {
        /// Send one UDP datagram with a best-effort per-packet TTL (IPv4) or hop
        /// limit (IPv6) override, never touching the socket's TTL option:
        /// - IPv6: `IPV6_HOPLIMIT` cmsg (RFC 3542)
        /// - IPv4 on Linux/Android: `IP_TTL` cmsg
        /// - IPv4 elsewhere: sent at the socket's default TTL; no per-packet TTL
        ///   cmsg exists (xnu honors only `IP_PKTINFO`) and a setsockopt swap would
        ///   race other senders on the shared socket
        ///
        /// Single nonblocking attempt; a full send buffer surfaces as `WouldBlock`.
        pub fn send_udp_datagram_with_ttl<S: std::os::fd::AsRawFd>(
            socket: &S,
            data: &[u8],
            remote_addr: SocketAddr,
            ttl: u32,
        ) -> io::Result<usize> {
            cfg_if! {
                if #[cfg(any(target_os = "linux", target_os = "android"))] {
                    let (cmsg_level, cmsg_type) = match remote_addr {
                        SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TTL),
                        SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT),
                    };
                    sendmsg_with_ttl_cmsg(socket.as_raw_fd(), data, remote_addr, cmsg_level, cmsg_type, ttl)
                } else {
                    match remote_addr {
                        SocketAddr::V4(_) => socket2_operation(socket, |s| s.send_to(data, &remote_addr.into())),
                        SocketAddr::V6(_) => sendmsg_with_ttl_cmsg(socket.as_raw_fd(), data, remote_addr, libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT, ttl),
                    }
                }
            }
        }

        fn sendmsg_with_ttl_cmsg(
            fd: std::os::fd::RawFd,
            data: &[u8],
            remote_addr: SocketAddr,
            cmsg_level: libc::c_int,
            cmsg_type: libc::c_int,
            ttl: u32,
        ) -> io::Result<usize> {
            let sockaddr = SockAddr::from(remote_addr);
            let mut iov = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            // u64 array for cmsg alignment; larger than CMSG_SPACE(sizeof(int)) everywhere
            let mut cmsg_buf = [0u64; 8];
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_name = sockaddr.as_ptr() as *mut libc::c_void;
                msg.msg_namelen = sockaddr.len();
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = cmsg_level;
                (*cmsg).cmsg_type = cmsg_type;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as libc::c_uint) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), ttl as libc::c_int);
                let res = libc::sendmsg(fd, &msg, 0);
                if res < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(res as usize)
            }
        }
    } else if #[cfg(windows)] {
        /// Send one UDP datagram with a best-effort per-packet TTL (IPv4) or hop
        /// limit (IPv6) override, never touching the socket's TTL option:
        /// - IPv6: `IPV6_HOPLIMIT` cmsg via `WSASendMsg`
        /// - IPv4: sent at the socket's default TTL; `WSASendMsg` has no TTL cmsg
        ///   and a setsockopt swap would race other senders on the shared socket
        ///
        /// Single nonblocking attempt; a full send buffer surfaces as `WouldBlock`.
        pub fn send_udp_datagram_with_ttl<S: std::os::windows::io::AsRawSocket>(
            socket: &S,
            data: &[u8],
            remote_addr: SocketAddr,
            ttl: u32,
        ) -> io::Result<usize> {
            match remote_addr {
                SocketAddr::V4(_) => socket2_operation(socket, |s| s.send_to(data, &remote_addr.into())),
                SocketAddr::V6(_) => wsasendmsg_with_hoplimit(socket, data, remote_addr, ttl),
            }
        }

        fn wsasendmsg_with_hoplimit<S: std::os::windows::io::AsRawSocket>(
            socket: &S,
            data: &[u8],
            remote_addr: SocketAddr,
            ttl: u32,
        ) -> io::Result<usize> {
            use winapi::shared::minwindef::DWORD;
            use winapi::shared::ws2def::{IPPROTO_IPV6, WSABUF, WSACMSGHDR, WSAMSG};
            use winapi::shared::ws2ipdef::IPV6_HOPLIMIT;
            use winapi::um::winsock2::{WSASendMsg, SOCKET, SOCKET_ERROR};

            // WSA_CMSG_SPACE(sizeof(int)) layout by hand; winapi has no cmsg macros
            #[repr(C)]
            struct CmsgHopLimit {
                hdr: WSACMSGHDR,
                value: i32,
            }

            let sockaddr = SockAddr::from(remote_addr);
            let mut wsabuf = WSABUF {
                len: data.len() as u32,
                buf: data.as_ptr() as *mut i8,
            };
            let mut cmsg = CmsgHopLimit {
                hdr: WSACMSGHDR {
                    cmsg_len: std::mem::size_of::<WSACMSGHDR>() + std::mem::size_of::<i32>(),
                    cmsg_level: IPPROTO_IPV6 as i32,
                    cmsg_type: IPV6_HOPLIMIT,
                },
                value: ttl as i32,
            };
            let mut msg = WSAMSG {
                name: sockaddr.as_ptr() as *mut _,
                namelen: sockaddr.len(),
                lpBuffers: &mut wsabuf,
                dwBufferCount: 1,
                Control: WSABUF {
                    len: std::mem::size_of::<CmsgHopLimit>() as u32,
                    buf: (&mut cmsg as *mut CmsgHopLimit) as *mut i8,
                },
                dwFlags: 0,
            };
            let mut sent: DWORD = 0;
            let res = unsafe {
                WSASendMsg(
                    socket.as_raw_socket() as SOCKET,
                    &mut msg,
                    0,
                    &mut sent,
                    std::ptr::null_mut(),
                    None,
                )
            };
            if res == SOCKET_ERROR {
                return Err(io::Error::last_os_error());
            }
            Ok(sent as usize)
        }
    }
}

// Run operations on underlying socket
cfg_if! {
    if #[cfg(unix)] {
        /// Run `callback` against the [`socket2::Socket`] backing `s` without taking ownership of it.
        pub fn socket2_operation<S: std::os::fd::AsRawFd, F: FnOnce(&mut socket2::Socket) -> R, R>(
            s: &S,
            callback: F,
        ) -> R {
            use std::os::fd::{FromRawFd, IntoRawFd};
            let mut s = unsafe { socket2::Socket::from_raw_fd(s.as_raw_fd()) };
            let res = callback(&mut s);
            let _ = s.into_raw_fd();
            res
        }
    } else if #[cfg(windows)] {
        /// Run `callback` against the [`socket2::Socket`] backing `s` without taking ownership of it.
        pub fn socket2_operation<
            S: std::os::windows::io::AsRawSocket,
            F: FnOnce(&mut socket2::Socket) -> R,
            R,
        >(
            s: &S,
            callback: F,
        ) -> R {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            let mut s = unsafe { socket2::Socket::from_raw_socket(s.as_raw_socket()) };
            let res = callback(&mut s);
            let _ = s.into_raw_socket();
            res
        }
    } else {
        #[compile_error("unimplemented")]
    }
}
