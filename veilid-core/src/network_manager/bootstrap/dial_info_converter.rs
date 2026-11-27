use super::*;

/// A bare bootstrap entry as a url host and port: `host`, `host:port`, an IP literal, or
/// `[ipv6]:port`. An IPv6 host comes back bracketed and a missing port is the bootstrap port
pub fn split_bootstrap_entry(entry: &str) -> Option<(String, u16)> {
    let url_host = |ip_addr: IpAddr| SplitUrlHost::IpAddr(ip_addr).to_string();
    if let Ok(ip_addr) = IpAddr::from_str(entry) {
        return Some((url_host(ip_addr), BOOTSTRAP_DIRECT_PORT));
    }
    if let Ok(socket_addr) = SocketAddr::from_str(entry) {
        return Some((url_host(socket_addr.ip()), socket_addr.port()));
    }
    if let Ok(host) = SplitUrlHost::from_str(entry) {
        return Some((host.to_string(), BOOTSTRAP_DIRECT_PORT));
    }
    let (host, port) = entry.rsplit_once(':')?;
    let host = SplitUrlHost::from_str(host).ok()?;
    Some((host.to_string(), port.parse().ok()?))
}

/// Whether a `bootstrap` entry names something to ask, checked without any lookup: a url
/// over a protocol this build dials, or a bare `host` or `host:port`
pub fn check_bootstrap_entry(entry: &str) -> VeilidAPIResult<()> {
    if entry.contains("://") {
        split_dial_info_url(entry)?;
        return Ok(());
    }
    if split_bootstrap_entry(entry).is_none() {
        apibail_parse_error!("not a url, host or host:port", entry);
    }
    Ok(())
}

/// A dial info url split, with the port its scheme defaults to
fn split_dial_info_url(url: &str) -> VeilidAPIResult<(SplitUrl, u16)> {
    let split_url = SplitUrl::from_str(url)
        .map_err(|e| VeilidAPIError::parse_error(format!("unable to split url: {}", e), url))?;
    let port = match split_url.scheme.as_str() {
        "udp" | "tcp" => split_url
            .port
            .ok_or_else(|| VeilidAPIError::parse_error("Missing port in udp url", url))?,
        "ws" => split_url.port.unwrap_or(80u16),
        #[cfg(feature = "enable-protocol-wss")]
        "wss" => split_url.port.unwrap_or(443u16),
        #[cfg(feature = "enable-protocol-webtransport")]
        "wts" => split_url.port.unwrap_or(443u16),
        _ => {
            apibail_parse_error!("Invalid dial info url scheme", split_url.scheme);
        }
    };
    Ok((split_url, port))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BootstrapDialInfoConverter {}

impl BootstrapDialInfoConverter {
    pub fn try_vec_from_url<'a>(
        &'a self,
        url: &'a str,
    ) -> PinBoxFuture<'a, VeilidAPIResult<Vec<DialInfo>>> {
        pin_dyn_future!(async move {
            let (split_url, port) = split_dial_info_url(url)?;

            let socket_addrs = match split_url.host {
                SplitUrlHost::Hostname(_) => resolve_socket_addrs(
                    &split_url.host_port(port),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port),
                )
                .await
                .map_err(|_| {
                    VeilidAPIError::parse_error("couldn't resolve hostname in url", url)
                })?,
                SplitUrlHost::IpAddr(a) => vec![SocketAddr::new(a, port)],
            };

            let mut out = Vec::new();
            for sa in socket_addrs {
                out.push(match split_url.scheme.as_str() {
                    "udp" => DialInfo::udp_from_socketaddr(sa),
                    "tcp" => DialInfo::tcp_from_socketaddr(sa),
                    "ws" => DialInfo::try_ws(
                        SocketAddress::from_socket_addr(sa).canonical(),
                        url.to_string(),
                    )?,
                    #[cfg(feature = "enable-protocol-wss")]
                    "wss" => DialInfo::try_wss(
                        SocketAddress::from_socket_addr(sa).canonical(),
                        url.to_string(),
                    )?,
                    #[cfg(feature = "enable-protocol-webtransport")]
                    "wts" => DialInfo::try_webtransport_stream(
                        SocketAddress::from_socket_addr(sa).canonical(),
                        url.replacen("wts://", "https://", 1),
                        vec![],
                        None,
                    )?,
                    _ => {
                        apibail_parse_error!("Invalid dial info url scheme", split_url.scheme);
                    }
                });
            }
            Ok(out)
        })
    }
}

/// The short form a legacy record line carries for a dial info: the hostname is the line's,
/// so only the protocol letter, port and path remain
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub fn to_short_dial_info(dial_info: &DialInfo) -> String {
    fn port_and_path(url: &str, default_port: u16) -> (u16, String) {
        let split_url = SplitUrl::from_str(url).unwrap_or_log();
        let path = split_url
            .path
            .map(|p| p.to_string())
            .filter(|p| !p.is_empty())
            .map(|p| format!("/{}", p))
            .unwrap_or_default();
        (split_url.port.unwrap_or(default_port), path)
    }
    match dial_info {
        DialInfo::UDP(di) => format!("U{}", di.socket_address.port()),
        DialInfo::TCP(di) => format!("T{}", di.socket_address.port()),
        DialInfo::WS(di) => {
            let (port, path) = port_and_path(&format!("ws://{}", di.request), 80);
            format!("W{}{}", port, path)
        }
        #[cfg(feature = "enable-protocol-wss")]
        DialInfo::WSS(di) => {
            let (port, path) = port_and_path(&format!("wss://{}", di.request), 443);
            format!("S{}{}", port, path)
        }
        // The datagram half shares the stream's `B` form; a form of its own would not parse
        #[cfg(feature = "enable-protocol-webtransport")]
        DialInfo::WebTransportStream(di) | DialInfo::WebTransportDatagram(di) => {
            let (port, path) = port_and_path(&di.request, 443);
            format!("B{}{}", port, path)
        }
    }
}

#[allow(unused_variables)]
fn resolve_socket_addrs(
    host: &str,
    default: SocketAddr,
) -> PinBoxFuture<'_, std::io::Result<Vec<SocketAddr>>> {
    // Resolve if possible, WASM doesn't support resolution and doesn't need it to connect to the dialinfo
    // This will not be used on signed dialinfo, only for bootstrapping, so we don't need to worry about
    // the '0.0.0.0' address being propagated across the routing table
    let host = host.to_owned();
    pin_dyn_future!(async move {
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                Ok(vec![default])
            } else {
                // getaddrinfo blocks for the system resolver's whole retry ladder
                blocking_wrapper(move || host.to_socket_addrs().map(|i| i.collect())).await
            }
        }
    })
}
