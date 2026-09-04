//! Nameserver discovery: the system's resolv.conf and the built-in fallback list.

use super::*;

pub(crate) const DNS_PORT: u16 = 53;
pub(crate) const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Quad9 public resolvers, used when the system resolver is unavailable or slow
const DEFAULT_NAME_SERVER_IPS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe)),
    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9)),
];

/// The built-in fallback nameservers
#[must_use]
pub(crate) fn default_name_servers() -> Vec<SocketAddr> {
    DEFAULT_NAME_SERVER_IPS
        .iter()
        .map(|ip| SocketAddr::new(*ip, DNS_PORT))
        .collect()
}

/// The system's nameservers; `None` when the platform exposes none to us
#[must_use]
pub(crate) fn system_name_servers() -> Option<Vec<SocketAddr>> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some(servers) = apple_resolv::system_name_servers() {
        return Some(servers);
    }
    resolv_conf_name_servers()
}

/// Nameservers from resolv.conf; `None` when it is unreadable or lists none
#[must_use]
fn resolv_conf_name_servers() -> Option<Vec<SocketAddr>> {
    let text = std::fs::read_to_string(RESOLV_CONF_PATH).ok()?;
    let servers = parse_resolv_conf(&text);
    (!servers.is_empty()).then_some(servers)
}

/// The `nameserver` entries of a resolv.conf, in order, without duplicates
#[must_use]
pub(crate) fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(server) = fields.next().and_then(parse_nameserver) else {
            continue;
        };
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    servers
}

fn parse_nameserver(token: &str) -> Option<SocketAddr> {
    let (addr, scope) = match token.split_once('%') {
        Some((addr, scope)) => (addr, Some(scope)),
        None => (token, None),
    };
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => Some(SocketAddr::V4(SocketAddrV4::new(v4, DNS_PORT))),
        IpAddr::V6(v6) => {
            let scope_id = match scope {
                Some(scope) => scope_id(scope)?,
                None => 0,
            };
            Some(SocketAddr::V6(SocketAddrV6::new(v6, DNS_PORT, 0, scope_id)))
        }
    }
}

/// A numeric zone index, or the index of the named interface
fn scope_id(scope: &str) -> Option<u32> {
    if let Ok(index) = scope.parse::<u32>() {
        return Some(index);
    }
    let name = std::ffi::CString::new(scope).ok()?;
    // SAFETY: name is a NUL-terminated C string that outlives the call, and if_nametoindex only reads it
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}
