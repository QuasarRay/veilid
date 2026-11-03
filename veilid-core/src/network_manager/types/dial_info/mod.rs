mod tcp;
mod udp;
#[cfg(feature = "enable-protocol-webtransport")]
mod webtransport;
mod ws;
#[cfg(feature = "enable-protocol-wss")]
mod wss;

use super::*;

pub(crate) use tcp::*;
pub(crate) use udp::*;
#[cfg(feature = "enable-protocol-webtransport")]
pub(crate) use webtransport::*;
pub(crate) use ws::*;
#[cfg(feature = "enable-protocol-wss")]
pub(crate) use wss::*;

// XXX: Eventually this needs to use the protocol FOURCC and become a more generic parser when protocols/address types become pluggable
// Keep member order appropriate for sorting < preference
// Must match ProtocolType order
#[derive(Clone, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum DialInfo {
    UDP(DialInfoUDP),
    TCP(DialInfoTCP),
    WS(DialInfoWS),
    #[cfg(feature = "enable-protocol-wss")]
    WSS(DialInfoWSS),
    #[cfg(feature = "enable-protocol-webtransport")]
    WebTransportStream(Box<DialInfoWebTransport>),
    #[cfg(feature = "enable-protocol-webtransport")]
    WebTransportDatagram(Box<DialInfoWebTransport>),
}
impl Default for DialInfo {
    fn default() -> Self {
        DialInfo::UDP(DialInfoUDP::default())
    }
}

impl fmt::Debug for DialInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // always use display for debug variant because everything about the
        // dialinfo is always in the full printed version and it makes debugging less verbose
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for DialInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            DialInfo::UDP(di) => write!(f, "udp|{}", di.socket_address),
            DialInfo::TCP(di) => write!(f, "tcp|{}", di.socket_address),
            DialInfo::WS(di) => {
                // The address is implied only when the url names it
                let url = format!("ws://{}", di.request);
                match SplitUrl::from_str(&url).map(|u| u.host) {
                    Ok(SplitUrlHost::IpAddr(a)) if di.socket_address.ip_addr() == a => {
                        write!(f, "ws|{}", di.request)
                    }
                    _ => write!(f, "ws|{}|{}", di.socket_address.ip_addr(), di.request),
                }
            }
            #[cfg(feature = "enable-protocol-wss")]
            DialInfo::WSS(di) => {
                let url = format!("wss://{}", di.request);
                match SplitUrl::from_str(&url).map(|u| u.host) {
                    Ok(SplitUrlHost::IpAddr(a)) if di.socket_address.ip_addr() == a => {
                        write!(f, "wss|{}", di.request)
                    }
                    _ => write!(f, "wss|{}|{}", di.socket_address.ip_addr(), di.request),
                }
            }
            #[cfg(feature = "enable-protocol-webtransport")]
            DialInfo::WebTransportStream(di) => {
                write!(
                    f,
                    "wts|{}|{}|{}|{}",
                    di.socket_address,
                    di.request,
                    encode_webtransport_cert_hashes(&di.cert_hashes),
                    di.expiration.unwrap_or_default().as_u64()
                )
            }
            #[cfg(feature = "enable-protocol-webtransport")]
            DialInfo::WebTransportDatagram(di) => {
                write!(
                    f,
                    "wtd|{}|{}|{}|{}",
                    di.socket_address,
                    di.request,
                    encode_webtransport_cert_hashes(&di.cert_hashes),
                    di.expiration.unwrap_or_default().as_u64()
                )
            }
        }
    }
}

impl FromStr for DialInfo {
    type Err = VeilidAPIError;
    fn from_str(s: &str) -> VeilidAPIResult<DialInfo> {
        let (proto, rest) = s.split_once('|').ok_or_else(|| {
            VeilidAPIError::parse_error("DialInfo::from_str missing protocol '|' separator", s)
        })?;
        match proto {
            "udp" => {
                let socket_address = SocketAddress::from_str(rest)?;
                Ok(DialInfo::udp(socket_address))
            }
            "tcp" => {
                let socket_address = SocketAddress::from_str(rest)?;
                Ok(DialInfo::tcp(socket_address))
            }
            "ws" => {
                let url = format!("ws://{}", rest);
                let split_url = SplitUrl::from_str(&url).map_err(|e| {
                    VeilidAPIError::parse_error(format!("unable to split WS url: {}", e), &url)
                })?;
                if split_url.scheme != "ws" || !url.starts_with("ws://") {
                    apibail_parse_error!("incorrect scheme for WS dialinfo", url);
                }
                let url_port = split_url.port.unwrap_or(80u16);

                match rest.split_once('|') {
                    Some((sa, rest)) => {
                        let address = Address::from_str(sa)?;

                        DialInfo::try_ws(
                            SocketAddress::new(address, url_port),
                            format!("ws://{}", rest),
                        )
                    }
                    None => {
                        let address = Address::from_str(&split_url.host.to_string())?;
                        DialInfo::try_ws(
                            SocketAddress::new(address, url_port),
                            format!("ws://{}", rest),
                        )
                    }
                }
            }
            #[cfg(feature = "enable-protocol-wss")]
            "wss" => {
                let url = format!("wss://{}", rest);
                let split_url = SplitUrl::from_str(&url).map_err(|e| {
                    VeilidAPIError::parse_error(format!("unable to split WSS url: {}", e), &url)
                })?;
                if split_url.scheme != "wss" || !url.starts_with("wss://") {
                    apibail_parse_error!("incorrect scheme for WSS dialinfo", url);
                }
                let url_port = split_url.port.unwrap_or(443u16);

                match rest.split_once('|') {
                    Some((sa, rest)) => {
                        let address = Address::from_str(sa)?;

                        DialInfo::try_wss(
                            SocketAddress::new(address, url_port),
                            format!("wss://{}", rest),
                        )
                    }
                    None => {
                        let address = Address::from_str(&split_url.host.to_string())?;
                        DialInfo::try_wss(
                            SocketAddress::new(address, url_port),
                            format!("wss://{}", rest),
                        )
                    }
                }
            }
            #[cfg(feature = "enable-protocol-webtransport")]
            "wts" | "wtd" => {
                let mut parts = rest.splitn(4, '|');
                let sa = parts.next().ok_or_else(|| {
                    VeilidAPIError::parse_error("missing webtransport socket address", s)
                })?;
                let request = parts.next().ok_or_else(|| {
                    VeilidAPIError::parse_error("missing webtransport request", s)
                })?;
                let cert_hashes = decode_webtransport_cert_hashes(parts.next().unwrap_or(""))?;
                let expiration = match parts.next() {
                    Some(x) if !x.is_empty() => {
                        let us = x.parse::<u64>().map_err(|e| {
                            VeilidAPIError::parse_error(
                                format!("invalid webtransport expiration: {}", e),
                                x,
                            )
                        })?;
                        (us != 0).then(|| Timestamp::new(us))
                    }
                    _ => None,
                };
                let socket_address = SocketAddress::from_str(sa)?;
                if proto == "wts" {
                    DialInfo::try_webtransport_stream(
                        socket_address,
                        request.to_string(),
                        cert_hashes,
                        expiration,
                    )
                } else {
                    DialInfo::try_webtransport_datagram(
                        socket_address,
                        request.to_string(),
                        cert_hashes,
                        expiration,
                    )
                }
            }
            _ => Err(VeilidAPIError::parse_error(
                "DialInfo::from_str has invalid scheme",
                s,
            )),
        }
    }
}

impl DialInfo {
    pub fn udp_from_socketaddr(socket_addr: SocketAddr) -> Self {
        Self::UDP(DialInfoUDP {
            socket_address: SocketAddress::from_socket_addr(socket_addr).canonical(),
        })
    }
    pub fn tcp_from_socketaddr(socket_addr: SocketAddr) -> Self {
        Self::TCP(DialInfoTCP {
            socket_address: SocketAddress::from_socket_addr(socket_addr).canonical(),
        })
    }
    pub fn udp(socket_address: SocketAddress) -> Self {
        Self::UDP(DialInfoUDP {
            socket_address: socket_address.canonical(),
        })
    }
    pub fn tcp(socket_address: SocketAddress) -> Self {
        Self::TCP(DialInfoTCP {
            socket_address: socket_address.canonical(),
        })
    }
    pub fn try_ws(socket_address: SocketAddress, url: String) -> VeilidAPIResult<Self> {
        let split_url = SplitUrl::from_str(&url).map_err(|e| {
            VeilidAPIError::parse_error(format!("unable to split WS url: {}", e), &url)
        })?;
        if split_url.scheme != "ws" || !url.starts_with("ws://") {
            apibail_parse_error!("incorrect scheme for WS dialinfo", url);
        }
        let url_port = split_url.port.unwrap_or(80u16);
        if url_port != socket_address.port() {
            apibail_parse_error!("socket address port doesn't match url port", url);
        }
        if let SplitUrlHost::IpAddr(a) = split_url.host {
            if socket_address.ip_addr() != a {
                apibail_parse_error!(
                    format!("request address does not match socket address: {}", a),
                    socket_address.to_string()
                );
            }
        }
        Ok(Self::WS(DialInfoWS {
            socket_address: socket_address.canonical(),
            request: url[5..].to_string(),
        }))
    }
    #[cfg(feature = "enable-protocol-wss")]
    pub fn try_wss(socket_address: SocketAddress, url: String) -> VeilidAPIResult<Self> {
        let split_url = SplitUrl::from_str(&url).map_err(|e| {
            VeilidAPIError::parse_error(format!("unable to split WSS url: {}", e), &url)
        })?;
        if split_url.scheme != "wss" || !url.starts_with("wss://") {
            apibail_parse_error!("incorrect scheme for WSS dialinfo", url);
        }
        let url_port = split_url.port.unwrap_or(443u16);
        if url_port != socket_address.port() {
            apibail_parse_error!("socket address port doesn't match url port", url);
        }
        if let SplitUrlHost::IpAddr(a) = split_url.host {
            if socket_address.ip_addr() != a {
                apibail_parse_error!(
                    format!("request address does not match socket address: {}", a),
                    socket_address.to_string()
                );
            }
        }
        Ok(Self::WSS(DialInfoWSS {
            socket_address: socket_address.canonical(),
            request: url[6..].to_string(),
        }))
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    pub fn try_webtransport_stream(
        socket_address: SocketAddress,
        url: String,
        cert_hashes: Vec<[u8; 32]>,
        expiration: Option<Timestamp>,
    ) -> VeilidAPIResult<Self> {
        Self::validate_webtransport_url(socket_address, &url, &cert_hashes)?;
        Ok(Self::WebTransportStream(Box::new(DialInfoWebTransport {
            socket_address: socket_address.canonical(),
            request: url,
            cert_hashes,
            expiration,
        })))
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    pub fn try_webtransport_datagram(
        socket_address: SocketAddress,
        url: String,
        cert_hashes: Vec<[u8; 32]>,
        expiration: Option<Timestamp>,
    ) -> VeilidAPIResult<Self> {
        Self::validate_webtransport_url(socket_address, &url, &cert_hashes)?;
        Ok(Self::WebTransportDatagram(Box::new(DialInfoWebTransport {
            socket_address: socket_address.canonical(),
            request: url,
            cert_hashes,
            expiration,
        })))
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    fn validate_webtransport_url(
        socket_address: SocketAddress,
        url: &str,
        cert_hashes: &[[u8; 32]],
    ) -> VeilidAPIResult<()> {
        if !url.starts_with("https://") {
            apibail_parse_error!("webtransport url must use https scheme", url);
        }
        let split_url = SplitUrl::from_str(url).map_err(|e| {
            VeilidAPIError::parse_error(format!("unable to split WebTransport url: {}", e), url)
        })?;
        let url_port = split_url.port.unwrap_or(443u16);
        if url_port != socket_address.port() {
            apibail_parse_error!("socket address port doesn't match url port", url);
        }
        if let SplitUrlHost::IpAddr(a) = split_url.host {
            if !Self::webtransport_ip_literal_matches_socket_address(socket_address, a) {
                apibail_parse_error!(
                    format!("request address does not match socket address: {}", a),
                    socket_address.to_string()
                );
            }
        }
        if !Self::webtransport_hostname_pins_no_cert_hashes(&split_url.host, cert_hashes) {
            apibail_parse_error!(
                "webtransport dial info with certificate hashes must use an IP-literal host, not a DNS hostname",
                url
            );
        }
        Ok(())
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    fn webtransport_ip_literal_matches_socket_address(
        socket_address: SocketAddress,
        host: IpAddr,
    ) -> bool {
        socket_address.ip_addr() == host
    }
    #[cfg(feature = "enable-protocol-webtransport")]
    fn webtransport_hostname_pins_no_cert_hashes(
        host: &SplitUrlHost,
        cert_hashes: &[[u8; 32]],
    ) -> bool {
        match host {
            SplitUrlHost::IpAddr(_) => true,
            SplitUrlHost::Hostname(_) => cert_hashes.is_empty(),
        }
    }
    pub fn protocol_type(&self) -> ProtocolType {
        match self {
            Self::UDP(_) => ProtocolType::UDP,
            Self::TCP(_) => ProtocolType::TCP,
            Self::WS(_) => ProtocolType::WS,
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(_) => ProtocolType::WSS,
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(_) => ProtocolType::WTS,
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportDatagram(_) => ProtocolType::WTD,
        }
    }
    pub fn address_type(&self) -> AddressType {
        self.socket_address().address_type()
    }
    pub fn transport_type(&self) -> TransportType {
        TransportType::new(self.protocol_type(), self.address_type())
    }
    pub fn address(&self) -> Address {
        match self {
            Self::UDP(di) => di.socket_address.address(),
            Self::TCP(di) => di.socket_address.address(),
            Self::WS(di) => di.socket_address.address(),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => di.socket_address.address(),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                di.socket_address.address()
            }
        }
    }
    #[expect(dead_code)]
    pub fn set_address(&mut self, address: Address) {
        match self {
            Self::UDP(di) => di.socket_address.set_address(address),
            Self::TCP(di) => di.socket_address.set_address(address),
            Self::WS(di) => di.socket_address.set_address(address),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => di.socket_address.set_address(address),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                di.socket_address.set_address(address)
            }
        }
    }
    pub fn socket_address(&self) -> SocketAddress {
        match self {
            Self::UDP(di) => di.socket_address,
            Self::TCP(di) => di.socket_address,
            Self::WS(di) => di.socket_address,
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => di.socket_address,
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => di.socket_address,
        }
    }
    pub fn ip_addr(&self) -> IpAddr {
        match self {
            Self::UDP(di) => di.socket_address.ip_addr(),
            Self::TCP(di) => di.socket_address.ip_addr(),
            Self::WS(di) => di.socket_address.ip_addr(),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => di.socket_address.ip_addr(),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                di.socket_address.ip_addr()
            }
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            Self::UDP(di) => di.socket_address.port(),
            Self::TCP(di) => di.socket_address.port(),
            Self::WS(di) => di.socket_address.port(),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => di.socket_address.port(),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                di.socket_address.port()
            }
        }
    }
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    pub fn set_port(&mut self, port: u16) {
        match self {
            Self::UDP(di) => di.socket_address.set_port(port),
            Self::TCP(di) => di.socket_address.set_port(port),
            Self::WS(di) => di.socket_address.set_port(port),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => di.socket_address.set_port(port),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                di.socket_address.set_port(port)
            }
        }
    }
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self {
            Self::UDP(di) => di.socket_address.socket_addr(),
            Self::TCP(di) => di.socket_address.socket_addr(),
            Self::WS(di) => di.socket_address.socket_addr(),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => di.socket_address.socket_addr(),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                di.socket_address.socket_addr()
            }
        }
    }
    pub fn peer_address(&self) -> PeerAddress {
        match self {
            Self::UDP(di) => PeerAddress::new(di.socket_address, ProtocolType::UDP),
            Self::TCP(di) => PeerAddress::new(di.socket_address, ProtocolType::TCP),
            Self::WS(di) => PeerAddress::new(di.socket_address, ProtocolType::WS),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => PeerAddress::new(di.socket_address, ProtocolType::WSS),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) => PeerAddress::new(di.socket_address, ProtocolType::WTS),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportDatagram(di) => {
                PeerAddress::new(di.socket_address, ProtocolType::WTD)
            }
        }
    }
    pub fn request(&self) -> Option<String> {
        match self {
            Self::UDP(_) => None,
            Self::TCP(_) => None,
            Self::WS(di) => Some(format!("ws://{}", di.request)),
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => Some(format!("wss://{}", di.request)),
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                Some(di.request.clone())
            }
        }
    }
    pub fn expiration(&self) -> Option<Timestamp> {
        match self {
            Self::UDP(_) | Self::TCP(_) | Self::WS(_) => None,
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(_) => None,
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => di.expiration,
        }
    }
    pub fn is_valid(&self) -> bool {
        let socket_address = self.socket_address();
        let address = socket_address.address();
        let port = socket_address.port();
        (address.is_global() || address.is_local()) && port > 0
    }

    pub fn validate(&self) -> VeilidAPIResult<()> {
        if !self.is_valid() {
            apibail_parse_error!(
                "dial info address is not routable, or its port is zero",
                self.socket_address().to_string()
            );
        }
        match self {
            Self::UDP(_) | Self::TCP(_) => Ok(()),
            Self::WS(di) => {
                Self::try_ws(di.socket_address, format!("ws://{}", di.request)).map(|_| ())
            }
            #[cfg(feature = "enable-protocol-wss")]
            Self::WSS(di) => {
                Self::try_wss(di.socket_address, format!("wss://{}", di.request)).map(|_| ())
            }
            #[cfg(feature = "enable-protocol-webtransport")]
            Self::WebTransportStream(di) | Self::WebTransportDatagram(di) => {
                Self::validate_webtransport_url(di.socket_address, &di.request, &di.cert_hashes)
            }
        }
    }

    pub fn make_filter(&self) -> DialInfoFilter {
        DialInfoFilter::from(TransportType::from(self))
    }

    pub fn ordered_sequencing_sort(a: &DialInfo, b: &DialInfo) -> core::cmp::Ordering {
        let s = ProtocolType::ordered_sequencing_sort(&a.protocol_type(), &b.protocol_type());
        if s != core::cmp::Ordering::Equal {
            return s;
        }
        match (a, b) {
            (DialInfo::UDP(a), DialInfo::UDP(b)) => a.cmp(b),
            (DialInfo::TCP(a), DialInfo::TCP(b)) => a.cmp(b),
            (DialInfo::WS(a), DialInfo::WS(b)) => a.cmp(b),
            #[cfg(feature = "enable-protocol-wss")]
            (DialInfo::WSS(a), DialInfo::WSS(b)) => a.cmp(b),
            #[cfg(feature = "enable-protocol-webtransport")]
            (DialInfo::WebTransportStream(a), DialInfo::WebTransportStream(b)) => a.cmp(b),
            #[cfg(feature = "enable-protocol-webtransport")]
            (DialInfo::WebTransportDatagram(a), DialInfo::WebTransportDatagram(b)) => a.cmp(b),
            _ => {
                #[cfg(debug_assertions)]
                // PANIC-CENSUS: debug-only release logs and orders anyway
                unreachable!("mismatched DialInfo variants after equal protocol_type");
                #[cfg(not(debug_assertions))]
                {
                    tracing::error!("mismatched DialInfo variants after equal protocol_type sort");
                    core::cmp::Ordering::Equal
                }
            }
        }
    }
}

impl MatchesDialInfoFilter for DialInfo {
    fn matches_filter(&self, filter: &DialInfoFilter) -> bool {
        filter.contains_transport(self.into())
    }
}

#[cfg(feature = "enable-protocol-webtransport")]
fn encode_webtransport_cert_hashes(cert_hashes: &[[u8; 32]]) -> String {
    cert_hashes
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(feature = "enable-protocol-webtransport")]
fn decode_webtransport_cert_hashes(s: &str) -> VeilidAPIResult<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    if s.is_empty() {
        return Ok(out);
    }
    for part in s.split(',') {
        let bytes = hex::decode(part).map_err(|e| {
            VeilidAPIError::parse_error(format!("invalid hex in cert hash: {}", e), part)
        })?;
        let h: [u8; 32] = bytes.try_into().map_err(|_| {
            VeilidAPIError::parse_error(
                "webtransport cert hash must be 32 bytes (64 hex chars)",
                part,
            )
        })?;
        out.push(h);
    }
    Ok(out)
}
