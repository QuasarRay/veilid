use crate::*;

cfg_if::cfg_if! {
    if #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] {
        use directories::ProjectDirs;
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
        /// Minimum allowed total `network.max_connections` on wasm32/browser.
        pub const MAX_CONNECTIONS_MIN: u32 = 16;
        /// Maximum allowed total `network.max_connections` on wasm32/browser.
        pub const MAX_CONNECTIONS_MAX: u32 = 64;
    } else {
        /// Minimum allowed total `network.max_connections` on native platforms.
        pub const MAX_CONNECTIONS_MIN: u32 = 32;
        /// Maximum allowed total `network.max_connections` on native platforms.
        pub const MAX_CONNECTIONS_MAX: u32 = 512;
    }
}

/// What the page a browser node runs in lets it dial
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PageContext {
    /// Served over https, so a clear websocket to a peer is refused as mixed content
    pub https: bool,
    /// A secure context
    pub secure: bool,
    /// The browser offers WebTransport to this page
    pub webtransport: bool,
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl PageContext {
    /// The page this node runs in
    pub fn current() -> Self {
        Self {
            https: is_browser_https(),
            secure: is_secure_context(),
            webtransport: has_webtransport(),
        }
    }
}

/// The protocols a node dials out over
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OutboundProtocols {
    /// Raw UDP
    pub udp: bool,
    /// Raw TCP
    pub tcp: bool,
    /// WebSocket, in the clear
    pub ws: bool,
    /// WebSocket over TLS
    pub wss: bool,
    /// WebTransport, streams and datagrams
    pub webtransport: bool,
}

impl OutboundProtocols {
    /// Whether this protocol can reach arbitrary peers; WSS cannot, peers listen on it only with a CA certificate
    fn dials_any_peer(&self) -> bool {
        self.udp || self.tcp || self.ws || self.webtransport
    }

    /// Whether a bootstrap can be dialed over this protocol
    fn dials_bootstraps(&self, bootstrap_protocol: VeilidConfigBootstrapProtocol) -> bool {
        match bootstrap_protocol {
            VeilidConfigBootstrapProtocol::Udp => self.udp,
            VeilidConfigBootstrapProtocol::Tcp => self.tcp,
            VeilidConfigBootstrapProtocol::Ws => self.ws,
            VeilidConfigBootstrapProtocol::Wss => self.wss,
            VeilidConfigBootstrapProtocol::Wts => self.webtransport,
        }
    }
}

/// Enable and configure UDP.
///
/// ```yaml
/// udp:
///     enabled: true
///     socket_pool_size: 0
///     listen_address: ':5150'
///     public_address: ''
/// ```
///
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigUDP {
    /// Enable the UDP protocol.
    pub enabled: bool,
    /// Local address to bind, as `ip:port` (empty binds the default port).
    pub listen_address: String,
    /// Externally-reachable `ip:port` to advertise, if behind NAT/port mapping.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub public_address: Option<String>,
}

impl Default for VeilidConfigUDP {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                let enabled = false;
            } else {
                let enabled = true;
            }
        }
        Self {
            enabled,
            listen_address: String::from(""),
            public_address: None,
        }
    }
}

/// Enable and configure TCP.
///
/// ```yaml
/// tcp:
///     connect: true
///     listen: true
///     listen_address: ':5150'
///     public_address: ''
///
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigTCP {
    /// Allow outbound TCP connections.
    pub connect: bool,
    /// Accept inbound TCP connections.
    pub listen: bool,
    /// Local address to bind, as `ip:port` (empty binds the default port).
    pub listen_address: String,
    /// Externally-reachable `ip:port` to advertise, if behind NAT/port mapping.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub public_address: Option<String>,
}

impl Default for VeilidConfigTCP {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                let connect = false;
                let listen = false;
            } else {
                let connect = true;
                let listen = true;
            }
        }
        Self {
            connect,
            listen,
            listen_address: String::from(""),
            public_address: None,
        }
    }
}

/// Enable and configure Web Sockets.
///
/// ```yaml
/// ws:
///     connect: true
///     listen: true
///     listen_address: ':5150'
///     path: 'ws'
///     url: 'ws://localhost:5150/ws'
///
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigWS {
    /// Allow outbound WebSocket connections.
    pub connect: bool,
    /// Accept inbound WebSocket connections.
    pub listen: bool,
    /// Local address to bind, as `ip:port` (empty binds the default port).
    pub listen_address: String,
    /// URL path served by the WebSocket listener.
    pub path: String,
    /// Externally-reachable URL to advertise, if behind NAT/proxy.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub url: Option<String>,
}

impl Default for VeilidConfigWS {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                let connect = true;
                let listen = false;
            } else {
                let connect = true;
                let listen = true;
            }
        }
        Self {
            connect,
            listen,
            listen_address: String::from(""),
            path: String::from("ws"),
            url: None,
        }
    }
}

/// Enable and configure Secure Web Sockets.
///
/// ```yaml
/// wss:
///     connect: true
///     listen: false
///     listen_address: ':5150'
///     path: 'ws'
///     url: ''
///
#[cfg(feature = "enable-protocol-wss")]
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigWSS {
    /// Allow outbound secure WebSocket connections.
    pub connect: bool,
    /// Accept inbound secure WebSocket connections.
    pub listen: bool,
    /// Local address to bind, as `ip:port` (empty binds the default port).
    pub listen_address: String,
    /// URL path served by the secure WebSocket listener.
    pub path: String,
    /// Externally-reachable URL to advertise (required and validated for TLS protocols).
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub url: Option<String>, // Fixed URL is not optional for TLS-based protocols and is dynamically validated
}

#[cfg(feature = "enable-protocol-wss")]
impl Default for VeilidConfigWSS {
    fn default() -> Self {
        Self {
            connect: true,
            listen: false,
            listen_address: String::from(""),
            path: String::from("ws"),
            url: None,
        }
    }
}

/// Enable and configure WebTransport (HTTP/3 over QUIC).
///
/// `listen_address` means the same thing here as it does for the other protocols. When it
/// resolves to the same bind target as `udp.listen_address`, WebTransport shares the node's
/// UDP listener socket and port, with the QUIC traffic demultiplexed from raw UDP. When it
/// resolves to a different bind target, WebTransport binds a dedicated QUIC-only UDP socket
/// instead. `listen` defaults to false in the browser, which cannot accept inbound
/// connections.
///
/// By default the listener generates and rotates its own ECDSA-P256 certificate and
/// advertises it by SHA-256 hash, so no CA certificate or hostname is required. Setting
/// `url` switches it into CA-signed mode for bootstrap servers reachable by domain name:
/// the certificate comes from `network.tls` and clients validate it against the system
/// CA roots.
///
/// ```yaml
/// webtransport:
///     connect: true
///     listen: true
///     listen_address: ':5150'
///     path: 'wt'
///     url: ''
///
#[cfg(feature = "enable-protocol-webtransport")]
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigWebTransport {
    /// Allow outbound WebTransport connections.
    pub connect: bool,
    /// Accept inbound WebTransport connections.
    pub listen: bool,
    /// Local address to bind, as `ip:port` (empty binds the default port). A bind target
    /// equal to `udp.listen_address`'s shares the node's UDP socket rather than binding a
    /// dedicated one.
    #[serde(default)]
    pub listen_address: String,
    /// URL path segment served by the WebTransport listener. Advertised self-signed URLs
    /// become `https://{addr}:{port}/{path}`, and inbound requests with a different path
    /// are rejected.
    #[serde(default = "default_webtransport_path")]
    pub path: String,
    /// Externally-reachable `https://host:port/` URL to advertise, which selects CA-signed
    /// mode.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub url: Option<String>,
}

#[cfg(feature = "enable-protocol-webtransport")]
fn default_webtransport_path() -> String {
    "wt".to_string()
}

/// Maximum length of an inbound WebTransport CONNECT request path, mirroring the WS listener's
/// `MAX_WS_HEADER_LENGTH` cap on a single request header.
///
/// The HTTP/3 layer bounds a CONNECT header block only by its 64 KiB frame limit, so without
/// this the path an unauthenticated peer sends is copied and logged at that size.
#[cfg(feature = "enable-protocol-webtransport")]
pub(crate) const MAX_WEBTRANSPORT_PATH_LENGTH: usize = 512;

#[cfg(feature = "enable-protocol-webtransport")]
impl Default for VeilidConfigWebTransport {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                // Browsers connect out via WebTransport but cannot listen.
                let connect = true;
                let listen = false;
            } else {
                let connect = true;
                let listen = true;
            }
        }
        Self {
            connect,
            listen,
            listen_address: String::from(""),
            path: default_webtransport_path(),
            url: None,
        }
    }
}

/// Configure Network Protocols.
///
/// Veilid can communicate over UDP, TCP, and Web Sockets.
///
/// All protocols are available by default, and the Veilid node will
/// sort out which protocol is used for each peer connection.
///
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigProtocol {
    /// UDP protocol configuration.
    pub udp: VeilidConfigUDP,
    /// TCP protocol configuration.
    pub tcp: VeilidConfigTCP,
    /// WebSocket protocol configuration.
    pub ws: VeilidConfigWS,
    /// Secure WebSocket protocol configuration (requires `enable-protocol-wss`).
    #[cfg(feature = "enable-protocol-wss")]
    #[serde(default)]
    pub wss: VeilidConfigWSS,
    /// WebTransport protocol configuration (requires `enable-protocol-webtransport`).
    #[cfg(feature = "enable-protocol-webtransport")]
    #[serde(default)]
    pub webtransport: VeilidConfigWebTransport,
}

/// Privacy preferences for routes.
///
/// ```yaml
/// privacy:
///     require_inbound_relay: false
///     country_code_denylist: [] # only with `--features=geolocation`
/// ```
#[apply(api_data_struct!)]
#[api(eq, default)]
#[cfg_attr(target_arch = "wasm32", derive(Tsify))]
pub struct VeilidConfigPrivacy {
    /// Always use an inbound relay; never accept direct inbound connections.
    pub require_inbound_relay: bool,
    /// Two-letter country codes to refuse routing through (requires `geolocation`).
    #[cfg(feature = "geolocation")]
    #[serde(default)]
    pub country_code_denylist: Vec<CountryCode>,
}

/// Virtual networking client support for testing/simulation purposes
///
/// ```yaml
/// virtual_network:
///     enabled: false
///     server_address: ""
/// ```
#[cfg(feature = "virtual-network")]
#[apply(api_data_struct!)]
#[api(eq, default)]
#[cfg_attr(target_arch = "wasm32", derive(Tsify))]
pub struct VeilidConfigVirtualNetwork {
    /// Route all networking through the virtual network server.
    pub enabled: bool,
    /// Address of the virtual network server, as `host:port`.
    pub server_address: String,
}

/// Configure TLS.
///
/// ```yaml
/// tls:
///     certificate_path: /path/to/cert
///     private_key_path: /path/to/private/key
///     connection_initial_timeout_ms: 2000
///
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigTLS {
    /// Path to the TLS certificate (PEM) for inbound TLS protocols.
    pub certificate_path: String,
    /// Path to the TLS private key (PEM) for inbound TLS protocols.
    pub private_key_path: String,
    /// Timeout for completing a TLS handshake, in milliseconds.
    pub connection_initial_timeout_ms: u32,
}

impl Default for VeilidConfigTLS {
    fn default() -> Self {
        Self {
            certificate_path: "".to_string(),
            private_key_path: "".to_string(),
            connection_initial_timeout_ms: 2000,
        }
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    allow(unused_variables)
)]
/// Default directory for TLS certificates and keys, given the program identity and a relative sub-path.
#[must_use]
pub fn get_default_ssl_directory(
    program_name: &str,
    organization: &str,
    qualifier: &str,
    sub_path: &str,
) -> String {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
            "".to_owned()
        } else {
            use std::path::PathBuf;
            ProjectDirs::from(qualifier, organization, program_name)
                .map(|dirs| dirs.data_local_dir().join("ssl").join(sub_path))
                .unwrap_or_else(|| PathBuf::from("./ssl").join(sub_path))
                .to_string_lossy()
                .into()
        }
    }
}

/// Configure the Distributed Hash Table (DHT).
/// Defaults should be used here unless you are absolutely sure you know what you're doing.
/// If you change the count/fanout/timeout parameters, you may render your node inoperable
/// for correct DHT operations.
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigDHT {
    /// Number of subkeys cached for locally-created DHT records.
    pub local_subkey_cache_size: u32,
    /// Memory cap for the local subkey cache, in megabytes.
    pub local_max_subkey_cache_memory_mb: u32,
    /// Number of subkeys cached for DHT records stored on behalf of others.
    pub remote_subkey_cache_size: u32,
    /// Maximum number of remote DHT records stored on behalf of others.
    pub remote_max_records: u32,
    /// Memory cap for the remote subkey cache, in megabytes.
    pub remote_max_subkey_cache_memory_mb: u32,
    /// Disk limit for remote DHT record storage, in MiB (0 = a share of the storage budget).
    pub remote_max_storage_space_mb: u32,
    /// Max concurrent DHT network operations in flight (local-only ops exempt).
    #[serde(default = "default_dht_max_concurrent_operations")]
    pub max_concurrent_operations: u32,
}

/// Per-platform default for max_concurrent_operations (single source for serde + Default).
fn default_dht_max_concurrent_operations() -> u32 {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
            16
        } else {
            16
        }
    }
}

impl Default for VeilidConfigDHT {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                let local_subkey_cache_size = 128;
                let local_max_subkey_cache_memory_mb = 256;
                let remote_subkey_cache_size = 64;
                let remote_max_records = 64;
                let remote_max_subkey_cache_memory_mb = 256;
            } else {
                let local_subkey_cache_size = 1024;
                let local_max_subkey_cache_memory_mb = match total_memory_bytes() {
                    Some(mem) => (mem / 32u64 / (1024u64 * 1024u64)) as u32,
                    None => 256,
                };
                let remote_subkey_cache_size = 128;
                let remote_max_records = 128;
                let remote_max_subkey_cache_memory_mb = match total_memory_bytes() {
                    Some(mem) => (mem / 32u64 / (1024u64 * 1024u64)) as u32,
                    None => 256,
                };
            }
        }

        let max_concurrent_operations = default_dht_max_concurrent_operations();

        Self {
            local_subkey_cache_size,
            local_max_subkey_cache_memory_mb,
            remote_subkey_cache_size,
            remote_max_records,
            remote_max_subkey_cache_memory_mb,
            remote_max_storage_space_mb: 0,
            max_concurrent_operations,
        }
    }
}

/// Configure RPC.
///
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigRPC {
    /// Default number of hops used when allocating private routes.
    pub default_route_hop_count: u8,
}

impl Default for VeilidConfigRPC {
    fn default() -> Self {
        Self {
            default_route_hop_count: 1,
        }
    }
}

/// Configure the network routing table.
///
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigRoutingTable {
    /// This node's identity public keys, by crypto kind (empty = generate fresh).
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        tsify(type = "string[]")
    )]
    pub public_keys: PublicKeyGroup,
    /// Node identity secret keys matching `public_keys` (empty = generate fresh).
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        tsify(type = "string[]")
    )]
    pub secret_keys: SecretKeyGroup,
    /// Bootstrap servers to join the network from: a dial info url, a `host`, or a `host:port`.
    /// A bare host resolves to every address it names, each dialed on port 5150 or the one
    /// given, over `bootstrap_protocols` in order.
    pub bootstrap: Vec<String>,
    /// Protocols a bootstrap request goes out on, in order of preference, for a bare host in
    /// `bootstrap` and for a payload's nodes. Defaults to the encrypted ones, WSS first: an
    /// insecure browser page can open WSS but not WebTransport. A node whose list has no
    /// protocol it can dial fails to start.
    #[serde(default = "default_bootstrap_protocols")]
    pub bootstrap_protocols: Vec<VeilidConfigBootstrapProtocol>,
    /// Public keys trusted to sign bootstrap records.
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        tsify(type = "string[]")
    )]
    pub bootstrap_keys: Vec<PublicKey>,
    /// Bootstrap record lines, verbatim: the signed payload line (`2|...`) that
    /// `veilid-server --sign-bootstrap-payload` prints, and the 0.5.x TXT lines that
    /// `--dump-bootstrap-records` prints (served only with `enable-bootstrap-v0`/`-v1`). The
    /// payload is served to bootstrap requests and names the nodes this node joins from. Empty
    /// by default, in which case the payload comes from the bootstraps.
    pub bootstrap_records: Vec<String>,
    /// Answer bootstrap requests with the payload this node holds and its peers. Off by
    /// default: a bootstrap server turns it on, and an app has no reason to serve. A node that
    /// finds itself among its own bootstraps answers regardless. Either way the node answers
    /// only while it is directly reachable on every protocol it listens on, which it advertises
    /// as the `BOOT` capability.
    #[serde(default)]
    pub serve_direct_bootstrap: bool,
    // xxx pub enable_public_internet: bool,
    // xxx pub enable_local_network: bool,
}

impl Default for VeilidConfigRoutingTable {
    fn default() -> Self {
        // A bare host expands over `bootstrap_protocols`, so browsers dial WSS and WebTransport
        let bootstrap = vec!["bootstrap.veilid.net".to_string()];
        let bootstrap_keys = vec![
            // Primary Veilid Foundation bootstrap signing key
            PublicKey::from_str("VLD0:Vj0lKDdUQXmQ5Ol1SZdlvXkBHUccBcQvGLN9vbLSI7k").unwrap_or_log(),
            // Secondary Veilid Foundation bootstrap signing key
            PublicKey::from_str("VLD0:QeQJorqbXtC7v3OlynCZ_W3m76wGNeB5NTF81ypqHAo").unwrap_or_log(),
            // Backup Veilid Foundation bootstrap signing key
            PublicKey::from_str("VLD0:QNdcl-0OiFfYVj9331XVR6IqZ49NG-E18d5P7lwi4TA").unwrap_or_log(),
        ];

        Self {
            public_keys: PublicKeyGroup::default(),
            secret_keys: SecretKeyGroup::default(),
            bootstrap,
            bootstrap_protocols: default_bootstrap_protocols(),
            bootstrap_keys,
            bootstrap_records: vec![],
            serve_direct_bootstrap: false,
        }
    }
}

fn default_bootstrap_protocols() -> Vec<VeilidConfigBootstrapProtocol> {
    vec![
        VeilidConfigBootstrapProtocol::Wss,
        VeilidConfigBootstrapProtocol::Wts,
    ]
}

/// A protocol a bootstrap request can go out on.
#[apply(api_data_enum!)]
#[api(eq, copy, ord, hash, ts(namespace))]
pub enum VeilidConfigBootstrapProtocol {
    /// Raw UDP, in the clear.
    #[serde(rename = "UDP", alias = "udp")]
    Udp,
    /// Raw TCP, in the clear.
    #[serde(rename = "TCP", alias = "tcp")]
    Tcp,
    /// WebSocket, in the clear.
    #[serde(rename = "WS", alias = "ws")]
    Ws,
    /// WebSocket over TLS.
    #[serde(rename = "WSS", alias = "wss")]
    Wss,
    /// WebTransport streams, over QUIC's TLS.
    #[serde(rename = "WTS", alias = "wts")]
    Wts,
}

impl fmt::Display for VeilidConfigBootstrapProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VeilidConfigBootstrapProtocol::Udp => write!(f, "UDP"),
            VeilidConfigBootstrapProtocol::Tcp => write!(f, "TCP"),
            VeilidConfigBootstrapProtocol::Ws => write!(f, "WS"),
            VeilidConfigBootstrapProtocol::Wss => write!(f, "WSS"),
            VeilidConfigBootstrapProtocol::Wts => write!(f, "WTS"),
        }
    }
}

impl FromStr for VeilidConfigBootstrapProtocol {
    type Err = VeilidAPIError;
    fn from_str(s: &str) -> VeilidAPIResult<VeilidConfigBootstrapProtocol> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Ok(VeilidConfigBootstrapProtocol::Udp),
            "tcp" => Ok(VeilidConfigBootstrapProtocol::Tcp),
            "ws" => Ok(VeilidConfigBootstrapProtocol::Ws),
            "wss" => Ok(VeilidConfigBootstrapProtocol::Wss),
            "wts" => Ok(VeilidConfigBootstrapProtocol::Wts),
            _ => apibail_invalid_argument!("invalid VeilidConfigBootstrapProtocol string", "s", s),
        }
    }
}

/// An IP address family (IP version) the node may use.
#[apply(api_data_enum!)]
#[api(eq, copy, ord, hash, ts(namespace))]
pub enum VeilidConfigAddressType {
    /// IPv4 (32-bit) addresses.
    #[serde(rename = "IPV4", alias = "ipv4", alias = "v4", alias = "4")]
    Ipv4,
    /// IPv6 (128-bit) addresses.
    #[serde(rename = "IPV6", alias = "ipv6", alias = "v6", alias = "6")]
    Ipv6,
}

impl fmt::Display for VeilidConfigAddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VeilidConfigAddressType::Ipv4 => write!(f, "IPV4"),
            VeilidConfigAddressType::Ipv6 => write!(f, "IPV6"),
        }
    }
}

impl FromStr for VeilidConfigAddressType {
    type Err = VeilidAPIError;
    fn from_str(s: &str) -> VeilidAPIResult<VeilidConfigAddressType> {
        match s.to_ascii_lowercase().as_str() {
            "v4" | "4" | "ipv4" => Ok(VeilidConfigAddressType::Ipv4),
            "v6" | "6" | "ipv6" => Ok(VeilidConfigAddressType::Ipv6),
            _ => apibail_invalid_argument!("invalid VeilidConfigAddressType string", "s", s),
        }
    }
}

/// Network subsystem configuration: connections, routing table, RPC, DHT, transports, and privacy.
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigNetwork {
    /// Maximum total simultaneous connections across all protocols.
    /// Range: native 32-512, wasm32/browser 16-64.
    pub max_connections: u32,
    /// Optional password; its presence joins a private network with a derived network key.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub network_key_password: Option<String>,
    /// Routing table identity and bootstrap configuration.
    pub routing_table: VeilidConfigRoutingTable,
    /// RPC configuration.
    pub rpc: VeilidConfigRPC,
    /// DHT cache and storage configuration.
    pub dht: VeilidConfigDHT,
    /// Enabled IP address families (empty = all available).
    #[serde(default)]
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub address_types: Vec<VeilidConfigAddressType>,
    /// Use UPnP to map ports on the local gateway.
    pub upnp: bool,
    /// Watch for and react to local address changes (`None` = auto-detect).
    pub detect_address_changes: Option<bool>,
    /// Wait before retrying a listen address that failed to bind, in milliseconds.
    #[serde(default = "default_bind_retry_ms")]
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub bind_retry_ms: u32,
    /// TLS configuration for inbound secure protocols.
    pub tls: VeilidConfigTLS,
    /// Per-protocol (UDP/TCP/WS/WSS) configuration.
    pub protocol: VeilidConfigProtocol,
    /// Privacy and relay preferences.
    pub privacy: VeilidConfigPrivacy,
    /// Virtual network client configuration for testing and simulation (requires `virtual-network`).
    #[cfg(feature = "virtual-network")]
    #[serde(default)]
    pub virtual_network: VeilidConfigVirtualNetwork,
}

impl Default for VeilidConfigNetwork {
    fn default() -> Self {
        Self {
            max_connections: 32,
            network_key_password: None,
            address_types: Vec::new(),
            routing_table: VeilidConfigRoutingTable::default(),
            rpc: VeilidConfigRPC::default(),
            dht: VeilidConfigDHT::default(),
            upnp: true,
            detect_address_changes: Some(true),
            bind_retry_ms: default_bind_retry_ms(),
            tls: VeilidConfigTLS::default(),
            protocol: VeilidConfigProtocol::default(),
            privacy: VeilidConfigPrivacy::default(),
            #[cfg(feature = "virtual-network")]
            virtual_network: VeilidConfigVirtualNetwork::default(),
        }
    }
}

/// Default for bind_retry_ms (single source for serde + Default).
fn default_bind_retry_ms() -> u32 {
    10_000
}

/// Default share of a filesystem the shared stores may use, when neither limit is set.
const DEFAULT_STORAGE_LIMIT_PERCENT: u32 = 25;

/// Default total for the shared stores in MiB, when neither limit is set.
pub(crate) fn default_storage_limit_mb() -> u32 {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
            128
        } else {
            256
        }
    }
}

/// Where the stores live and the disk budget of the stores that hold data for other nodes.
///
/// A store directory left empty is `<directory>/<store>`. The shared stores (the remote record
/// store, and later the block store's remote cache) split one budget per filesystem:
/// `limit_percent` of its free space plus what the shared stores already use there, and
/// `limit_mb` across all of them. Setting one limit drops the other's default; with neither set
/// both defaults apply. Each shared store may always grow to an equal share of each budget it
/// draws on, or to `minimum_mb` if larger, and may borrow what the others leave unused.
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigStorage {
    /// Base directory for the stores (empty = each store's own directory).
    pub directory: String,
    /// Share of each filesystem the shared stores may use, in percent.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub limit_percent: Option<u32>,
    /// Total the shared stores may use, in MiB.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub limit_mb: Option<u32>,
    /// Size each shared store may always grow to, in MiB.
    pub minimum_mb: u32,
}

impl VeilidConfigStorage {
    /// The percent and MiB limits in force: both defaults when neither is set, else as set.
    #[must_use]
    pub fn effective_limits(&self) -> (Option<u32>, Option<u32>) {
        if self.limit_percent.is_none() && self.limit_mb.is_none() {
            (
                Some(DEFAULT_STORAGE_LIMIT_PERCENT),
                Some(default_storage_limit_mb()),
            )
        } else {
            (self.limit_percent, self.limit_mb)
        }
    }

    fn validate(&self) -> VeilidAPIResult<()> {
        if let Some(limit_percent) = self.limit_percent {
            if !(1..=100).contains(&limit_percent) {
                apibail_generic!(
                    "storage limit percent must be from 1 to 100 in 'storage.limit_percent'"
                );
            }
        }
        if self.limit_mb == Some(0) {
            apibail_generic!("storage limit must be >= 1 in 'storage.limit_mb'");
        }
        // The default total counts when no limit is set
        if let Some(limit_mb) = self.effective_limits().1 {
            if self.minimum_mb > limit_mb {
                apibail_generic!(
                    "storage minimum must be <= the {} MiB storage limit in 'storage.minimum_mb <= storage.limit_mb'",
                    limit_mb
                );
            }
        }
        Ok(())
    }
}

/// Table store configuration: the encrypted key-value database backing node state.
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigTableStore {
    /// Directory holding the table store database (empty = `<storage.directory>/table_store`).
    pub directory: String,
    /// Delete the table store on startup.
    pub delete: bool,
    /// Wipe the table store on an invalid device encryption key, rather than failing.
    pub wipe_on_invalid_device_encryption_key: bool,
    /// Maximum size of a single stored value, in megabytes.
    pub max_value_size_mb: u32,
}

impl Default for VeilidConfigTableStore {
    fn default() -> Self {
        Self {
            directory: "".to_string(),
            delete: false,
            wipe_on_invalid_device_encryption_key: true,
            max_value_size_mb: 64,
        }
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    allow(unused_variables)
)]
#[must_use]
fn get_default_storage_directory(
    program_name: &str,
    organization: &str,
    qualifier: &str,
) -> String {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
            "".to_owned()
        } else {
            use std::path::PathBuf;
            ProjectDirs::from(qualifier, organization, program_name)
                .map(|dirs| dirs.data_local_dir().to_path_buf())
                .unwrap_or_else(|| PathBuf::from("./"))
                .to_string_lossy()
                .into()
        }
    }
}

/// Block store configuration: content-addressed block storage.
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigBlockStore {
    /// Directory holding the block store (empty = `<storage.directory>/block_store`).
    pub directory: String,
    /// Delete the block store on startup.
    pub delete: bool,
    /// Disk limit for blocks stored for other nodes, in MiB (0 = a share of the storage budget).
    #[serde(default)]
    pub remote_max_storage_space_mb: u32,
}

impl Default for VeilidConfigBlockStore {
    fn default() -> Self {
        Self {
            directory: "".to_string(),
            delete: false,
            remote_max_storage_space_mb: 0,
        }
    }
}

/// Which storage backend the protected store uses for secrets.
///
/// The browser-only variants (`LocalStorage`, `IndexedDb`, `ExtensionStorage`) are rejected on
/// native platforms. `PlatformDefault` chooses per platform and runtime context: the OS keyring on
/// native, `localStorage` in a browser Window, IndexedDB in a worker, and extension storage in a
/// WebExtension.
#[apply(api_data_enum!)]
#[api(eq, copy, ord, default, ts(namespace))]
pub enum VeilidConfigProtectedStoreBackend {
    /// Choose automatically based on the platform and runtime context.
    #[default]
    PlatformDefault,
    /// Browser `localStorage` (Window contexts only).
    LocalStorage,
    /// Browser IndexedDB (available in worker contexts).
    IndexedDb,
    /// WebExtension storage (`chrome.storage.local`/`browser.storage.local`).
    ExtensionStorage,
    // /// Delegate to a registered secret-resolver callback.
    // Callback,
}

/// Protected store configuration: where secrets such as the device encryption key are kept.
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigProtectedStore {
    /// Fall back to insecure file storage if no OS keychain/keyring is available.
    pub allow_insecure_fallback: bool,
    /// Always use insecure file storage, ignoring any OS keychain/keyring.
    pub always_use_insecure_storage: bool,
    /// Directory for insecure-fallback storage (empty = `<storage.directory>/protected_store`).
    pub directory: String,
    /// Delete the protected store on startup.
    pub delete: bool,
    /// Password used to encrypt the device encryption key.
    pub device_encryption_key_password: String,
    /// New password to re-encrypt the device encryption key with, triggering a rotation.
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub new_device_encryption_key_password: Option<String>,
    /// Storage backend for secrets (`PlatformDefault` chooses per platform and runtime context).
    pub backend: VeilidConfigProtectedStoreBackend,
}

impl Default for VeilidConfigProtectedStore {
    fn default() -> Self {
        Self {
            allow_insecure_fallback: false,
            always_use_insecure_storage: false,
            directory: "".to_string(),
            delete: false,
            device_encryption_key_password: "".to_owned(),
            new_device_encryption_key_password: None,
            backend: VeilidConfigProtectedStoreBackend::PlatformDefault,
        }
    }
}

/// Capabilities advertised by this node.
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigCapabilities {
    /// Capabilities to disable (advertised as unavailable).
    pub disable: Vec<VeilidCapability>,
}

/// How the node lives through its host application moving between foreground and background.
///
/// ```yaml
/// app_lifecycle:
///     prefer_foreground: true
///     auto_detect_state: true
/// ```
#[cfg(feature = "app-lifecycle")]
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigAppLifecycle {
    /// While attached, keep a hidden desktop app from being throttled (macOS App Nap, Windows power throttling); no effect on mobile.
    pub prefer_foreground: bool,
    /// Follow the platform's own lifecycle reports where it has them; when false, only `report_app_lifecycle_state` counts.
    #[serde(default = "default_auto_detect_state")]
    pub auto_detect_state: bool,
}

#[cfg(feature = "app-lifecycle")]
impl Default for VeilidConfigAppLifecycle {
    fn default() -> Self {
        Self {
            prefer_foreground: true,
            auto_detect_state: default_auto_detect_state(),
        }
    }
}

/// Default for auto_detect_state (single source for serde + Default).
#[cfg(feature = "app-lifecycle")]
fn default_auto_detect_state() -> bool {
    true
}

/// Attachment configuration, owned by the attachment manager.
///
/// ```yaml
/// attachment:
///     app_lifecycle: # only with `--features=app-lifecycle`
///         prefer_foreground: true
///         auto_detect_state: true
/// ```
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigAttachment {
    /// Host application lifecycle handling (requires `app-lifecycle`).
    #[cfg(feature = "app-lifecycle")]
    #[serde(default)]
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub app_lifecycle: VeilidConfigAppLifecycle,
}

/// Logging level threshold (`Off` disables logging).
#[apply(api_data_enum!)]
#[api(eq, copy, ord, default, ts(namespace))]
pub enum VeilidConfigLogLevel {
    /// Logging disabled.
    #[default]
    Off,
    /// Errors only.
    Error,
    /// Warnings and above.
    Warn,
    /// Informational messages and above.
    Info,
    /// Debug messages and above.
    Debug,
    /// All messages, including trace.
    Trace,
}

impl From<VeilidLogLevel> for VeilidConfigLogLevel {
    fn from(value: VeilidLogLevel) -> Self {
        match value {
            VeilidLogLevel::Error => Self::Error,
            VeilidLogLevel::Warn => Self::Warn,
            VeilidLogLevel::Info => Self::Info,
            VeilidLogLevel::Debug => Self::Debug,
            VeilidLogLevel::Trace => Self::Trace,
        }
    }
}

impl From<Option<VeilidLogLevel>> for VeilidConfigLogLevel {
    fn from(value: Option<VeilidLogLevel>) -> Self {
        match value {
            None => Self::Off,
            Some(VeilidLogLevel::Error) => Self::Error,
            Some(VeilidLogLevel::Warn) => Self::Warn,
            Some(VeilidLogLevel::Info) => Self::Info,
            Some(VeilidLogLevel::Debug) => Self::Debug,
            Some(VeilidLogLevel::Trace) => Self::Trace,
        }
    }
}

impl From<tracing::level_filters::LevelFilter> for VeilidConfigLogLevel {
    fn from(value: tracing::level_filters::LevelFilter) -> Self {
        match value {
            tracing::level_filters::LevelFilter::OFF => Self::Off,
            tracing::level_filters::LevelFilter::ERROR => Self::Error,
            tracing::level_filters::LevelFilter::WARN => Self::Warn,
            tracing::level_filters::LevelFilter::INFO => Self::Info,
            tracing::level_filters::LevelFilter::DEBUG => Self::Debug,
            tracing::level_filters::LevelFilter::TRACE => Self::Trace,
        }
    }
}

impl From<VeilidConfigLogLevel> for tracing::level_filters::LevelFilter {
    fn from(val: VeilidConfigLogLevel) -> Self {
        match val {
            VeilidConfigLogLevel::Off => tracing::level_filters::LevelFilter::OFF,
            VeilidConfigLogLevel::Error => tracing::level_filters::LevelFilter::ERROR,
            VeilidConfigLogLevel::Warn => tracing::level_filters::LevelFilter::WARN,
            VeilidConfigLogLevel::Info => tracing::level_filters::LevelFilter::INFO,
            VeilidConfigLogLevel::Debug => tracing::level_filters::LevelFilter::DEBUG,
            VeilidConfigLogLevel::Trace => tracing::level_filters::LevelFilter::TRACE,
        }
    }
}

impl From<tracing::log::LevelFilter> for VeilidConfigLogLevel {
    fn from(value: tracing::log::LevelFilter) -> Self {
        match value {
            tracing::log::LevelFilter::Off => Self::Off,
            tracing::log::LevelFilter::Error => Self::Error,
            tracing::log::LevelFilter::Warn => Self::Warn,
            tracing::log::LevelFilter::Info => Self::Info,
            tracing::log::LevelFilter::Debug => Self::Debug,
            tracing::log::LevelFilter::Trace => Self::Trace,
        }
    }
}

impl From<VeilidConfigLogLevel> for tracing::log::LevelFilter {
    fn from(val: VeilidConfigLogLevel) -> Self {
        match val {
            VeilidConfigLogLevel::Off => tracing::log::LevelFilter::Off,
            VeilidConfigLogLevel::Error => tracing::log::LevelFilter::Error,
            VeilidConfigLogLevel::Warn => tracing::log::LevelFilter::Warn,
            VeilidConfigLogLevel::Info => tracing::log::LevelFilter::Info,
            VeilidConfigLogLevel::Debug => tracing::log::LevelFilter::Debug,
            VeilidConfigLogLevel::Trace => tracing::log::LevelFilter::Trace,
        }
    }
}

impl TryFrom<&str> for VeilidConfigLogLevel {
    type Error = VeilidAPIError;

    fn try_from(value: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
        Self::from_str(value)
    }
}

impl TryFrom<String> for VeilidConfigLogLevel {
    type Error = VeilidAPIError;

    fn try_from(value: String) -> Result<Self, <Self as TryFrom<String>>::Error> {
        Self::from_str(value.as_str())
    }
}

impl TryFrom<&String> for VeilidConfigLogLevel {
    type Error = VeilidAPIError;

    fn try_from(value: &String) -> Result<Self, <Self as TryFrom<&String>>::Error> {
        Self::from_str(value.as_str())
    }
}

impl FromStr for VeilidConfigLogLevel {
    type Err = VeilidAPIError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => {
                apibail_invalid_argument!("invalid VeilidConfigLogLevel string", "s", s);
            }
        })
    }
}
impl fmt::Display for VeilidConfigLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let text = match self {
            Self::Off => "Off",
            Self::Error => "Error",
            Self::Warn => "Warn",
            Self::Info => "Info",
            Self::Debug => "Debug",
            Self::Trace => "Trace",
        };
        write!(f, "{}", text)
    }
}

/// Internal "footgun" UDP configuration. See [VeilidConfigInternal].
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigInternalUDP {
    /// Number of UDP sockets in the send/receive pool (0 = automatic).
    pub socket_pool_size: u32,
}

/// Internal "footgun" per-protocol configuration. See [VeilidConfigInternal].
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigInternalProtocol {
    /// Internal UDP tuning.
    pub udp: VeilidConfigInternalUDP,
}

/// Internal "footgun" RPC configuration. See [VeilidConfigInternal].
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigInternalRPC {
    /// Number of concurrent RPC worker tasks (0 = automatic).
    pub concurrency: u32,
    /// Maximum number of queued RPC operations.
    pub queue_size: u32,
    /// Reject messages timestamped more than this many ms in the past (`None` = no limit).
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub max_timestamp_behind_ms: Option<u32>,
    /// Reject messages timestamped more than this many ms in the future (`None` = no limit).
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub max_timestamp_ahead_ms: Option<u32>,
    /// Timeout for an RPC round-trip, in milliseconds.
    pub timeout_ms: u32,
    /// Maximum number of hops allowed in a route.
    pub max_route_hop_count: u8,
}
impl Default for VeilidConfigInternalRPC {
    fn default() -> Self {
        Self {
            concurrency: 0,
            queue_size: 1024,
            max_timestamp_behind_ms: Some(10000),
            max_timestamp_ahead_ms: Some(10000),
            timeout_ms: 5000,
            max_route_hop_count: 4,
        }
    }
}

/// Internal "footgun" DHT configuration. See [VeilidConfigInternal].
/// Changing the count/fanout/timeout parameters may render your node inoperable for
/// correct DHT operations.
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigInternalDHT {
    /// Maximum number of nodes returned by a FindNode query.
    pub max_find_node_count: u32,
    /// Timeout for resolving a node, in milliseconds.
    pub resolve_node_timeout_ms: u32,
    /// Number of nodes sought when resolving a node.
    pub resolve_node_count: u32,
    /// Parallel fanout width when resolving a node.
    pub resolve_node_fanout: u32,
    /// Timeout for a GetValue operation, in milliseconds.
    pub get_value_timeout_ms: u32,
    /// Number of matching values sought for GetValue consensus.
    pub get_value_count: u32,
    /// Parallel fanout width for GetValue.
    pub get_value_fanout: u32,
    /// Timeout for a SetValue operation, in milliseconds.
    pub set_value_timeout_ms: u32,
    /// Number of nodes that must accept a SetValue for consensus.
    pub set_value_count: u32,
    /// Parallel fanout width for SetValue.
    pub set_value_fanout: u32,
    /// Maximum number of nodes considered 'close to a record key' for storing a record.
    pub consensus_width: u32,
    /// Minimum number of peers to keep in the routing table.
    pub min_peer_count: u32,
    /// Minimum interval between peer-refresh rounds, in milliseconds.
    pub min_peer_refresh_time_ms: u32,
    /// Time allowed to receive a dial-info validation receipt, in milliseconds.
    pub validate_dial_info_receipt_time_ms: u32,
    /// Maximum lifetime of a DHT watch, in milliseconds.
    pub max_watch_expiration_ms: u32,
    /// Longest interval between change inspections of a watch, in milliseconds: the interval
    /// doubles up to it while inspections find nothing. Half the watch lifetime by default, so a
    /// quiet watch inspects before each renewal; a watch short of consensus delivers changes at
    /// most this late.
    pub max_watch_inspect_interval_ms: u32,
    /// Maximum concurrent watches by anonymous watchers (signer not a schema member).
    pub public_watch_limit: u32,
    /// Reserved watch slots for watchers whose signer is a schema member of the record.
    pub member_watch_limit: u32,
    /// Maximum concurrent transactions by anonymous signers (not a schema member).
    pub public_transaction_limit: u32,
    /// Reserved transaction slots for signers who are schema members of the record.
    pub member_transaction_limit: u32,
}
impl Default for VeilidConfigInternalDHT {
    fn default() -> Self {
        Self {
            max_find_node_count: 20,
            resolve_node_timeout_ms: 10000,
            resolve_node_count: 1,
            resolve_node_fanout: 5,
            get_value_timeout_ms: 10000,
            get_value_count: 3,
            get_value_fanout: 5,
            set_value_timeout_ms: 10000,
            set_value_count: 5,
            set_value_fanout: 6,
            consensus_width: 10,
            min_peer_count: 20,
            min_peer_refresh_time_ms: 60000,
            validate_dial_info_receipt_time_ms: 1000,
            max_watch_expiration_ms: 600000,
            max_watch_inspect_interval_ms: 300000,
            public_watch_limit: 32,
            member_watch_limit: 8,
            public_transaction_limit: 8,
            member_transaction_limit: 4,
        }
    }
}

/// Internal "footgun" routing table save schedule. See [VeilidConfigInternal].
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigInternalRoutingTableSave {
    /// Quiet time after a change worth saving before the table is saved, in milliseconds.
    pub settle_ms: u32,
    /// Least time between saves driven by changes, in milliseconds.
    pub min_interval_ms: u32,
    /// Least time between saves in the background, where the process may be frozen within
    /// seconds, in milliseconds.
    pub background_min_interval_ms: u32,
    /// Longest the table goes unsaved, so changes too small to drive a save still reach disk,
    /// in milliseconds.
    pub period_ms: u32,
}
impl Default for VeilidConfigInternalRoutingTableSave {
    fn default() -> Self {
        Self {
            settle_ms: 5000,
            min_interval_ms: 10000,
            background_min_interval_ms: 5000,
            period_ms: 300000,
        }
    }
}

/// Internal "footgun" routing table configuration. See [VeilidConfigInternal].
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigInternalRoutingTable {
    /// When the routing table is saved.
    pub save: VeilidConfigInternalRoutingTableSave,
}

/// Internal "footgun" network configuration. See [VeilidConfigInternal].
#[apply(api_data_struct!)]
#[api(eq, ts)]
pub struct VeilidConfigInternalNetwork {
    /// Timeout to establish a new connection, in milliseconds.
    pub connection_initial_timeout_ms: u32,
    /// Cap on any single low-level send, in milliseconds, so a send on a wedged
    /// transport cannot consume the caller's whole RPC timeout budget.
    pub single_send_timeout_ms: u32,
    /// Idle time before an inactive connection is dropped, in milliseconds.
    pub connection_inactivity_timeout_ms: u32,
    /// Maximum simultaneous connections from a single IPv4 address.
    pub max_connections_per_ip4: u32,
    /// Maximum simultaneous connections from a single IPv6 prefix.
    pub max_connections_per_ip6_prefix: u32,
    /// IPv6 prefix length (bits) used to group connections for the per-prefix limit.
    pub max_connections_per_ip6_prefix_size: u32,
    /// Maximum new connections accepted per minute from one source.
    pub max_connection_frequency_per_min: u32,
    /// Time a client stays on the allowlist after connecting, in milliseconds.
    pub client_allowlist_timeout_ms: u32,
    /// Time allowed to receive a reverse-connection receipt, in milliseconds.
    pub reverse_connection_receipt_time_ms: u32,
    /// Time allowed to receive a hole-punch receipt, in milliseconds.
    pub hole_punch_receipt_time_ms: u32,
    /// TTL (hop limit) of a hole punch, enough to pass this node's NAT but not reach the peer's.
    pub default_hole_punch_ttl: u32,
    /// Hole punch TTL behind a carrier-grade NAT, which sits more hops out than a home router.
    pub cgnat_hole_punch_ttl: u32,
    /// NAT-detection retries during dial-info confirmation for port/address-restricted NAT
    /// (some NATs open to full-cone after a few attempts; off by default).
    pub restricted_nat_retries: u32,
    /// Internal RPC tuning.
    pub rpc: VeilidConfigInternalRPC,
    /// Internal DHT tuning.
    pub dht: VeilidConfigInternalDHT,
    /// Internal per-protocol tuning.
    pub protocol: VeilidConfigInternalProtocol,
    /// Internal routing table tuning.
    pub routing_table: VeilidConfigInternalRoutingTable,
}
impl Default for VeilidConfigInternalNetwork {
    fn default() -> Self {
        Self {
            connection_initial_timeout_ms: 5000,
            single_send_timeout_ms: 2000,
            connection_inactivity_timeout_ms: 60000,
            max_connections_per_ip4: 32,
            max_connections_per_ip6_prefix: 32,
            max_connections_per_ip6_prefix_size: 56,
            max_connection_frequency_per_min: 128,
            client_allowlist_timeout_ms: 300000,
            reverse_connection_receipt_time_ms: 5000,
            hole_punch_receipt_time_ms: 5000,
            default_hole_punch_ttl: 3,
            cgnat_hole_punch_ttl: 8,
            restricted_nat_retries: 0,
            rpc: VeilidConfigInternalRPC::default(),
            dht: VeilidConfigInternalDHT::default(),
            protocol: VeilidConfigInternalProtocol::default(),
            routing_table: VeilidConfigInternalRoutingTable::default(),
        }
    }
}

/// Internal "footgun" configuration tree, parallel to the main config.
///
/// These fields tune low-level network/DHT timing, fanout, consensus and connection limits.
/// Changing them from the defaults can render a node inoperable. They are only honored when
/// veilid-core is built with the `footgun-config` feature; without it, any non-default values
/// here are reset to defaults at startup (with a warning).
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfigInternal {
    /// Internal network tuning.
    pub network: VeilidConfigInternalNetwork,
}

/// Top level of the Veilid configuration tree
///
/// A section or field that exists only with a cargo feature takes its default when a config
/// leaves it out, and a core built without the feature ignores it, so one config serves every
/// build. Bindings model such sections as optional and leave them out when unset.
#[apply(api_data_struct!)]
#[api(eq, default, ts)]
pub struct VeilidConfig {
    /// An identifier used to describe the program using veilid-core.
    /// Used to partition storage locations in places like the ProtectedStore.
    /// Must be non-empty and a valid filename for all Veilid-capable systems, which means
    /// no backslashes or forward slashes in the name. Stick to a-z,0-9,_ and space and you should be fine.
    ///
    /// Caution: If you change this string, there is no migration support. Your app's protected store and
    /// table store will very likely experience data loss. Pick a program name and stick with it. This is
    /// not a 'visible' identifier and it should uniquely identify your application.
    pub program_name: String,
    /// To run multiple Veilid nodes within the same application, either through a single process running
    /// api_startup/api_startup_json multiple times, or your application running mulitple times side-by-side
    /// there needs to be a key used to partition the application's storage (in the TableStore, ProtectedStore, etc).
    /// An empty value here is the default, but if you run multiple veilid nodes concurrently, you should set this
    /// to a string that uniquely identifies this -instance- within the same 'program_name'.
    /// Must be a valid filename for all Veilid-capable systems, which means no backslashes or forward slashes
    /// in the name. Stick to a-z,0-9,_ and space and you should be fine.
    pub namespace: String,
    /// Capabilities to enable for your application/node
    pub capabilities: VeilidConfigCapabilities,
    /// Where the stores live and the disk budget for data held for other nodes
    #[serde(default)]
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub storage: VeilidConfigStorage,
    /// Configuring the protected store (keychain/keyring/etc)
    pub protected_store: VeilidConfigProtectedStore,
    /// Configuring the table store (persistent encrypted database)
    pub table_store: VeilidConfigTableStore,
    /// Configuring the block store (storage of large content-addressable content)
    pub block_store: VeilidConfigBlockStore,
    /// Configuring how Veilid interacts with the low level network
    pub network: VeilidConfigNetwork,
    /// Configuring how the node attaches to the network
    #[serde(default)]
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub attachment: VeilidConfigAttachment,
    /// Internal "footgun" tuning. `None` uses safe defaults. Only honored with the
    /// `footgun-config` feature; otherwise ignored (a warning is logged at startup).
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), tsify(optional))]
    pub internal: Option<VeilidConfigInternal>,
}

impl VeilidConfig {
    /// The effective internal config: configured values with the `footgun-config` feature,
    /// otherwise always the built-in defaults.
    pub fn internal(&self) -> &VeilidConfigInternal {
        static DEFAULT: std::sync::OnceLock<VeilidConfigInternal> = std::sync::OnceLock::new();
        let default = || DEFAULT.get_or_init(VeilidConfigInternal::default);
        #[cfg(feature = "footgun-config")]
        {
            self.internal.as_ref().unwrap_or_else(default)
        }
        #[cfg(not(feature = "footgun-config"))]
        {
            let _ = &self.internal;
            default()
        }
    }

    /// Create a new 'VeilidConfig' for use with `setup_from_config`
    /// Should match the application bundle name if used elsewhere in the format:
    /// `qualifier.organization.program_name` - for example `org.veilid.veilidchat`
    ///
    /// The 'bundle name' will be used when choosing the default storage location for the
    /// application in a platform-dependent fashion, unless 'storage_directory' is
    /// specified to override this location
    ///
    /// * `program_name` - Pick a program name and do not change it from release to release,
    ///   see `VeilidConfig::program_name` for details.
    /// * `organization_name` - Similar to program_name, but for the organization publishing this app
    /// * `qualifier` - Suffix for the application bundle name
    /// * `storage_directory` - Override for the path where veilid-core stores its content
    ///   such as the table store, protected store, and block store
    /// * `config_directory` - Override for the path where veilid-core can retrieve extra configuration files
    ///   such as certificates and keys
    pub fn new(
        program_name: &str,
        organization: &str,
        qualifier: &str,
        storage_directory: Option<&str>,
        config_directory: Option<&str>,
    ) -> Self {
        let mut out = Self {
            program_name: program_name.to_owned(),
            ..Default::default()
        };

        out.storage.directory = match storage_directory {
            Some(storage_directory) => storage_directory.to_owned(),
            None => get_default_storage_directory(program_name, organization, qualifier),
        };

        if let Some(config_directory) = config_directory {
            out.network.tls.certificate_path = (std::path::PathBuf::from(config_directory)
                .join("ssl/certs/server.crt"))
            .to_string_lossy()
            .to_string();
            out.network.tls.private_key_path = (std::path::PathBuf::from(config_directory)
                .join("ssl/keys/server.key"))
            .to_string_lossy()
            .to_string();
        } else {
            out.network.tls.certificate_path = get_default_ssl_directory(
                program_name,
                organization,
                qualifier,
                "certs/server.crt",
            );
            out.network.tls.private_key_path =
                get_default_ssl_directory(program_name, organization, qualifier, "keys/server.key");
        }

        out
    }

    /// Clone the config with secrets stripped (routing-table secret keys and encryption-key passwords), safe to log or serialize.
    #[must_use]
    pub fn safe(&self) -> Arc<VeilidConfig> {
        let mut safe_cfg = self.clone();

        // Remove secrets
        safe_cfg.network.routing_table.secret_keys = SecretKeyGroup::new();
        "".clone_into(&mut safe_cfg.protected_store.device_encryption_key_password);
        safe_cfg.protected_store.new_device_encryption_key_password = None;

        Arc::new(safe_cfg)
    }

    /// The table store's directory: its own, else `<storage.directory>/table_store`
    #[must_use]
    pub fn table_store_directory(&self) -> String {
        Self::store_directory(
            &self.table_store.directory,
            &self.storage.directory,
            "table_store",
        )
    }

    /// The block store's directory: its own, else `<storage.directory>/block_store`
    #[must_use]
    pub fn block_store_directory(&self) -> String {
        Self::store_directory(
            &self.block_store.directory,
            &self.storage.directory,
            "block_store",
        )
    }

    /// The protected store's directory: its own, else `<storage.directory>/protected_store`
    #[must_use]
    pub fn protected_store_directory(&self) -> String {
        Self::store_directory(
            &self.protected_store.directory,
            &self.storage.directory,
            "protected_store",
        )
    }

    fn store_directory(own: &str, base: &str, store: &str) -> String {
        if !own.is_empty() || base.is_empty() {
            return own.to_owned();
        }
        std::path::PathBuf::from(base)
            .join(store)
            .to_string_lossy()
            .into_owned()
    }

    /// The RPC reply timeout, the base most other durations derive from
    pub(crate) fn rpc_timeout(&self) -> TimestampDuration {
        TimestampDuration::new_ms(self.internal().network.rpc.timeout_ms.into())
    }

    /// Serialize the config, or the subtree at a dot-separated `key` path, to JSON. Empty `key` returns the whole config.
    pub fn get_key_json(&self, key: &str, pretty: bool) -> VeilidAPIResult<String> {
        // Generate json from whole config
        let jvc = serde_json::to_value(self).map_err(VeilidAPIError::generic)?;

        // Find requested subkey
        if key.is_empty() {
            Ok(if pretty {
                serde_json::to_string_pretty(&jvc).map_err(VeilidAPIError::generic)?
            } else {
                serde_json::to_string(&jvc).map_err(VeilidAPIError::generic)?
            })
        } else {
            // Split key into path parts
            let keypath: Vec<&str> = key.split('.').collect();
            let mut out = &jvc;
            for k in keypath {
                let Some(next_out) = out.get(k) else {
                    apibail_parse_error!(format!("invalid subkey in key '{}'", key), k);
                };
                out = next_out;
            }
            if pretty {
                serde_json::to_string_pretty(out).map_err(VeilidAPIError::generic)
            } else {
                serde_json::to_string(out).map_err(VeilidAPIError::generic)
            }
        }
    }

    // Rejects illegal/control chars, Windows-reserved names, trailing dot/space, len > 255
    fn is_valid_filename(s: &str) -> bool {
        if s.len() > 255 {
            return false;
        }
        if s.chars().any(|c| {
            matches!(c, '/' | '?' | '<' | '>' | '\\' | ':' | '*' | '|' | '"')
                || c <= '\u{1f}'
                || ('\u{80}'..='\u{9f}').contains(&c)
        }) {
            return false;
        }
        if !s.is_empty() && s.bytes().all(|b| b == b'.') {
            return false;
        }
        if s.ends_with('.') || s.ends_with(' ') {
            return false;
        }
        let base = s.split('.').next().unwrap_or_default().as_bytes();
        match base.len() {
            3 => {
                !(base.eq_ignore_ascii_case(b"con")
                    || base.eq_ignore_ascii_case(b"prn")
                    || base.eq_ignore_ascii_case(b"aux")
                    || base.eq_ignore_ascii_case(b"nul"))
            }
            4 => {
                !((base[..3].eq_ignore_ascii_case(b"com")
                    || base[..3].eq_ignore_ascii_case(b"lpt"))
                    && base[3].is_ascii_digit())
            }
            _ => true,
        }
    }

    fn validate_program_name(program_name: &str) -> VeilidAPIResult<()> {
        if program_name.is_empty() {
            apibail_generic!("Program name must not be empty in 'program_name'");
        }
        if !Self::is_valid_filename(program_name) {
            apibail_generic!("'program_name' must not be an invalid filename");
        }
        Ok(())
    }

    fn validate_namespace(namespace: &str) -> VeilidAPIResult<()> {
        if namespace.is_empty() {
            return Ok(());
        }
        if !Self::is_valid_filename(namespace) {
            apibail_generic!("'namespace' must not be an invalid filename");
        }

        Ok(())
    }

    /// The protocols enabled for outbound connections
    fn enabled_outbound_protocols(&self) -> OutboundProtocols {
        let protocol = &self.network.protocol;
        OutboundProtocols {
            udp: protocol.udp.enabled,
            tcp: protocol.tcp.connect,
            ws: protocol.ws.connect,
            #[cfg(feature = "enable-protocol-wss")]
            wss: protocol.wss.connect,
            #[cfg(not(feature = "enable-protocol-wss"))]
            wss: false,
            #[cfg(feature = "enable-protocol-webtransport")]
            webtransport: protocol.webtransport.connect,
            #[cfg(not(feature = "enable-protocol-webtransport"))]
            webtransport: false,
        }
    }

    /// The enabled outbound protocols this node can dial; in a browser, those its page allows
    pub(crate) fn outbound_protocols(&self) -> OutboundProtocols {
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                self.outbound_protocols_on(&PageContext::current())
            } else {
                self.enabled_outbound_protocols()
            }
        }
    }

    /// The protocols a node on this page dials: the enabled ones the page can use
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub(crate) fn outbound_protocols_on(&self, page: &PageContext) -> OutboundProtocols {
        let enabled = self.enabled_outbound_protocols();
        OutboundProtocols {
            udp: false,
            tcp: false,
            ws: enabled.ws && !page.https,
            webtransport: enabled.webtransport && page.webtransport,
            ..enabled
        }
    }

    /// Why a node on this page would reach no peer, if it would not
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub(crate) fn peer_reach_error_on(&self, page: &PageContext) -> Option<&'static str> {
        if self.outbound_protocols_on(page).dials_any_peer() {
            return None;
        }
        Some(if page.https {
            "a page served over https reaches peers only over WebTransport, which is off in 'network.protocol.webtransport.connect' or missing from this browser"
        } else if page.secure {
            "no protocol that reaches peers can be dialed from this page: enable 'network.protocol.ws.connect', or 'network.protocol.webtransport.connect' in a browser that has WebTransport"
        } else {
            "a page that is not a secure context reaches peers only over a clear websocket: enable 'network.protocol.ws.connect'"
        })
    }

    /// The configured bootstrap protocols this node can dial, in order
    pub(crate) fn dialable_bootstrap_protocols(&self) -> Vec<VeilidConfigBootstrapProtocol> {
        let dialable = self.outbound_protocols();
        let mut out = Vec::new();
        for bootstrap_protocol in &self.network.routing_table.bootstrap_protocols {
            if dialable.dials_bootstraps(*bootstrap_protocol) && !out.contains(bootstrap_protocol) {
                out.push(*bootstrap_protocol);
            }
        }
        out
    }

    /// A node must dial a protocol that reaches peers; a browser page narrows the choice
    fn validate_outbound_protocols(&self) -> VeilidAPIResult<()> {
        let enabled = self.enabled_outbound_protocols();
        if !enabled.dials_any_peer() {
            if enabled.wss {
                apibail_generic!(
                    "WSS is the only protocol enabled for outbound connections under 'network.protocol', and it reaches bootstraps but no other peer"
                );
            }
            apibail_generic!(
                "no protocol is enabled for outbound connections under 'network.protocol', so this node could reach no peer"
            );
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        if let Some(error) = self.peer_reach_error_on(&PageContext::current()) {
            apibail_generic!(error);
        }
        Ok(())
    }

    /// A node with bootstraps must be able to dial one of its `bootstrap_protocols`
    fn validate_bootstrap_protocols(&self) -> VeilidAPIResult<()> {
        let rt = &self.network.routing_table;
        let has_bootstraps = !rt.bootstrap.is_empty()
            || rt
                .bootstrap_records
                .iter()
                .any(|line| line.trim().starts_with("2|"));
        if !has_bootstraps {
            return Ok(());
        }
        if self.dialable_bootstrap_protocols().is_empty() {
            apibail_generic!(
                "no protocol in 'network.routing_table.bootstrap_protocols' can be dialed by this node, so it could not bootstrap"
            );
        }
        Ok(())
    }

    fn validate_max_connections(max_connections: u32, key: &str) -> VeilidAPIResult<()> {
        if !(MAX_CONNECTIONS_MIN..=MAX_CONNECTIONS_MAX).contains(&max_connections) {
            apibail_generic!(format!(
                "max connections must be in the range {}-{} in config key '{}'",
                MAX_CONNECTIONS_MIN, MAX_CONNECTIONS_MAX, key
            ));
        }
        Ok(())
    }

    /// Peers dial the advertised WebTransport URL after WHATWG normalization, so a configured
    /// path that normalization rewrites, or that overruns the listener's request path cap,
    /// would 404 against this node's own listener.
    #[cfg(feature = "enable-protocol-webtransport")]
    fn validate_webtransport_path(&self) -> VeilidAPIResult<()> {
        let request_path = format!(
            "/{}",
            self.network.protocol.webtransport.path.trim_matches('/')
        );
        let advertised = url::Url::parse(&format!("https://veilid.invalid{request_path}"))
            .map_err(|e| {
                VeilidAPIError::generic(format!(
                    "invalid 'network.protocol.webtransport.path': {e}"
                ))
            })?;
        if advertised.path() != request_path {
            apibail_generic!(format!(
                "'network.protocol.webtransport.path' is rewritten to '{}' by URL normalization and would not match this node's own advertised WebTransport URL",
                advertised.path()
            ));
        }
        if request_path.len() > MAX_WEBTRANSPORT_PATH_LENGTH {
            apibail_generic!(format!(
                "'network.protocol.webtransport.path' makes a request path longer than the {MAX_WEBTRANSPORT_PATH_LENGTH} byte WebTransport listener limit"
            ));
        }
        Ok(())
    }

    /// A dialing peer takes its CONNECT path from the advertised URL as the `url` crate parses
    /// it, so the configured path must match that round trip rather than a percent-decoding of
    /// the configured URL.
    #[cfg(feature = "enable-protocol-webtransport")]
    fn validate_webtransport_url(&self, url: &str) -> VeilidAPIResult<()> {
        SplitUrl::from_str(url).map_err(|e| {
            VeilidAPIError::generic(format!("invalid 'network.protocol.webtransport.url': {e}"))
        })?;
        let advertised = url::Url::parse(url).map_err(|e| {
            VeilidAPIError::generic(format!("invalid 'network.protocol.webtransport.url': {e}"))
        })?;
        let url_path = advertised.path().trim_matches('/');
        let configured_path = self.network.protocol.webtransport.path.trim_matches('/');
        if !url_path.is_empty() && url_path != configured_path {
            apibail_generic!(
                "WebTransport URL path in 'network.protocol.webtransport.url' must match 'network.protocol.webtransport.path'"
            );
        }
        Ok(())
    }

    /// Check the config for invalid or out-of-range values.
    pub fn validate(&self) -> VeilidAPIResult<()> {
        Self::validate_program_name(&self.program_name)?;
        Self::validate_namespace(&self.namespace)?;
        self.storage.validate()?;

        // Total connection cap across all protocols
        Self::validate_max_connections(self.network.max_connections, "network.max_connections")?;

        // if inner.network.protocol.udp.enabled {
        //     // Validate UDP settings
        // }
        #[cfg(feature = "enable-protocol-wss")]
        if self.network.protocol.wss.listen {
            // Validate WSS settings
            if self
                .network
                .protocol
                .wss
                .url
                .as_ref()
                .map(|u| u.is_empty())
                .unwrap_or_default()
            {
                apibail_generic!(
                    "WSS URL must be specified in config key 'network.protocol.wss.url'"
                );
            }
        }
        #[cfg(feature = "enable-protocol-webtransport")]
        if self.network.protocol.webtransport.listen {
            // WebTransport listens on its own QUIC socket when RawUDP is off, or shares the UDP
            // socket when it is on; either way its listen flag stands alone
            if self
                .network
                .protocol
                .webtransport
                .url
                .as_ref()
                .is_some_and(|u| !u.is_empty())
                && (self.network.tls.certificate_path.is_empty()
                    || self.network.tls.private_key_path.is_empty())
            {
                apibail_generic!(
                    "WebTransport CA-signed mode ('network.protocol.webtransport.url' is set) requires 'network.tls.certificate_path' and 'network.tls.private_key_path'"
                );
            }
            self.validate_webtransport_path()?;
            if let Some(url) = self
                .network
                .protocol
                .webtransport
                .url
                .as_ref()
                .filter(|u| !u.is_empty())
            {
                self.validate_webtransport_url(url)?;
            }
        }
        self.validate_outbound_protocols()?;
        self.validate_bootstrap_protocols()?;
        if self.internal().network.rpc.max_route_hop_count == 0 {
            apibail_generic!(
                "max route hop count must be >= 1 in 'network.rpc.max_route_hop_count'"
            );
        }
        if self.internal().network.rpc.max_route_hop_count > 5 {
            apibail_generic!(
                "max route hop count must be <= 5 in 'network.rpc.max_route_hop_count'"
            );
        }
        if self.network.rpc.default_route_hop_count == 0 {
            apibail_generic!(
                "default route hop count must be >= 1 in 'network.rpc.default_route_hop_count'"
            );
        }
        if self.network.rpc.default_route_hop_count
            > self.internal().network.rpc.max_route_hop_count
        {
            apibail_generic!(
                "default route hop count must be <= max route hop count in 'network.rpc.default_route_hop_count <= network.rpc.max_route_hop_count'"
            );
        }
        for (ttl, key) in [
            (
                self.internal().network.default_hole_punch_ttl,
                "network.default_hole_punch_ttl",
            ),
            (
                self.internal().network.cgnat_hole_punch_ttl,
                "network.cgnat_hole_punch_ttl",
            ),
        ] {
            if !(1..=255).contains(&ttl) {
                apibail_generic!("hole punch ttl must be from 1 to 255 in '{}'", key);
            }
        }
        if self.internal().network.rpc.queue_size < 256 {
            apibail_generic!("rpc queue size must be >= 256 in 'network.rpc.queue_size'");
        }
        if self.internal().network.rpc.timeout_ms < 1000 {
            apibail_generic!("rpc timeout must be >= 1000 in 'network.rpc.timeout_ms'");
        }
        if self.internal().network.dht.consensus_width < self.internal().network.dht.set_value_count
        {
            apibail_generic!(
                "consensus width must be >= set value count in 'network.dht.consensus_width'"
            );
        }
        if self.internal().network.dht.get_value_count
            <= (self.internal().network.dht.set_value_count / 2)
        {
            apibail_generic!("get consensus count must be >= (set value count / 2) in 'network.dht.get_value_count'");
        }
        if self.internal().network.dht.get_value_fanout < 1 {
            apibail_generic!("get value fanout must be >= 1 in 'network.dht.get_value_fanout'");
        }
        if self.internal().network.dht.set_value_fanout < 1 {
            apibail_generic!("set value fanout must be >= 1 in 'network.dht.set_value_fanout'");
        }
        if self.internal().network.dht.get_value_timeout_ms
            < (2 * self.internal().network.rpc.timeout_ms)
        {
            apibail_generic!("get value timeout must be >= (2 * the rpc timeout) in 'network.dht.get_value_timeout_ms'");
        }
        if self.internal().network.dht.set_value_timeout_ms
            < (2 * self.internal().network.rpc.timeout_ms)
        {
            apibail_generic!("set value timeout must be >= (2 * the rpc timeout) in 'network.dht.set_value_timeout_ms'");
        }

        if self.internal().network.dht.public_watch_limit < 1 {
            apibail_generic!("public watch limit must be >= 1 in 'network.dht.public_watch_limit'");
        }
        if self.internal().network.dht.member_watch_limit < 1 {
            apibail_generic!("member watch limit must be >= 1 in 'network.dht.member_watch_limit'");
        }
        if self.internal().network.dht.max_watch_expiration_ms
            < (2 * self.internal().network.rpc.timeout_ms)
        {
            apibail_generic!("max watch expiration must be >= (2 * rpc timeout) 'network.dht.max_watch_expiration_ms'");
        }
        if self.internal().network.dht.public_transaction_limit < 1 {
            apibail_generic!(
                "public transaction limit must be >= 1 in 'network.dht.public_transaction_limit'"
            );
        }
        if self.internal().network.dht.member_transaction_limit < 1 {
            apibail_generic!(
                "member transaction limit must be >= 1 in 'network.dht.member_transaction_limit'"
            );
        }

        Ok(())
    }

    /// Take the secrets a config from `get_state` lacks from `current`: blank
    /// `network.routing_table.secret_keys` or `protected_store` passwords keep the current values.
    pub fn fill_secrets_from(&mut self, current: &VeilidConfig) {
        if self.network.routing_table.secret_keys.is_empty() {
            self.network.routing_table.secret_keys =
                current.network.routing_table.secret_keys.clone();
        }
        if self
            .protected_store
            .device_encryption_key_password
            .is_empty()
        {
            self.protected_store.device_encryption_key_password = current
                .protected_store
                .device_encryption_key_password
                .clone();
        }
        if self
            .protected_store
            .new_device_encryption_key_password
            .is_none()
        {
            self.protected_store.new_device_encryption_key_password = current
                .protected_store
                .new_device_encryption_key_password
                .clone();
        }
    }

    /// Check that this config can replace `current` on a node that stays up: the keys a
    /// running node cannot take a new value for must be unchanged. Those are the storage
    /// identity (`program_name`, `namespace`, `storage.directory`, `protected_store`,
    /// `table_store`, `block_store`), the node identity (`network.routing_table.public_keys` and
    /// `secret_keys`), the network partition (`network.network_key_password`), the
    /// `network.dht` storage sizing and `internal`.
    ///
    /// Errors with [VeilidAPIError::InvalidArgument] naming the first such key that differs.
    pub fn ensure_changeable_from(&self, current: &VeilidConfig) -> VeilidAPIResult<()> {
        let fixed = [
            (self.program_name == current.program_name, "program_name"),
            (self.namespace == current.namespace, "namespace"),
            (
                self.storage.directory == current.storage.directory,
                "storage.directory",
            ),
            (
                self.protected_store == current.protected_store,
                "protected_store",
            ),
            (self.table_store == current.table_store, "table_store"),
            (self.block_store == current.block_store, "block_store"),
            (
                self.network.network_key_password == current.network.network_key_password,
                "network.network_key_password",
            ),
            (
                self.network.routing_table.public_keys == current.network.routing_table.public_keys,
                "network.routing_table.public_keys",
            ),
            (
                self.network.routing_table.secret_keys == current.network.routing_table.secret_keys,
                "network.routing_table.secret_keys",
            ),
            (self.network.dht == current.network.dht, "network.dht"),
            (self.internal == current.internal, "internal"),
        ];
        if let Some((_, key)) = fixed.iter().find(|(same, _)| !same) {
            apibail_invalid_argument!("change_config", key, "needs a restart to change");
        }
        Ok(())
    }
}

/// The configuration built for each Veilid node during API startup
#[derive(Clone)]
#[must_use]
pub struct VeilidStartupOptions {
    /// Where the node delivers its updates to the app
    update_cb: UpdateCallback,
    /// Shared by every clone, so a change reaches every component's `config()`
    config: Arc<ArcSwap<VeilidConfig>>,
}

impl fmt::Debug for VeilidStartupOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VeilidConfig")
            .field("config", &*self.config())
            .finish()
    }
}

impl VeilidStartupOptions {
    pub(crate) fn try_new(
        config: VeilidConfig,
        update_cb: UpdateCallback,
    ) -> VeilidAPIResult<Self> {
        config.validate()?;

        Ok(Self {
            update_cb,
            config: Arc::new(ArcSwap::from_pointee(config)),
        })
    }

    /// The callback invoked to deliver `VeilidUpdate` events to the application.
    #[must_use]
    pub fn update_callback(&self) -> UpdateCallback {
        self.update_cb.clone()
    }

    /// The validated configuration for this node, as it stands now.
    #[must_use]
    pub fn config(&self) -> Arc<VeilidConfig> {
        self.config.load_full()
    }

    /// Replace the configuration; the caller has validated it
    pub(crate) fn set_config(&self, config: VeilidConfig) {
        self.config.store(Arc::new(config));
    }
}

/// Return the default veilid config as a json object.
#[must_use]
pub fn default_veilid_config() -> String {
    serialize_json(VeilidConfig::default())
}
