---
title: Veilid Server Configuration
keywords:
- config
- veilid-server
status: Draft
---
# Veilid Server Configuration

## Configuration File

`veilid-server` may be run using configuration from both command-line arguments
and the `veilid-server.conf` file.

## Global Directives

| Directive                    | Description                           |
| ---------------------------- | ------------------------------------- |
| [daemon](#daemon)            | Run `veilid-server` in the background |
| [client\_api](#client_api)   |                                       |
| [auto\_attach](#auto_attach) |                                       |
| [logging](#logging)          |                                       |
| [testing](#testing)          |                                       |
| [core](#core)                |                                       |


### daemon

```yaml
daemon:
    enabled: false
```

### client_api

```yaml
client_api:
    enabled: true
    listen_address: 'localhost:5959'
```

| Parameter                                    | Description |
| -------------------------------------------- | ----------- |
| [enabled](#client_apienabled)                |             |
| [listen\_address](#client_apilisten_address) |             |

#### client\_api:enabled

**TODO**

#### client\_api:listen\_address

**TODO**

### auto\_attach

```yaml
auto_attach: true
```

### logging

```yaml
logging:
    system:
        enabled: false
        level: 'info'
    terminal:
        enabled: true
        level: 'info'
    file:
        enabled: false
        path: ''
        append: true
        level: 'info'
    api:
        enabled: true
        level: 'info'
    otlp:
        enabled: false
        level: 'trace'
        grpc_endpoint: 'localhost:4317'
```

| Parameter                    | Description |
| ---------------------------- | ----------- |
| [system](#loggingsystem)     |             |
| [terminal](#loggingterminal) |             |
| [file](#loggingfile)         |             |
| [api](#loggingapi)           |             |
| [otlp](#loggingotlp)         |             |

#### logging:system

```yaml
system:
    enabled: false
    level: 'info'
```

#### logging:terminal

```yaml
terminal:
    enabled: true
    level: 'info'
```

#### logging:file

```yaml
file:
    enabled: false
    path: ''
    append: true
    level: 'info'
```

#### logging:api

```yaml
api:
    enabled: true
    level: 'info'
```

#### logging:otlp

```yaml
otlp:
    enabled: false
    level: 'trace'
    grpc_endpoint: 'localhost:4317'
```

### testing

```yaml
testing:
    subnode_index: 0
    subnode_count: 1
```

### core

| Parameter                                | Description |
| ---------------------------------------- | ----------- |
| [storage](#corestorage)                  | Where the stores live and how much disk they may use |
| [protected\_store](#coreprotected_store) |             |
| [table\_store](#coretable_store)         |             |
| [block\_store](#block_store)             |             |
| [network](#corenetwork)                  |             |

#### core:storage

```yaml
storage:
    directory: '%STORAGE_DIRECTORY%'
    limit_percent: null
    limit_mb: null
    minimum_mb: 0
```

| Parameter       | Description |
| --------------- | ----------- |
| `directory`     | Base directory for the stores. Defaults to `/var/db/veilid-server` where it exists, otherwise the platform's local data directory. A store whose own `directory` is empty uses `<directory>/<store>` (`table_store`, `block_store`, `protected_store`). The IPC directory does not follow it. |
| `limit_percent` | Share of each filesystem's free space, plus what the shared stores already use there, that the shared stores may use. 1 to 100. |
| `limit_mb`      | Total the shared stores may use across all filesystems, in MiB. |
| `minimum_mb`    | Size each shared store may always grow to, in MiB, whatever the free space allows. It may not exceed the MiB total in force. |

The shared stores hold data for other nodes: the remote DHT record store (when `network.dht.remote_max_storage_space_mb` is 0) and, later, the block store's remote cache (when `block_store.remote_max_storage_space_mb` is 0). With neither limit set, both defaults apply: 25% and 10240 MiB. Setting only one of them drops the other's default, and setting both applies both.

Each filesystem holding a shared store gets its own `limit_percent` budget, so a `table_store.directory` or `block_store.directory` on another disk is limited by that disk's free space. A store's own files count toward its filesystem's budget, so its growth never shrinks its limit. Each shared store may always grow to an equal share of every budget it draws on, and may borrow what the others leave unused. veilid-server measures free space once a second and adjusts the limits.

Store files do not shrink: freed space inside them is reused. A store at or over its limit keeps its records and replaces the least recently used ones instead of growing. At startup, veilid-server logs each store's directory, its size and its limit.

#### core:protected\_store

```yaml
protected_store:
    allow_insecure_fallback: true
    always_use_insecure_storage: true
    directory: ''
    delete: false
```

#### core:table\_store

```yaml
table_store:
    directory: ''
    delete: false
```

#### core:block\_store

```yaml
block_store:
    directory: ''
    delete: false
    remote_max_storage_space_mb: 0
```

#### core:network

```yaml
network:
    connection_initial_timeout_ms: 2000
    connection_inactivity_timeout_ms: 60000
    max_connections_per_ip4: 32
    max_connections_per_ip6_prefix: 32
    max_connections_per_ip6_prefix_size: 56
    max_connection_frequency_per_min: 128
    client_allowlist_timeout_ms: 300000
    reverse_connection_receipt_time_ms: 5000
    hole_punch_receipt_time_ms: 5000
    default_hole_punch_ttl: 3
    cgnat_hole_punch_ttl: 8
    network_key_password: null
    disable_capabilites: []
    public_keys: null
    secret_keys: null
    address_types: []
    upnp: true
    detect_address_changes: null
    bind_retry_ms: 10000
    enable_local_peer_scope: false
    restricted_nat_retries: 0
```

| Parameter                                   | Description |
| ------------------------------------------- | ----------- |
| detect\_address\_changes                    | `true` finds this node's public dial info by asking other nodes, `false` never does, and `null` does so only for an address family with no global address on an interface and no `public_address` (or `url`) configured for every listening protocol. A bootstrap, or any of the first nodes of a network, needs `null` with such addresses or `false`: there is no one to ask yet |
| [routing\_table](#corenetworkrouting_table) |             |
| [rpc](#corenetworkrpc)                      |             |
| [dht](#corenetworkdht)                      |             |
| [tls](#corenetworktls)                      |             |
| [application](#corenetworkapplication)      |             |
| [protocol](#corenetworkprotocol)            |             |

#### core:network:routing\_table

```yaml
routing_table:
    public_keys: null
    secret_keys: null
    bootstrap: ['bootstrap.veilid.net']
    bootstrap_protocols: ['WSS', 'WTS']
    bootstrap_keys: ['VLD0:Vj0lKDdUQXmQ5Ol1SZdlvXkBHUccBcQvGLN9vbLSI7k','VLD0:QeQJorqbXtC7v3OlynCZ_W3m76wGNeB5NTF81ypqHAo','VLD0:QNdcl-0OiFfYVj9331XVR6IqZ49NG-E18d5P7lwi4TA']
    bootstrap_records: []
    serve_direct_bootstrap: true
    limit_over_attached: 64
    limit_fully_attached: 32
    limit_attached_strong: 16
    limit_attached_good: 8
    limit_attached_weak: 4
```

A `bootstrap` entry is a dial info url, a bare `host`, or a `host:port` (port 5150 by default).
A bare host resolves to every A and AAAA address it names, and each address is dialed over
`bootstrap_protocols` in order. A host can also be an IP address (`203.0.113.5`, `2001:db8::1`,
`[2001:db8::1]:5150`), which is dialed with no lookup; over WSS and WebTransport the bootstrap
then needs a certificate for that address.

`bootstrap_protocols` lists the protocols a bootstrap request goes out on, in order of
preference, from `UDP`, `TCP`, `WS`, `WSS` and `WTS` (WebTransport). The default is the
encrypted pair, WSS first, because an insecure browser page can open WSS but not WebTransport.
A node with bootstraps configured and no protocol in this list it can dial, given
`network.protocol`, fails to start.

`bootstrap_records` holds bootstrap record lines, verbatim: the network's signed payload line
(`2|...`) as `veilid-server --sign-bootstrap-payload` prints it, and, for nodes running 0.5.x,
the legacy TXT lines as `veilid-server --dump-bootstrap-records` prints them. The payload names
nodes this node also joins from, beside its `bootstrap` entries, and a node that serves holds
it from startup and answers with it once it advertises `BOOT`; the legacy lines answer 0.5.x
nodes. Leaving the list empty (the default) means the payload comes from the bootstrap servers. [BOOTSTRAP-SETUP.md](../../BOOTSTRAP-SETUP.md) walks through producing both.

An older veilid-server logs a key it does not know and starts normally, so a config file
carrying these keys is still usable on an older node.

`serve_direct_bootstrap` makes the node answer bootstrap requests with the payload it holds
and its peers. The reply is large and the request is unauthenticated, so a node that is not a
bootstrap server should not serve; each sender is held to `max_connection_frequency_per_min`.
The server setting defaults to on, and the packaged `veilid-server.conf` sets it off, so a
bootstrap operator turns it on in the config file. A node that finds itself among its own
bootstraps answers whatever the setting says. Either way a node answers only while it is
directly reachable on every protocol it listens on and has no relay, which it advertises as
the `BOOT` capability.

#### core:network:rpc

```yaml
rpc:
    concurrency: 0
    queue_size: 1024
    max_timestamp_behind_ms: 10000
    max_timestamp_ahead_ms: 10000
    timeout_ms: 5000
    max_route_hop_count: 4
    default_route_hop_count: 1
```

#### core:network:dht

```yaml
dht:
    max_find_node_count: 20
    resolve_node_timeout_ms: 10000
    resolve_node_count: 1
    resolve_node_fanout: 4
    get_value_timeout_ms: 10000
    get_value_count: 3
    get_value_fanout: 4
    set_value_timeout_ms: 10000
    set_value_count: 5
    set_value_fanout: 4
    consensus_width: 10
    min_peer_count: 20
    min_peer_refresh_time_ms: 60000
    validate_dial_info_receipt_time_ms: 2000
    local_subkey_cache_size: 128
    local_max_subkey_cache_memory_mb: 256
    remote_subkey_cache_size: 1024
    remote_max_records: 65536
    remote_max_subkey_cache_memory_mb: %REMOTE_MAX_SUBKEY_CACHE_MEMORY_MB%
    remote_max_storage_space_mb: 0
    public_watch_limit: 32
    member_watch_limit: 8
    max_watch_expiration_ms: 600000
```

#### core:network:tls

```yaml
tls:
    certificate_path: '%CERTIFICATE_PATH%'
    private_key_path: '%PRIVATE_KEY_PATH%'
    connection_initial_timeout_ms: 2000
```

WSS and CA-signed WebTransport serve this certificate to a client that dials the node by name. A client that dials by IP literal is served the `ipv4` or `ipv6` certificate beside it, when one is present (the file naming is under [core:network:protocol:webtransport](#corenetworkprotocolwebtransport)). The node re-reads all of these files when they change, so a renewed certificate is served without a restart.

#### core:network:application

```yaml
application:
    https:
        enabled: false
        listen_address: ':5150'
        path: 'app'
        # url: 'https://localhost:5150'
    http:
        enabled: false
        listen_address: ':5150'
        path: 'app'
        # url: 'http://localhost:5150'
```

#### core:network:protocol

```yaml
protocol:
    udp:
        enabled: true
        socket_pool_size: 0
        listen_address: ':5150'
        # public_address: ''
    tcp:
        connect: true
        listen: true
        max_connections: 32
        listen_address: ':5150'
        #'public_address: ''
    ws:
        connect: true
        listen: true
        max_connections: 16
        listen_address: ':5150'
        path: 'ws'
        # url: 'ws://localhost:5150/ws'
    wss:
        connect: true
        listen: false
        max_connections: 16
        listen_address: ':5150'
        path: 'ws'
        # url: ''
    webtransport:
        connect: true
        listen: true
        listen_address: ':5150'
        path: 'wt'
        # url: ''
```

WSS reaches a bootstrap and little else, because a node listens on WSS only with a CA-signed certificate. A node whose only outbound protocol is WSS fails to start.

#### core:network:protocol:webtransport

WebTransport (HTTP/3 over QUIC) supports both self-signed certificate mode (default) and CA-signed bootstrap mode.

Both inbound `listen` and outbound `connect` are on by default, and the `enable-protocol-webtransport` cargo feature is in the default feature set. A build without that feature carries no WebTransport. Set `listen: false` to dial WebTransport peers without accepting or advertising inbound WebTransport.

`listen_address` is parsed the same way as it is for the other protocols, and an empty value binds the default port. When it resolves to the same address/port as `udp.listen_address`, WebTransport shares the node's UDP socket via QUIC demultiplexing. When it resolves to a different address/port, or when `udp.enabled` is false, WebTransport gets a dedicated QUIC-only UDP socket. Hole punching (NAT traversal) works through either kind of socket.

The `path` parameter sets the URL path for the WebTransport endpoint (default `'wt'`). Self-signed dial-info URLs are advertised as `https://{address}:{port}/wt`. Inbound sessions requesting a different path are rejected with 404.

In CA-signed mode (when `url` is set), the listener serves the CA certificate from `network.tls` instead of self-signed certificates, and advertises the provided URL. If the URL has no path component, the configured `path` is appended. If it has a path component, it must match `path`.

In CA-signed mode a node can also advertise its dial info by IP literal (`https://{ip}:{port}/{path}`). This lets a peer that already learned this node dial the IP directly instead of re-resolving the hostname, which frequently resolves to a UDP-blackholed IPv6 address. It is enabled by convention rather than a config field. Drop a per-family IP-SAN certificate next to the configured `network.tls` certificate, named `ipv4` / `ipv6` with the same directory and extension. For example, if `network.tls.certificate_path` is `/etc/veilid-server/ssl/certs/server.crt`, the siblings are `/etc/veilid-server/ssl/certs/ipv4.crt` and `/etc/veilid-server/ssl/certs/ipv6.crt`, with matching `ipv4`/`ipv6` keys next to `network.tls.private_key_path`. A family is advertised by IP literal only when its sibling certificate is present and readable. When neither family's sibling is present, the node logs at info level and advertises the configured hostname URL instead. An IP-SAN certificate does not follow DHCP renewal, host migration, or multihoming, so a node whose advertised IP can change should either keep these certificates current or omit them and fall back to hostname advertisement.
