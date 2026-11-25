# Creating a Veilid Bootstrap Server

A bootstrap server is a node that other nodes join the network from. One payload, signed by
the bootstrap operator, lists every bootstrap node's ids and dial infos. Every bootstrap holds
that same payload in its `bootstrap_records` and answers bootstrap requests with it and with its
own peers. While it can answer, it advertises the `BOOT` capability.

A joining node dials a bootstrap over the protocols in its `bootstrap_protocols` (WSS, then
WebTransport, by default), asks for the payload, checks its signature against the node's
`bootstrap_keys`, and connects to the payload's nodes. A network with no signing key
(`bootstrap_keys: []` on every node) runs on an unsigned payload: any node can bootstrap from
it, but nothing tells a node which network it reached, since DNS is open to tampering. Sign
the payload.

## Instance Recommended Setup

CPU: Single<br>
RAM: 1GB<br>
Storage: 25GB<br>
IP: Static v4 & v6<br>
Firewall: 5150/TCP/UDP inbound allow all<br>
TLS: a certificate from a CA browsers trust<br>

A bootstrap answers bootstrap requests once it has published its own node info with a direct
address for every protocol it listens on and no relay. With its
public IPv4 and IPv6 addresses on its own interfaces it confirms them at startup and publishes
by itself, as the first bootstrap of a new network must. A host whose public addresses are
translated elsewhere waits for other nodes to validate them, so give it static addresses
instead (`public_address` per protocol, `network.detect_address_changes: false`).

Clients dial a bootstrap by name over WSS and WebTransport, and the payload carries the
bootstrap's WebTransport dial infos without the rotating certificate hashes a self-signed
listener would need, so a bootstrap runs WebTransport in CA-signed mode: `network.tls` names
the certificate and `network.protocol.webtransport.url` names the host. The certificate must
cover the per-host name (`bootstrap-1.<your.domain>`) and the shared round-robin name clients
dial (`bootstrap.<your.domain>`). Per-family IP certificates beside it cover the host's IP
literals, so a client can list a bootstrap by address and bootstrap without any DNS lookup,
over WSS or WebTransport. See "CA-signed mode" under
[core:network:protocol:webtransport](./doc/config/veilid-server-config.md#corenetworkprotocolwebtransport)
for their file names. veilid-server re-reads the certificate files when they change, so a
renewal needs no restart.

Browsers do not accept every IP literal over WebTransport. Chrome rejects the certificate of
a session to an IPv6 literal, and Safari rejects the one of a session to an IPv4 literal on a
network that reaches IPv4 through NAT64, as IPv6-only mobile carriers do. WSS by address works
in both, and so does either protocol by name, so a browser app lists its bootstraps by name.

## Install Veilid

Follow instructions in [INSTALL.md](./INSTALL.md)

## Configure Veilid as Bootstrap

### Stop the Veilid service

```shell
sudo systemctl stop veilid-server.service
```

### Create a bootstrap signing key

The bootstrap signing key signs the network's payload; one key serves every bootstrap on the
network. If you don't have one yet, with `veilid-server` not already running:

```shell
sudo -u veilid veilid-server --generate-key-pairs=VLD0
```

which outputs a key in this form (example: `VLD0:NAPctwUP5NNynWdkX8rcUz_yk44v-cHuDM9ZzvsDXnQ:-ncghvgw2NFQK2RH2vCfvCJj3M3gTVOD-UM08-7n6kQ`):

```
VLD0:PUBLIC_KEY:SECRET_KEY
```

Copy down the generated keypair and store it in a secure location, preferably offline.
Remove the part after the second colon (the SECRET_KEY), and this is your 'Bootstrap Signing
Public Key' (should look like: `VLD0:NAPctwUP5NNynWdkX8rcUz_yk44v-cHuDM9ZzvsDXnQ`)

### Setup the config

In `/etc/veilid-server/veilid-server.conf`, under `core: network:`:

```yaml
    routing_table:
      bootstrap: ['bootstrap.<your.domain>']
      bootstrap_protocols: ['WSS', 'WTS']
      bootstrap_keys: ['VLD0:<your bootstrap signing public key>']
      bootstrap_records: []
      serve_direct_bootstrap: true
    tls:
      certificate_path: '/etc/veilid-server/ssl/certs/server.crt'
      private_key_path: '/etc/veilid-server/ssl/keys/server.key'
    protocol:
      wss:
        listen: true
        url: 'wss://bootstrap-1.<your.domain>:5150/ws'
      webtransport:
        url: 'https://bootstrap-1.<your.domain>:5150/wt'
```

- `bootstrap`: a bare host resolves to every A and AAAA record it has, each dialed on port
  5150. `host:port` and dial info urls (`wss://bootstrap.<your.domain>:5150/ws`) also work,
  and so does an IP address, which is dialed with no DNS lookup.
- `bootstrap_protocols`: the protocols a bootstrap request goes out on, in order. The value
  above is the default. A node whose list has no protocol it can dial fails to start.
- `bootstrap_keys`: the signing public keys this node trusts. If this is a bootstrap for the
  main Veilid network, include Veilid Foundation's signing keys as well:
  `['VLD0:<your bootstrap signing public key>', 'VLD0:Vj0lKDdUQXmQ5Ol1SZdlvXkBHUccBcQvGLN9vbLSI7k', 'VLD0:QeQJorqbXtC7v3OlynCZ_W3m76wGNeB5NTF81ypqHAo', 'VLD0:QNdcl-0OiFfYVj9331XVR6IqZ49NG-E18d5P7lwi4TA']`.
  An unsigned network uses `[]`.
- `bootstrap_records`: filled in below, once the payload is signed.
- `serve_direct_bootstrap`: the packaged `veilid-server.conf` turns serving off, since a node
  that is not a bootstrap has no reason to answer unauthenticated requests with its peer set.
  A node that finds itself among its own bootstraps answers regardless. Either way a node
  answers only while it is directly reachable on every protocol it listens on and has no
  relay, which is when it advertises the `BOOT` capability.
- `wss.url` and `webtransport.url`: the per-host name, so the dial infos this node advertises
  and puts in its payload line validate against the certificate.

(If you came here from the [dev network setup](./dev-setup/dev-network-setup.md) guide, this is
when you set the network key as well in the `network_key_password` field of the `network:`
section)

**Switch to veilid user**

```shell
sudo -u veilid /bin/bash
```

### Set the node's keypair

Generate a keypair for the node and copy the output to secure storage such as a password
manager. It identifies the node in the payload, and lets you recover the node or move it to a
different server.

```shell
veilid-server --generate-key-pairs=VLD0
```

Set it and flush the routing table. The keypair is requested interactively and does not echo
when pasted; an empty line finishes.

```shell
veilid-server --set-key-pairs --delete-table-store
```

### Print this node's bootstrap record lines

```shell
veilid-server --dump-bootstrap-records
```

The signing keypair is requested on stdin (one per crypto kind, no echo, an empty line
finishes). The node starts, waits for its public dial info, prints its records and exits:

- `V0:` and `V1 (VLD0):` lines, the legacy TXT records for
  [nodes running 0.5.x](#for-nodes-running-05x-txt-records). Without a signing keypair only
  the V0 line is printed.
- `V2 node:` followed by `node|<base64>`, this node's ids and dial infos for the payload.

Keep the `node|...` line. Collect one from every bootstrap server, then sign the payload once.

### Sign the payload

Once per network, on a machine holding the signing key:

```shell
veilid-server --sign-bootstrap-payload --bootstrap-record-lifetime none 'node|...' 'node|...'
```

Each argument is a node line or `@<file>` naming a file of node lines, one per line. The
signing keypair is requested on stdin; with none the payload is unsigned, which only a network
with `bootstrap_keys: []` accepts. The command prints the payload line:

```
2|<base64>
```

- `--bootstrap-record-lifetime` is required: `none` or `0` for a payload that never expires,
  or `1y`, `6mo`, `30d` (combinable; a year is 365 days and a month 30). Nodes stop serving
  a payload at its expiration, so a lifetime makes the network depend on someone re-signing
  in time; with `none` the payload is re-signed only when the bootstrap set changes.
- `--bootstrap-cache-ttl-hours` (default 24) is advisory: a serving node that learned the
  payload re-checks its source on the first bootstrap request after that long, after a random
  delay of up to half of it. A node that answers bootstrap requests while holding no payload,
  or an expired one, asks its bootstraps for one when a request arrives, at most once in that
  time.

### Paste the payload line into every bootstrap

In `routing_table:` on every bootstrap server:

- `bootstrap_records: ['2|<the payload line, exactly as printed>']`

A bootstrap holds the payload from its config as soon as it starts and serves it once it has
published its node info, and joins the network from the payload's nodes without resolving
`bootstrap`. A node with an empty
`bootstrap_records` learns the payload from the bootstraps. A newer payload replaces an older
one wherever it arrives, so adding or replacing a bootstrap means a new node line, a new
signing, and a paste into every bootstrap.

### Start the Veilid service

Disconnect from the Veilid user and start veilid-server.service.

```shell
exit
```

```shell
sudo systemctl start veilid-server.service
```

Optionally configure the service to start at boot `sudo systemctl enable veilid-server.service`

Check that it serves: `veilid-cli -e 'peerinfo'` shows the published node info with `BOOT`
among its capabilities, and `veilid-cli -e 'dialinfo'` shows a `Bootstrap Payload: signed ...`
line.

_REPEAT FOR EACH BOOTSTRAP SERVER_

## Enter DNS Records

Create the following DNS records for your domain:

(This example assumes two bootstrap servers are being created)

| Record      | Value               | Record Type |
| ----------- | ------------------- | ----------- |
| bootstrap   | IPv4 of bootstrap 1 | A           |
| bootstrap   | IPv4 of bootstrap 2 | A           |
| bootstrap   | IPv6 of bootstrap 1 | AAAA        |
| bootstrap   | IPv6 of bootstrap 2 | AAAA        |
| bootstrap-1 | IPv4 of bootstrap 1 | A           |
| bootstrap-1 | IPv6 of bootstrap 1 | AAAA        |
| bootstrap-2 | IPv4 of bootstrap 2 | A           |
| bootstrap-2 | IPv6 of bootstrap 2 | AAAA        |

The round-robin name is what clients put in `bootstrap`; the per-host names are what each
certificate and `wss.url` and `webtransport.url` carry. Give each bootstrap address a PTR
record pointing at its per-host name; `--dump-bootstrap-records` names the legacy lines by it
when `--bootstrap-hostname` is not given.

## For nodes running 0.5.x (TXT records)

Nodes of the previous version bootstrap from DNS TXT records and `BOOT`/`B01T` requests, and
never see the payload. A 0.6.0 bootstrap keeps answering them while it is built with
`enable-bootstrap-v0` and `enable-bootstrap-v1` (both on by default) and holds their record
lines:

1. Print the legacy lines on each bootstrap with the signing keypair on stdin:

   ```shell
   veilid-server --dump-bootstrap-records --bootstrap-hostname bootstrap-1.<your.domain>
   ```

   A legacy line names its host once, so the tool reverse-looks-up (PTR) each of the node's
   public addresses and uses `--bootstrap-hostname` when given (a PTR that disagrees is a
   warning), else the one name every PTR agrees on, else the IP literal when the node has a
   single address.
2. Paste the `V0` and `V1` lines into `bootstrap_records` beside the payload line, so the
   bootstrap answers 0.5.x nodes that ask it directly. A 0.5.x node without a TXT resolver
   (Android below API 29) resolves only A and AAAA records and contacts each address on port
   5150 over UDP or TCP, so every bootstrap server listens on 5150 for at least one of them.
3. Publish the lines as TXT records at the names 0.5.x nodes have in their `bootstrap`
   setting (the Veilid network's 0.5.x nodes use `bootstrap-v1`, its 0.6.0 nodes `bootstrap`):

   V1:
   | Record       | Value                        | Record Type |
   | ------------ | ---------------------------- | ----------- |
   | bootstrap-v1 | IPv4 of bootstrap 1          | A           |
   | bootstrap-v1 | IPv4 of bootstrap 2          | A           |
   | bootstrap-v1 | IPv6 of bootstrap 1          | AAAA        |
   | bootstrap-v1 | IPv6 of bootstrap 2          | AAAA        |
   | bootstrap-v1 | TXTRecord v0 for bootstrap 1 | TXT         |
   | bootstrap-v1 | TXTRecord v1 for bootstrap 1 | TXT         |
   | bootstrap-v1 | TXTRecord v0 for bootstrap 2 | TXT         |
   | bootstrap-v1 | TXTRecord v1 for bootstrap 2 | TXT         |

   V0:
   | Record      | Value                        | Record Type |
   | ----------- | ---------------------------- | ----------- |
   | bootstrap   | 1,2                          | TXT         |
   | 1.bootstrap | IPv4                         | A           |
   | 1.bootstrap | IPv6                         | AAAA        |
   | 1.bootstrap | TXTRecord v0 for bootstrap 1 | TXT         |
   | 2.bootstrap | IPv4                         | A           |
   | 2.bootstrap | IPv6                         | AAAA        |
   | 2.bootstrap | TXTRecord v0 for bootstrap 2 | TXT         |

The JSON replies a 0.6.0 bootstrap sends to 0.5.x nodes carry UDP, TCP and WS dial infos only:
a 0.5.x node fails the whole reply on a kind it was not built with, and WSS is an optional
feature there. A 0.5.8 node takes the bootstrap's other dial infos from the signed peer info in
the same reply. 0.5.x nodes reach a bootstrap over UDP, TCP, WS or WSS.
