# veilid-wasm

This package is a Rust cargo crate the generates WebAssembly (WASM) bindings for `veilid-core::VeilidAPI`, and outputs JavaScript and TypeScript interfaces for calling the WASM module.

## Limitations

Running Veilid in the browser via WebAssembly has some limitations:

### Browser-based limitations

1. TCP/UDP sockets are unavailable in the browser. This limits WASM nodes to communicating using WebSockets and WebTransport.
1. DNS lookups are unavailable in the browser, so the browser resolves a bootstrap's name itself when it opens the connection. A WASM node bootstraps over WSS and WebTransport (`network.routing_table.bootstrap_protocols`, WSS first by default) to the hosts or urls in `network.routing_table.bootstrap[]`, such as `bootstrap-v1.veilid.net` or `wss://bootstrap-v1.veilid.net:5150/ws`; a `ws://` url works only from an `http://` page.
1. Do not set up any nodes with a core.network.protocol.wss.url IP address such as wss://12.34.56.78:5150/ws to support SSL. Even though a Certificate Authority (trusted by browsers) will give you an SSL certificate for an IP address, this is unsupported by Veilid as of v0.2.3. Any wss:// URL containing an IP address causes an RPC error in veilid-core and your node will lose communication with other nodes.
1. Since a WASM node running in the browser can't open ports, WASM nodes select another node to act as its Inbound Relay, so other nodes can react out to it and open a WS connection.
1. Because of browser security policy regarding WebSockets:
   1. `ws://` only works on `http://` sites
   1. `wss://` only works on `https://` site with SSL certificates.

### Running WASM on HTTPS sites [Not currently implemented]

Since WSS connections require WSS peers with valid SSL certificates, `veilid-core` plans to implement a feature called Outbound Relays. Outbound Relays will likely be hosted by the same host of the WASM web-app, and must run have valid SSL certificates that are signed by a Certificate Authority that's trusted by browsers. Outbound Relays will allow WASM nodes to communicate to other nodes over TCP/UDP/WS/WSS through the Outbound Relay's connection.

## Loading the package

This package exports a default `init()` function that instantiates the WebAssembly module, and callers must `await` it before using any other export:

```js
import init, { /* ...API... */ } from "veilid-wasm";

await init();          // instantiate the wasm; call once, before any other API
// ...the rest of the veilid-wasm API is now usable...
```

## Running unit tests

Prerequisites:

- NodeJS - ensure `node` and `npm` are installed.
- Firefox browser installed, and available as `firefox`.

Run the test script:

- `./wasm_test_js.sh` to test with debug symbols.
- `./wasm_test_js.sh release` to test against a release build.

## Development notes

### Important cargo crates and their functions

- [`wasm-bindgen`](https://rustwasm.github.io/wasm-bindgen/) is used to generate interop code between JavaScript and Rust, as well as basic TypeScript types.
- [`tsify`](https://github.com/madonoharu/tsify) is used to export TypeScript types in places where `wasm-bindgen` runs into limitations, or in places where you don't need the mappings that `wasm-bindgen` generates.
- [`serde-wasm-bindgen`](https://github.com/cloudflare/serde-wasm-bindgen) enables serialization/deserialization.
