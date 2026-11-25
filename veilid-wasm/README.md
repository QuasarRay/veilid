# veilid-wasm

This package is a Rust cargo crate the generates WebAssembly (WASM) bindings for `veilid-core::VeilidAPI`, and outputs JavaScript and TypeScript interfaces for calling the WASM module.

## Limitations

Running Veilid in the browser via WebAssembly has some limitations:

### Browser-based limitations

1. TCP/UDP sockets are unavailable in the browser. This limits WASM nodes to communicating using WebSockets and WebTransport.
1. DNS lookups are unavailable in the browser, so the browser resolves a bootstrap's name itself when it opens the connection. A WASM node bootstraps over WSS and WebTransport (`network.routing_table.bootstrap_protocols`, WSS first by default) to the hosts or urls in `network.routing_table.bootstrap[]`, such as `bootstrap.veilid.net` or `wss://bootstrap.veilid.net:5150/ws`; a url over a protocol the page cannot use, such as `ws://` from an `https://` page, is skipped.
1. A browser node cannot listen, so it picks another node as its inbound relay, through which other nodes reach it.
1. The page decides which protocols reach other nodes:
   1. A page served over `https://` reaches them over WebTransport only, since the browser refuses it `ws://`. Startup fails there when `webtransport.connect` is off or the browser has no WebTransport.
   1. A page that is not a secure context (`http://` other than localhost) has no WebTransport and reaches them over `ws://`. The node logs that WebTransport is disabled, and startup fails when `ws.connect` is off.
   1. `wss://` reaches a bootstrap from any page, but other nodes listen on it only with a certificate from a Certificate Authority, so it does not count: a node with WSS as its only outbound protocol fails to start.

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
