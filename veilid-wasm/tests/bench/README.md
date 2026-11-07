# Veilid WASM WebTransport Test Bench

A browser test bench that boots a WebTransport-only Veilid node and joins the staging
network. It shows that Veilid can run in a browser on a secure origin that cannot use
insecure `ws://`.

It is a standalone Vite app inside the wdio test project, run by hand: it renders the
node's state as it changes, where the harness's `../src/webtransport-network.test.ts`
asserts the same path headlessly. It has its own `package.json` and dependencies, so it
neither builds nor runs as part of a wdio run.

Because the browser has no UDP or TCP and this bench disables WebSocket
(`network.protocol.ws.connect = false`), the node's only transport is WebTransport:

- CA-signed WebTransport to the staging bootstrap (`wts://bootstrap-v1.staging.veilid.net:5150/`),
  validated against the browser's system roots. This works on a secure origin where a
  self-signed `wss://` to a bare IP would not.
- Self-signed, hash-pinned WebTransport to peers, via the WebTransport
  `serverCertificateHashes` option (the SHA-256 hashes carried in each peer's dial info).

The page shows secure-context status, whether the WebTransport feature is compiled in,
whether the node bootstrapped over WebTransport, the attachment state, the selected
WebTransport relay, and public-internet readiness.

## Run

1. Build the wasm (writes `../../pkg`):

   ```
   npm run build:wasm
   ```

   (equivalently: `cd ../.. && ./wasm_build_js.sh release`)

2. Set the staging network's WebTransport bootstrap configuration as environment variables
   (there is no default, and the dev server will refuse to serve a working page without them):

   ```
   export VITE_NETWORK_KEY=...
   export VITE_BOOTSTRAP=wts://host1:port/,wts://host2:port/
   export VITE_BOOTSTRAP_KEYS=VLD0:...,VLD0:...
   ```

   `VITE_BOOTSTRAP` and `VITE_BOOTSTRAP_KEYS` are comma-separated lists. These must match the
   staging deploy's WebTransport bootstrap configuration
   (`deploy/staging/assets/veilid-server-server-staging.conf`). Vite only exposes env vars
   prefixed `VITE_` to the browser bundle; it reads them from the shell environment or from an
   `.env` file in this directory. `.env*` files are gitignored here, so an untracked
   `.env.local` is a convenient place to keep them across runs.

3. Install deps and start the dev server:

   ```
   npm install
   npm run dev
   ```

4. Open the served URL (default <http://localhost:5002>). `localhost` is a secure context,
   so WebTransport is available; to exercise a true HTTPS origin, serve the built output
   (`npm run build`) behind TLS.

## Notes

- Full `publicInternetReady` additionally requires background safety-route allocation,
  which needs a larger pool of route-capable nodes than the small staging fleet always
  provides; the WebTransport bootstrap/attach/relay path itself completes regardless.
