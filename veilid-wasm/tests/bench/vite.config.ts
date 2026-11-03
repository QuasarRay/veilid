import { defineConfig, searchForWorkspaceRoot } from 'vite';
import wasm from 'vite-plugin-wasm';
import { fileURLToPath } from 'node:url';

// The web-target wasm-bindgen package loads its `.wasm` by a URL relative to its own module, and
// `veilid-wasm` is a `file:../../pkg` dependency, so the asset resolves outside this app's root
// and has to be added to `server.fs.allow` below. It is resolved from this file rather than from
// the discovered workspace root, which moves with whichever lockfiles exist.
const pkgDir = fileURLToPath(new URL('../../pkg', import.meta.url));

export default defineConfig({
  plugins: [wasm()],
  server: {
    port: 5002,
    fs: {
      allow: [searchForWorkspaceRoot(process.cwd()), pkgDir],
    },
  },
});
