import { defineConfig } from 'vite';
import { copyFileSync } from 'node:fs';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

// Chrome loads an unpacked extension straight from disk, so the background service worker must be
// a self-contained static bundle. Same MV3/service-worker constraints as vite.sw.config.ts.
export default defineConfig({
  plugins: [
    wasm(),
    topLevelAwait(),
    {
      name: 'copy-manifest',
      closeBundle() {
        copyFileSync('extension/manifest.json', 'extensionDist/manifest.json');
      },
    },
  ],
  optimizeDeps: { exclude: ['veilid-wasm'] },
  publicDir: false,
  build: {
    outDir: 'extensionDist',
    emptyOutDir: true,
    target: 'esnext',
    rollupOptions: {
      input: 'extension/background.ts',
      output: {
        format: 'es',
        entryFileNames: 'background.js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
});
