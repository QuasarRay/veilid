import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';
export default defineConfig({
  plugins: [wasm()],
  // Module workers need their own plugin pipeline to resolve the bundler-target wasm import.
  worker: {
    format: 'es',
    plugins: () => [wasm()],
  },
  // Preserve the relative worker/wasm paths of the file: veilid-wasm dep.
  optimizeDeps: {
    exclude: ['veilid-wasm'],
  },
});
