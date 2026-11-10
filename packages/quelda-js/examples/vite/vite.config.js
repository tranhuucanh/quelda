import { defineConfig } from 'vite';

export default defineConfig({
  // Pre-bundling rewrites the package and breaks its
  // `new URL('./worker.js' | 'quelda_bg.wasm', import.meta.url)` in dev mode.
  optimizeDeps: { exclude: ['quelda'] },
  // The worker imports the wasm-bindgen glue as an ES module.
  worker: { format: 'es' },
});
