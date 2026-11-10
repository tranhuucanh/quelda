// webpack 5 needs no quelda-specific configuration: it bundles the worker from
// `new Worker(new URL('./worker.js', import.meta.url))` and emits the .wasm
// from `new URL('quelda_bg.wasm', import.meta.url)` as an asset.
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

export default {
  mode: 'production',
  context: here,
  entry: './src/main.js',
  output: {
    path: resolve(here, 'dist'),
    filename: 'main.js',
    clean: true,
  },
};
