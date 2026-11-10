// Builds with webpack's Node API (no webpack-cli) and copies index.html.
import { copyFileSync } from 'node:fs';
import { join } from 'node:path';
import webpack from 'webpack';
import config from './webpack.config.js';

webpack(config, (err, stats) => {
  if (err || stats.hasErrors()) {
    console.error(err ?? stats.toString({ colors: false, all: false, errors: true }));
    process.exit(1);
  }
  copyFileSync(new URL('./index.html', import.meta.url), join(config.output.path, 'index.html'));
  console.log(stats.toString({ colors: false, assets: true, modules: false, chunks: false }));
});
