// Loading quelda straight from a CDN (jsDelivr, unpkg, your own static host on
// another origin): browsers refuse `new Worker(url)` for a cross-origin url,
// so the worker starts from a same-origin blob that imports the real one.
// Bundled builds (Vite, webpack, …) serve the worker from the page's origin
// and never take this path.

/**
 * The source of the blob worker to use when this module was loaded from
 * `moduleUrl`, another http(s) origin than the page at `pageHref`; else
 * `undefined` (start the worker from its own URL).
 */
export function crossOriginWorkerSource(moduleUrl: string, pageHref: string | undefined): string | undefined {
  if (pageHref === undefined) return undefined;
  let module: URL;
  let page: URL;
  try {
    module = new URL(moduleUrl);
    page = new URL(pageHref);
  } catch {
    return undefined;
  }
  if (module.protocol !== 'http:' && module.protocol !== 'https:') return undefined;
  if (module.origin === page.origin) return undefined;
  const worker = new URL('worker.js', module).href;
  return `import ${JSON.stringify(worker)};\n`;
}
