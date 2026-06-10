// CLI executor for renderDom: runs the render bundle inside a real isolated-vm
// isolate. True isolation — the page's untrusted JS gets web-global polyfills and
// a floor-dropping fetch, and cannot reach the host's fetch/process/fs. A fresh
// context per page prevents cross-page contamination; the heavy bundles are
// compiled once.
import { resolve } from "node:path";
import ivm from "isolated-vm";
import { build } from "esbuild";
import type { RenderInput, RenderResult } from "../../src/render";

const HERE = import.meta.dirname;
const PUNYCODE = resolve(HERE, "../../node_modules/punycode/punycode.es6.js");
const CALL_TIMEOUT_MS = 6000;

let ready: Promise<{ isolate: ivm.Isolate; poly: ivm.Script; render: ivm.Script }> | null = null;

async function bundleOnce(entry: string): Promise<string> {
  const result = await build({
    entryPoints: [resolve(HERE, entry)],
    bundle: true,
    format: "iife",
    platform: "node",
    treeShaking: false, // keep polyfill side-effects (sideEffects:false would drop them)
    alias: { punycode: PUNYCODE },
    write: false
  });
  return result.outputFiles[0].text;
}

async function init() {
  if (!ready) {
    ready = (async () => {
      const [polyCode, renderCode] = await Promise.all([bundleOnce("polyfills.ts"), bundleOnce("entry.ts")]);
      const isolate = new ivm.Isolate({ memoryLimit: 256 });
      const poly = await isolate.compileScript(polyCode);
      const render = await isolate.compileScript(renderCode);
      return { isolate, poly, render };
    })();
  }
  return ready;
}

export async function renderInIsolate(input: RenderInput): Promise<RenderResult> {
  const { isolate, poly, render } = await init();
  const context = await isolate.createContext();
  try {
    await context.global.set("globalThis", context.global.derefInto());
    // self/window must exist before the polyfill bundle (fast-text-encoding
    // detects them), and polyfills must run before the render bundle (linkedom's
    // entity decoder reads atob/Buffer at module init).
    await context.eval("globalThis.self = globalThis; globalThis.window = globalThis;");
    await poly.run(context);
    await render.run(context);
    const out = await context.evalClosure(
      "return JSON.stringify(globalThis.__renderAndScan($0))",
      [input],
      { arguments: { copy: true }, result: { copy: true }, timeout: CALL_TIMEOUT_MS }
    );
    return JSON.parse(out as string) as RenderResult;
  } finally {
    context.release();
  }
}
