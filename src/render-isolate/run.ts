// CLI executor for renderDom: runs the render bundle inside a real isolated-vm
// isolate. True isolation — the page's untrusted JS gets web-global polyfills and
// a floor-dropping fetch, and cannot reach the host's fetch/process/fs. A fresh
// context per page prevents cross-page contamination; the heavy bundles are
// compiled once.
//
// `isolated-vm` and `esbuild` are optionalDependencies: a base install can still
// run the static scan/crawl. They are loaded lazily here so the package imports
// cleanly without them; if absent, renderInIsolate throws and the caller
// (cli.ts) skips dynamic rendering for that page.
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { RenderInput, RenderResult } from "../render.js";

const HERE = import.meta.dirname;
const CALL_TIMEOUT_MS = 6000;

// Punycode lives in a transitive (linkedom/whatwg-url); resolve it through the
// module graph so it works whether or not node_modules is hoisted.
const require = createRequire(import.meta.url);
const PUNYCODE = require.resolve("punycode/punycode.es6.js");

// Sibling bundle entry: `.js` once compiled into dist/, `.ts` when run from
// source via tsx. esbuild bundles either.
function entryPath(base: string): string {
  const js = resolve(HERE, `${base}.js`);
  return existsSync(js) ? js : resolve(HERE, `${base}.ts`);
}

let depsWarned = false;
async function loadDeps(): Promise<{ ivm: any; build: any }> {
  try {
    const [ivmMod, esbuildMod] = await Promise.all([import("isolated-vm"), import("esbuild")]);
    return { ivm: ivmMod.default ?? ivmMod, build: (esbuildMod as any).build };
  } catch (error) {
    if (!depsWarned) {
      depsWarned = true;
      console.error(
        "signal-scanner: dynamic rendering is disabled — install the optional " +
          "dependencies `isolated-vm` and `esbuild` to enable it. Static analysis continues."
      );
    }
    throw error instanceof Error ? error : new Error(String(error));
  }
}

// Typed as `any` so the build does not hard-depend on the optional deps' types.
let ready: Promise<{ isolate: any; poly: any; render: any }> | null = null;

async function bundleOnce(build: any, base: string): Promise<string> {
  const result = await build({
    entryPoints: [entryPath(base)],
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
      const { ivm, build } = await loadDeps();
      const [polyCode, renderCode] = await Promise.all([bundleOnce(build, "polyfills"), bundleOnce(build, "entry")]);
      const isolate = new ivm.Isolate({ memoryLimit: 256 });
      const poly = await isolate.compileScript(polyCode);
      const render = await isolate.compileScript(renderCode);
      return { isolate, poly, render };
    })();
    // A failed init must not poison every later call (e.g. transient bundle error).
    ready.catch(() => { ready = null; });
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
