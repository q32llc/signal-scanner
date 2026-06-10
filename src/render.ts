// Render-and-scan: build a REAL DOM (linkedom), run the page's inline AND
// external scripts against it with our behavioral surfaces instrumented, then
// hand back the rendered HTML (to re-scan with the static rules) plus a
// BehaviorReport (exfil endpoints, runtime redirects, eval'd code, surfaced
// URLs). This closes the gap where a credential form is injected by an external
// JS bundle — invisible to inline-only analysis.
//
// linkedom replaces only the DOM; the instrumentation (fetch/XHR/sendBeacon/
// location/eval/Function/atob/cookie) is layered ON the linkedom window so both
// `fetch(...)` and `window.fetch(...)`/`window.location.href=` are recorded.
//
// linkedom + new Function run in any JS isolate (Node + workerd). For UNTRUSTED
// pages the caller supplies a `run` that executes in a real sandbox (node:vm with
// a timeout in the CLI; a globalOutbound:null Dynamic Worker in the Worker). The
// default in-process runner is for trusted/synthetic use (tests).

import { parseHTML } from "linkedom";
import { extractInlineScripts, extractScriptSources, type BehaviorReport, type NetworkAttempt } from "./dynamic";

const MAX_EXTERNAL_SCRIPTS = 8;
const MAX_SCRIPT_BYTES = 512 * 1024;

/** Self-contained input for the in-isolate core: HTML + already-fetched external script bodies. */
export interface RenderInput {
  html: string;
  url?: string;
  externalScripts?: string[];
}

/** Runs renderDom — in-process by default, or inside an isolate (isolated-vm / Dynamic Worker). */
export type RenderInvoke = (input: RenderInput) => RenderResult | Promise<RenderResult>;

export interface RenderOptions {
  url?: string;
  /** Fetch an external script body (caller provides IO + egress). Omit to skip externals. */
  fetchScript?: (absoluteUrl: string) => Promise<string | null>;
  /** Where renderDom runs (caller's isolate). Default: in-process (trusted/synthetic use only). */
  invoke?: RenderInvoke;
  maxExternalScripts?: number;
}

export interface RenderResult {
  /** Serialized DOM after scripts ran — feed this to the static scanner. */
  html: string;
  /** Behaviors recorded while scripts ran. */
  report: BehaviorReport;
}

function emptyReport(): BehaviorReport {
  return { redirects: [], network: [], writes: [], evals: [], decoded: [], cookies: [], errors: [] };
}

// Host orchestrator: pre-fetch external scripts (IO stays on the host — the
// isolate has no network), then run the pure renderDom core inside the caller's
// isolate (or in-process by default).
export async function renderAndScan(html: string, options: RenderOptions = {}): Promise<RenderResult> {
  let externalScripts: string[] = [];
  if (options.fetchScript) {
    const sources = extractScriptSources(html).slice(0, options.maxExternalScripts ?? MAX_EXTERNAL_SCRIPTS);
    externalScripts = (
      await Promise.all(
        sources.map(async (src) => {
          let absolute: string;
          try {
            absolute = new URL(src, options.url ?? "https://invalid.example/").toString();
          } catch {
            return "";
          }
          if (!/^https?:/i.test(absolute)) return "";
          try {
            const body = await options.fetchScript!(absolute);
            return (body ?? "").slice(0, MAX_SCRIPT_BYTES);
          } catch {
            return "";
          }
        })
      )
    ).filter(Boolean);
  }
  const invoke = options.invoke ?? renderDom;
  return await invoke({ html, url: options.url, externalScripts });
}

// The pure, self-contained core: build a real DOM, run inline + provided external
// scripts against it with instrumented surfaces, return rendered HTML + behaviors.
// No IO, no host-global mutation — safe to run in-process or bundled into an
// isolate (isolated-vm / CF Dynamic Worker).
export function renderDom(input: RenderInput): RenderResult {
  const report = emptyReport();
  let parsed: { document: any; window: any };
  try {
    parsed = parseHTML(input.html);
  } catch {
    report.errors.push("linkedom parse failed");
    return { html: input.html, report };
  }
  const globals = instrument(parsed.window, parsed.document, input.url, report);
  const scripts = [...extractInlineScripts(input.html), ...(input.externalScripts ?? [])];
  for (const body of scripts) {
    try {
      // eslint-disable-next-line no-new-func
      new Function(...Object.keys(globals), body)(...Object.values(globals));
    } catch (error) {
      report.errors.push(error instanceof Error ? error.message : "script error");
    }
  }
  let rendered = input.html;
  try {
    rendered = parsed.document.toString();
  } catch {
    /* keep raw html */
  }
  return { html: rendered, report };
}

// Install instrumented behavioral surfaces on the linkedom window AND return the
// matching bare globals (so `fetch(...)` and `window.fetch(...)` both record).
function instrument(window: any, document: any, url: string | undefined, report: BehaviorReport): Record<string, unknown> {
  const resolve = (value: unknown): string => {
    const raw = String(value ?? "");
    try {
      return url ? new URL(raw, url).toString() : raw;
    } catch {
      return raw;
    }
  };
  const pushNet = (kind: NetworkAttempt["kind"], target: unknown) => report.network.push({ kind, url: resolve(target) });

  const fetchStub = (input: unknown) => {
    pushNet("fetch", typeof input === "object" && input ? (input as any).url ?? input : input);
    return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(""), json: () => Promise.resolve({}), headers: { get: () => null } });
  };
  const XHRStub = function (this: any) {
    this.open = (_method: string, target: string) => { this._url = target; };
    this.send = () => { if (this._url) pushNet("xhr", this._url); };
    this.setRequestHeader = () => {};
    this.addEventListener = () => {};
  };
  const beacon = (target: unknown) => { pushNet("beacon", target); return true; };
  const recordEval = (code: unknown) => { report.evals.push(String(code)); return undefined; };
  const FunctionStub = function (...args: unknown[]) { report.evals.push(String(args[args.length - 1] ?? "")); return function () {}; };
  const safeAtob = (value: unknown) => {
    let out: string;
    try { out = atob(String(value)); } catch { out = String(value); }
    report.decoded.push(out);
    return out;
  };
  const safeBtoa = (value: unknown) => { try { return btoa(String(value)); } catch { return String(value); } };
  const location = new Proxy(
    { href: url ?? "", assign: (u: unknown) => report.redirects.push(resolve(u)), replace: (u: unknown) => report.redirects.push(resolve(u)), reload: () => {}, toString: () => url ?? "" },
    { set: (target, prop, value) => { if (prop === "href") report.redirects.push(resolve(value)); (target as any)[prop] = value; return true; } }
  );

  // Override the surfaces the page reaches via the window object.
  try { Object.defineProperty(window, "location", { value: location, configurable: true, writable: true }); } catch { /* non-configurable */ }
  try { window.fetch = fetchStub; } catch {}
  try { window.XMLHttpRequest = XHRStub; } catch {}
  try { if (window.navigator) window.navigator.sendBeacon = beacon; } catch {}
  try { Object.defineProperty(document, "cookie", { configurable: true, get: () => "", set: (v: unknown) => { report.cookies.push(String(v)); } }); } catch {}

  const noop = () => {};
  const timerRun = (fn: unknown) => { try { if (typeof fn === "function") (fn as () => void)(); } catch {} return 0; };
  return {
    window,
    document,
    self: window,
    globalThis: window,
    top: window,
    parent: window,
    location,
    fetch: fetchStub,
    XMLHttpRequest: XHRStub,
    navigator: window.navigator ?? { userAgent: "Mozilla/5.0", language: "en-US", platform: "Win32", sendBeacon: beacon },
    screen: { width: 1920, height: 1080 },
    history: { pushState: noop, replaceState: noop },
    atob: safeAtob,
    btoa: safeBtoa,
    eval: recordEval,
    Function: FunctionStub,
    setTimeout: timerRun,
    setInterval: () => 0,
    clearTimeout: noop,
    clearInterval: noop,
    requestAnimationFrame: timerRun,
    queueMicrotask: (fn: unknown) => { try { (fn as () => void)(); } catch {} },
    console: { log: noop, warn: noop, error: noop, info: noop, debug: noop },
    MutationObserver: function (this: any) { this.observe = noop; this.disconnect = noop; },
    IntersectionObserver: function (this: any) { this.observe = noop; this.disconnect = noop; }
  };
}

function defaultRun(scripts: string[], globals: Record<string, unknown>): void {
  const names = Object.keys(globals);
  const values = names.map((name) => globals[name]);
  for (const body of scripts) {
    try {
      // eslint-disable-next-line no-new-func
      new Function(...names, body)(...values);
    } catch {
      /* malformed/strict-mode-conflicting script — skip, best effort */
    }
  }
}
