// Dynamic JavaScript behavior analysis.
//
// Runs a page's inline scripts against an instrumented window/document where the
// dangerous primitives (eval/Function, fetch/XHR/sendBeacon/WebSocket, location,
// document.write/innerHTML, form.action, atob, cookies) are NEUTERED and
// RECORDED rather than executed. What the script *tries* to do is the signal:
// JS redirects (decloaking), exfil endpoints, injected credential forms,
// decoded payloads. Recorded markup and eval'd code are re-fed through the
// static scanner so existing rules light up on runtime-produced content.
//
// Runtime-agnostic: evaluation uses `new Function` with the globals shadowed by
// recorder stubs, which runs unchanged in a Worker isolate and in Node. The
// executor can be hardened per runtime later (a CF sub-isolate / Durable Object,
// or node:vm / isolated-vm) — this module is the shared instrumentation and the
// behavior→findings analysis.

import { createScanner, type Finding, type Severity, type Confidence } from "./index";
import type { RuleScoreModel } from "./rules/types";

export interface NetworkAttempt {
  kind: "fetch" | "xhr" | "beacon" | "websocket" | "script" | "image" | "form";
  url: string;
}

export interface BehaviorReport {
  redirects: string[];
  network: NetworkAttempt[];
  writes: string[];
  evals: string[];
  decoded: string[];
  cookies: string[];
  errors: string[];
}

export interface DynamicAnalysisOptions {
  /** Base/page URL, used to resolve relative targets and classify off-origin. */
  url?: string;
  /** Cap on inline scripts evaluated. */
  maxScripts?: number;
  /** Cap on characters per script. */
  maxScriptChars?: number;
}

const DEFAULT_MAX_SCRIPTS = 64;
const DEFAULT_MAX_SCRIPT_CHARS = 256 * 1024;

const EXFIL_SCORE: RuleScoreModel = { base: 72, tags: ["exfiltration", "script"] };
const REDIRECT_SCORE: RuleScoreModel = { base: 45, tags: ["redirect", "script"] };
const EVAL_SCORE: RuleScoreModel = { base: 30, tags: ["obfuscation", "script"] };

/** Extract inline <script> bodies (no src) from HTML. */
export function extractInlineScripts(html: string): string[] {
  const scripts: string[] = [];
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = match[1] ?? "";
    if (/\bsrc\s*=/i.test(attrs)) continue; // external scripts are fetched + scanned separately
    if (/\btype\s*=\s*["']?(?:application\/json|application\/ld\+json|text\/template)/i.test(attrs)) continue;
    const body = match[2]?.trim();
    if (body) scripts.push(body);
  }
  return scripts;
}

/**
 * Run inline scripts against the recording shim and return what they attempted.
 * Pure recording — no network egress, no real eval, no real navigation.
 */
export function runInstrumented(scripts: string[], options: DynamicAnalysisOptions = {}): BehaviorReport {
  const report: BehaviorReport = { redirects: [], network: [], writes: [], evals: [], decoded: [], cookies: [], errors: [] };
  const maxScripts = options.maxScripts ?? DEFAULT_MAX_SCRIPTS;
  const maxChars = options.maxScriptChars ?? DEFAULT_MAX_SCRIPT_CHARS;
  const sandbox = buildSandbox(report, options.url);

  for (const script of scripts.slice(0, maxScripts)) {
    if (script.length > maxChars) {
      report.errors.push("script too large");
      continue;
    }
    try {
      // Shadow the dangerous globals with recorder stubs. References in the
      // script body resolve to these params, not the host isolate's globals.
      // NOT strict mode on purpose: strict forbids a parameter named `eval`,
      // and shadowing `eval`/`Function` is precisely how we record them.
      const runner = new Function(...Object.keys(sandbox), script);
      runner(...Object.values(sandbox));
    } catch (error) {
      report.errors.push(error instanceof Error ? error.message : "script error");
    }
  }
  return report;
}

/** Full pass: extract inline scripts, record behavior, and turn it into findings. */
export function analyzeDynamic(html: string, options: DynamicAnalysisOptions = {}): { report: BehaviorReport; findings: Finding[] } {
  const report = runInstrumented(extractInlineScripts(html), options);
  return { report, findings: behaviorFindings(report, options.url) };
}

/** Map recorded behavior to scanner findings, re-scanning injected markup and decoded/eval'd code. */
export function behaviorFindings(report: BehaviorReport, baseUrl?: string): Finding[] {
  const findings: Finding[] = [];
  let i = 0;
  const add = (severity: Severity, confidence: Confidence, model: RuleScoreModel, ruleId: string, title: string, description: string, location: string, metadata: Record<string, unknown>) => {
    findings.push({ id: `${ruleId}:${i++}`, ruleId, severity, confidence, score: model.base, scoreModel: model, title, description, locationType: "javascript", locationValue: location, metadata });
  };

  for (const target of report.network) {
    if (isOffOrigin(target.url, baseUrl)) {
      add("high", "high", EXFIL_SCORE, "runtime_offsite_exfil", `Runtime ${target.kind} to an off-origin endpoint`, `Page JavaScript issued a ${target.kind} request to a different origin at runtime — a common credential/data exfiltration pattern.`, target.url, { kind: target.kind });
    }
  }
  for (const redirect of report.redirects) {
    if (isOffOrigin(redirect, baseUrl)) {
      add("medium", "high", REDIRECT_SCORE, "runtime_offsite_redirect", "JavaScript navigated to a different origin at runtime", "Page JavaScript set location to an off-origin URL — used to cloak content from scanners and route victims onward.", redirect, {});
    }
  }
  if (report.evals.length) {
    add("low", "medium", EVAL_SCORE, "runtime_dynamic_code", "Runtime dynamic code execution", `Page JavaScript invoked eval/Function/string-timer ${report.evals.length} time(s) at runtime.`, "eval", { count: report.evals.length });
  }

  // Re-scan runtime-produced content (injected markup, decoded blobs, eval'd
  // code) through the static scanner so existing rules apply to it.
  const derived = [...report.writes, ...report.decoded, ...report.evals];
  for (const chunk of derived) {
    if (!chunk || chunk.length < 8) continue;
    const scanner = createScanner({ source: { url: baseUrl, contentType: "text/html" } });
    scanner.feed(new TextEncoder().encode(chunk));
    for (const finding of scanner.finish().findings) {
      findings.push({ ...finding, id: `dyn.${finding.ruleId}:${i++}`, metadata: { ...finding.metadata, via: "dynamic_analysis" } });
    }
  }
  return findings;
}

// ---- the recording sandbox ------------------------------------------------

function buildSandbox(report: BehaviorReport, baseUrl?: string): Record<string, unknown> {
  const resolve = (value: unknown): string => {
    const raw = String(value ?? "");
    try {
      return baseUrl ? new URL(raw, baseUrl).toString() : raw;
    } catch {
      return raw;
    }
  };
  const net = (kind: NetworkAttempt["kind"]) => (url: unknown) => {
    report.network.push({ kind, url: resolve(url) });
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}), text: () => Promise.resolve("") });
  };

  const locationProxy = new Proxy(
    { href: baseUrl ?? "", assign: (u: unknown) => report.redirects.push(resolve(u)), replace: (u: unknown) => report.redirects.push(resolve(u)), reload() {}, toString: () => baseUrl ?? "" },
    {
      set(targetObj, prop, value) {
        if (prop === "href") report.redirects.push(resolve(value));
        (targetObj as any)[prop] = value;
        return true;
      }
    }
  );

  const makeElement = (tag: string): any => {
    const el: any = { tagName: String(tag).toUpperCase(), style: {}, children: [], attributes: {} };
    let _src = "";
    let _action = "";
    Object.defineProperty(el, "src", { get: () => _src, set: (v) => { _src = String(v); report.network.push({ kind: el.tagName === "IMG" ? "image" : "script", url: resolve(v) }); } });
    Object.defineProperty(el, "action", { get: () => _action, set: (v) => { _action = String(v); report.network.push({ kind: "form", url: resolve(v) }); } });
    Object.defineProperty(el, "innerHTML", { get: () => "", set: (v) => { report.writes.push(String(v)); } });
    el.setAttribute = (k: string, v: unknown) => { if (k === "src") el.src = v; else if (k === "action") el.action = v; else el.attributes[k] = v; };
    el.appendChild = (c: unknown) => c;
    el.addEventListener = () => {};
    return el;
  };

  const documentShim: any = {
    write: (...args: unknown[]) => report.writes.push(args.map(String).join("")),
    writeln: (...args: unknown[]) => report.writes.push(args.map(String).join("")),
    createElement: (tag: unknown) => makeElement(String(tag)),
    getElementById: () => null,
    getElementsByTagName: () => [],
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
    body: makeElement("body"),
    head: makeElement("head"),
    location: locationProxy
  };
  Object.defineProperty(documentShim, "cookie", { get: () => "", set: (v) => report.cookies.push(String(v)) });

  const recordEval = (code: unknown) => { report.evals.push(String(code)); return undefined; };
  const FunctionStub = function (...args: unknown[]) { report.evals.push(String(args[args.length - 1] ?? "")); return () => undefined; } as unknown as FunctionConstructor;

  const windowShim: any = {
    document: documentShim,
    location: locationProxy,
    navigator: { userAgent: "Mozilla/5.0", platform: "Win32", language: "en-US" },
    screen: { width: 1920, height: 1080 },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    sessionStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    atob: (v: unknown) => { const out = base64Decode(String(v)); report.decoded.push(out); return out; },
    btoa: (v: unknown) => base64Encode(String(v)),
    fetch: net("fetch"),
    XMLHttpRequest: class { open(_m: unknown, url: unknown) { report.network.push({ kind: "xhr", url: resolve(url) }); } send() {} setRequestHeader() {} addEventListener() {} },
    WebSocket: class { constructor(url: unknown) { report.network.push({ kind: "websocket", url: resolve(url) }); } send() {} close() {} },
    navigatorSendBeacon: (url: unknown) => report.network.push({ kind: "beacon", url: resolve(url) }),
    eval: recordEval,
    Function: FunctionStub,
    setTimeout: (fn: unknown) => { if (typeof fn === "string") report.evals.push(fn); return 0; },
    setInterval: (fn: unknown) => { if (typeof fn === "string") report.evals.push(fn); return 0; },
    addEventListener: () => {},
    console: { log: () => {}, warn: () => {}, error: () => {} }
  };
  windowShim.navigator.sendBeacon = (url: unknown) => { report.network.push({ kind: "beacon", url: resolve(url) }); return true; };
  windowShim.window = windowShim;
  windowShim.self = windowShim;
  windowShim.globalThis = windowShim;
  windowShim.top = windowShim;

  // The exact parameter names that will shadow host globals inside the script.
  return {
    window: windowShim,
    self: windowShim,
    globalThis: windowShim,
    document: documentShim,
    location: locationProxy,
    navigator: windowShim.navigator,
    fetch: windowShim.fetch,
    XMLHttpRequest: windowShim.XMLHttpRequest,
    WebSocket: windowShim.WebSocket,
    eval: recordEval,
    Function: FunctionStub,
    atob: windowShim.atob,
    btoa: windowShim.btoa,
    setTimeout: windowShim.setTimeout,
    setInterval: windowShim.setInterval,
    localStorage: windowShim.localStorage,
    console: windowShim.console
  };
}

function isOffOrigin(url: string, baseUrl?: string): boolean {
  if (!baseUrl) {
    return /^[a-z]+:\/\//i.test(url);
  }
  try {
    return new URL(url, baseUrl).origin !== new URL(baseUrl).origin;
  } catch {
    return false;
  }
}

function base64Decode(value: string): string {
  try {
    if (typeof atob === "function") return atob(value);
    const buf = (globalThis as any).Buffer;
    return buf ? buf.from(value, "base64").toString("binary") : value;
  } catch {
    return value;
  }
}

function base64Encode(value: string): string {
  try {
    if (typeof btoa === "function") return btoa(value);
    const buf = (globalThis as any).Buffer;
    return buf ? buf.from(value, "binary").toString("base64") : value;
  } catch {
    return value;
  }
}
