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
// This module is isolate-agnostic on purpose. It exposes:
//   - RECORDER_SOURCE: the recorder as self-contained source, for a caller to
//     run inside whatever isolate it has (a CF Dynamic Worker, node isolated-vm,
//     a node:vm context, ...). The lib knows nothing about those mechanisms.
//   - runInstrumented(): an in-process default (compiles RECORDER_SOURCE here)
//     for when no isolate boundary is needed.
//   - analyzeDynamicWith(html, opts, evaluate): the generic seam — the caller
//     passes an `evaluate` that produces a BehaviorReport however it likes.

import { assessRedirect, createScanner, isAdOrAnalyticsHost, registrableDomainFor, type Finding, type Severity, type Confidence } from "./index";
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
}

/** The caller supplies one of these: "run these scripts in an isolate, give me what they attempted." */
export type IsolatedEvaluator = (scripts: string[], options: DynamicAnalysisOptions) => BehaviorReport | Promise<BehaviorReport>;

const EMPTY_REPORT: BehaviorReport = { redirects: [], network: [], writes: [], evals: [], decoded: [], cookies: [], errors: [] };

// Self-contained recorder. Evaluating this source defines `recordBehavior(scripts, url)`
// which returns a BehaviorReport. It references only standard globals (URL, atob,
// btoa, Proxy) available in any JS isolate — no imports, no transport, no
// assumptions about how it is hosted. Inline scripts run via `new Function` with
// the dangerous globals shadowed by recorder stubs (sloppy mode so `eval` /
// `Function` can be shadowed as parameters).
export const RECORDER_SOURCE = String.raw`
function recordBehavior(scripts, url) {
  var report = { redirects: [], network: [], writes: [], evals: [], decoded: [], cookies: [], errors: [] };
  var resolve = function (v) { var raw = String(v == null ? "" : v); try { return url ? new URL(raw, url).toString() : raw; } catch (e) { return raw; } };
  var recordEval = function (c) { report.evals.push(String(c)); return undefined; };
  var FunctionStub = function () { var a = arguments; report.evals.push(String(a[a.length - 1] == null ? "" : a[a.length - 1])); return function () {}; };
  var locationProxy = new Proxy({ href: url || "", assign: function (u) { report.redirects.push(resolve(u)); }, replace: function (u) { report.redirects.push(resolve(u)); }, reload: function () {}, toString: function () { return url || ""; } }, { set: function (t, p, val) { if (p === "href") report.redirects.push(resolve(val)); t[p] = val; return true; } });
  var makeElement = function (tag) {
    var el = { tagName: String(tag).toUpperCase(), style: {}, children: [], attributes: {} };
    var s = "", a = "";
    Object.defineProperty(el, "src", { get: function () { return s; }, set: function (v) { s = String(v); report.network.push({ kind: el.tagName === "IMG" ? "image" : "script", url: resolve(v) }); } });
    Object.defineProperty(el, "action", { get: function () { return a; }, set: function (v) { a = String(v); report.network.push({ kind: "form", url: resolve(v) }); } });
    Object.defineProperty(el, "innerHTML", { get: function () { return ""; }, set: function (v) { report.writes.push(String(v)); } });
    el.setAttribute = function (k, v) { if (k === "src") el.src = v; else if (k === "action") el.action = v; else el.attributes[k] = v; };
    el.appendChild = function (c) { return c; }; el.addEventListener = function () {};
    return el;
  };
  var documentShim = { write: function () { report.writes.push(Array.prototype.map.call(arguments, String).join("")); }, writeln: function () { report.writes.push(Array.prototype.map.call(arguments, String).join("")); }, createElement: function (t) { return makeElement(String(t)); }, getElementById: function () { return null; }, getElementsByTagName: function () { return []; }, querySelector: function () { return null; }, querySelectorAll: function () { return []; }, addEventListener: function () {}, body: makeElement("body"), head: makeElement("head"), location: locationProxy };
  Object.defineProperty(documentShim, "cookie", { get: function () { return ""; }, set: function (v) { report.cookies.push(String(v)); } });
  var safeAtob = function (v) { var out; try { out = atob(String(v)); } catch (e) { out = String(v); } report.decoded.push(out); return out; };
  var safeBtoa = function (v) { try { return btoa(String(v)); } catch (e) { return String(v); } };
  var win = {
    document: documentShim, location: locationProxy,
    navigator: { userAgent: "Mozilla/5.0", platform: "Win32", language: "en-US", sendBeacon: function (u) { report.network.push({ kind: "beacon", url: resolve(u) }); return true; } },
    screen: { width: 1920, height: 1080 },
    localStorage: { getItem: function () { return null; }, setItem: function () {}, removeItem: function () {} },
    sessionStorage: { getItem: function () { return null; }, setItem: function () {}, removeItem: function () {} },
    atob: safeAtob, btoa: safeBtoa,
    fetch: function (u) { report.network.push({ kind: "fetch", url: resolve(u) }); return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({}); }, text: function () { return Promise.resolve(""); } }); },
    XMLHttpRequest: function () { return { open: function (m, u) { report.network.push({ kind: "xhr", url: resolve(u) }); }, send: function () {}, setRequestHeader: function () {}, addEventListener: function () {} }; },
    WebSocket: function (u) { report.network.push({ kind: "websocket", url: resolve(u) }); return { send: function () {}, close: function () {} }; },
    eval: recordEval, Function: FunctionStub,
    setTimeout: function (fn) { if (typeof fn === "string") report.evals.push(fn); return 0; },
    setInterval: function (fn) { if (typeof fn === "string") report.evals.push(fn); return 0; },
    addEventListener: function () {}, console: { log: function () {}, warn: function () {}, error: function () {} }
  };
  win.window = win; win.self = win; win.globalThis = win; win.top = win;
  var params = { window: win, self: win, globalThis: win, document: documentShim, location: locationProxy, navigator: win.navigator, fetch: win.fetch, XMLHttpRequest: win.XMLHttpRequest, WebSocket: win.WebSocket, eval: recordEval, Function: FunctionStub, atob: safeAtob, btoa: safeBtoa, setTimeout: win.setTimeout, setInterval: win.setInterval, localStorage: win.localStorage, console: win.console };
  var keys = Object.keys(params), vals = keys.map(function (k) { return params[k]; });
  var list = Array.isArray(scripts) ? scripts.slice(0, 64) : [];
  for (var i = 0; i < list.length; i++) {
    var script = list[i];
    if (typeof script !== "string" || script.length > 262144) { report.errors.push("script skipped"); continue; }
    try { Function.apply(null, keys.concat([script])).apply(null, vals); }
    catch (e) { report.errors.push(e && e.message ? e.message : "script error"); }
  }
  return report;
}
`;

let compiledRecorder: ((scripts: string[], url?: string) => BehaviorReport) | null = null;
function inProcessRecorder(): (scripts: string[], url?: string) => BehaviorReport {
  if (!compiledRecorder) {
    // eslint-disable-next-line no-new-func
    compiledRecorder = new Function(`${RECORDER_SOURCE}\nreturn recordBehavior;`)() as (scripts: string[], url?: string) => BehaviorReport;
  }
  return compiledRecorder;
}

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
 * In-process default evaluator. Runs the recorder in THIS isolate (no boundary).
 * Use analyzeDynamicWith with a caller-supplied evaluator when isolation matters.
 */
export function runInstrumented(scripts: string[], options: DynamicAnalysisOptions = {}): BehaviorReport {
  try {
    return inProcessRecorder()(scripts, options.url);
  } catch (error) {
    return { ...EMPTY_REPORT, errors: [error instanceof Error ? error.message : "recorder failed"] };
  }
}

/** Full in-process pass: extract inline scripts, record behavior, turn it into findings. */
export function analyzeDynamic(html: string, options: DynamicAnalysisOptions = {}): { report: BehaviorReport; findings: Finding[] } {
  const report = runInstrumented(extractInlineScripts(html), options);
  return { report, findings: behaviorFindings(report, options.url) };
}

/** Generic seam: the caller supplies how scripts are evaluated (in whatever isolate it has). */
export async function analyzeDynamicWith(
  html: string,
  options: DynamicAnalysisOptions,
  evaluate: IsolatedEvaluator
): Promise<{ report: BehaviorReport; findings: Finding[] }> {
  const scripts = extractInlineScripts(html);
  const report = scripts.length ? await evaluate(scripts, options) : EMPTY_REPORT;
  return { report, findings: behaviorFindings(report, options.url) };
}

const EXFIL_SCORE: RuleScoreModel = { base: 72, tags: ["exfiltration", "script"] };
const OFFSITE_REQUEST_SCORE: RuleScoreModel = { base: 8, tags: ["script"] };
const REDIRECT_SCORE: RuleScoreModel = { base: 45, tags: ["redirect", "script"] };
// eval/Function/string-timer use is ubiquitous in legitimate bundles — weak
// alone. The re-scan of what they produce (below) is where real convictions come from.
const EVAL_SCORE: RuleScoreModel = { base: 12, tags: ["obfuscation", "script"] };

/** Map recorded behavior to scanner findings, re-scanning injected markup and decoded/eval'd code. */
export function behaviorFindings(report: BehaviorReport, baseUrl?: string): Finding[] {
  const findings: Finding[] = [];
  let i = 0;
  const add = (severity: Severity, confidence: Confidence, model: RuleScoreModel, ruleId: string, title: string, description: string, location: string, metadata: Record<string, unknown>) => {
    findings.push({ id: `${ruleId}:${i++}`, ruleId, severity, confidence, score: model.base, scoreModel: model, title, description, locationType: "javascript", locationValue: location, metadata });
  };

  for (const target of report.network) {
    // An off-site runtime request is NOT exfiltration on its own — legit sites
    // constantly fetch their own subdomains, CDNs, payment processors, analytics
    // and APIs. Only convict (high) when the destination host ITSELF looks
    // suspicious (shortener, suspicious TLD, punycode, IP literal, shared/
    // generated host) — the actual sketchy-endpoint exfil pattern. A request to
    // an ordinary off-site domain is recorded as a low-signal note, not a flag.
    if (!isThirdPartyTarget(target.url, baseUrl)) continue;
    const suspiciousDestination = baseUrl ? assessRedirect(baseUrl, target.url)?.destinationSuspicious ?? false : false;
    if (suspiciousDestination) {
      add("high", "high", EXFIL_SCORE, "runtime_offsite_exfil", `Runtime ${target.kind} to a suspicious off-site endpoint`, `Page JavaScript issued a ${target.kind} request to a suspicious unrelated host at runtime — a common credential/data exfiltration pattern.`, target.url, { kind: target.kind });
    } else {
      add("info", "low", OFFSITE_REQUEST_SCORE, "runtime_offsite_request", `Runtime ${target.kind} to an unrelated domain`, `Page JavaScript issued a ${target.kind} request to an unrelated (but not obviously suspicious) domain at runtime.`, target.url, { kind: target.kind });
    }
  }
  for (const redirect of report.redirects) {
    if (isThirdPartyTarget(redirect, baseUrl)) {
      add("medium", "high", REDIRECT_SCORE, "runtime_offsite_redirect", "JavaScript navigated to an unrelated domain at runtime", "Page JavaScript set location to an unrelated domain — used to cloak content from scanners and route victims onward.", redirect, {});
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

// A runtime target counts only if it's a different registrable domain than the
// page AND not a known ad/analytics/CDN host — so a site's own subdomains and
// mainstream third parties (gstatic, analytics) don't read as exfil.
function isThirdPartyTarget(url: string, baseUrl?: string): boolean {
  let absolute: string;
  let targetHost: string;
  try {
    const resolved = new URL(url, baseUrl);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return false;
    absolute = resolved.toString();
    targetHost = resolved.hostname.toLowerCase();
  } catch {
    return false;
  }
  if (isAdOrAnalyticsHost(absolute)) return false;
  if (!baseUrl) return true;
  try {
    const baseHost = new URL(baseUrl).hostname.toLowerCase();
    const targetReg = registrableDomainFor(targetHost) ?? targetHost;
    const baseReg = registrableDomainFor(baseHost) ?? baseHost;
    return targetReg !== baseReg;
  } catch {
    return true;
  }
}
