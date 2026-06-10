import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { createScanner, dispositionForScore, normalizeUrl, scoreFindings, type Finding, type ScannerReport } from "../src/index";
import { RECORDER_SOURCE, behaviorFindings, extractInlineScripts, type BehaviorReport } from "../src/dynamic";

const DYNAMIC_TIMEOUT_MS = 3000;

// Node-native isolation for the untrusted page JS: a fresh node:vm context with
// only the globals the recorder needs (no process/require/fs) and a hard
// timeout. The lib's RECORDER_SOURCE is isolate-agnostic; this is the CLI's
// chosen executor. (isolated-vm can be swapped in here for a stronger boundary.)
function recordBehaviorInVm(scripts: string[], url?: string): BehaviorReport {
  const context = vm.createContext({ URL, atob, btoa, __scripts: scripts, __url: url });
  return vm.runInNewContext(`${RECORDER_SOURCE}\nrecordBehavior(__scripts, __url)`, context, {
    timeout: DYNAMIC_TIMEOUT_MS,
    // Untrusted page JS may use dynamic import(). Without a handler node:vm
    // throws ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING — and because import() is
    // async the throw escapes the caller's try/catch. Block it with a rejecting
    // stub instead: the scanner records behavior, it never loads page modules.
    importModuleDynamically: () => {
      throw new Error("dynamic import blocked in scanner sandbox");
    }
  }) as BehaviorReport;
}

// Run a fetched HTML page's inline scripts in the sandbox and fold the dynamic
// findings (runtime exfil/redirects + re-scanned injected/decoded content) into
// the page report, re-scoring so they count.
function applyDynamicAnalysis(report: ScannerReport, chunks: Uint8Array[], url: string): void {
  if (report.contentKind !== "html") return;
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
  const scripts = extractInlineScripts(new TextDecoder("utf-8", { fatal: false }).decode(merged));
  if (!scripts.length) return;
  let dynamic: Finding[];
  try {
    dynamic = behaviorFindings(recordBehaviorInVm(scripts, url), url);
  } catch {
    return; // sandbox/timeout failure never breaks the scan
  }
  if (!dynamic.length) return;
  report.findings = [...report.findings, ...dynamic];
  report.score = scoreFindings(report.findings);
  report.disposition = dispositionForScore(report.score);
}

const MAX_FETCH_BYTES = 512 * 1024;
const MAX_CRAWL_URLS = 128;
const MAX_CRAWL_DEPTH = 2;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_SITEMAP_URLS = 512;
const REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_PARALLEL = 10;
// A real browser UA so cloaking kits (which serve benign pages to obvious
// scanners) reveal their actual content.
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

// Reusable defaults so other scripts (e.g. the eval harness) can build
// CrawlOptions without re-deriving them.
export const DEFAULT_CRAWL_OPTIONS: CrawlOptions = {
  parallel: DEFAULT_PARALLEL,
  maxUrls: MAX_CRAWL_URLS,
  maxDepth: MAX_CRAWL_DEPTH,
  maxBytes: MAX_FETCH_BYTES,
  maxTotalBytes: MAX_TOTAL_BYTES,
  maxSitemapUrls: MAX_SITEMAP_URLS,
  timeoutMs: REQUEST_TIMEOUT_MS,
  robots: true,
  userAgent: USER_AGENT
};

export interface TargetReport {
  target: string;
  kind: "url" | "file";
  status?: number;
  bytes: number;
  report: ScannerReport;
  error?: string;
}

export interface CrawlOptions {
  parallel: number;
  maxUrls: number;
  maxDepth: number;
  maxBytes: number;
  maxTotalBytes: number;
  maxSitemapUrls: number;
  timeoutMs: number;
  robots: boolean;
  userAgent: string;
}

interface FileOptions {
  maxFileBytes: number;
}

interface ParsedArgs {
  mode: "crawl" | "files";
  targets: string[];
  crawl: CrawlOptions;
  files: FileOptions;
}

interface QueueItem {
  url: string;
  depth: number;
  source: "start" | "sitemap" | "page";
}

interface RobotsPolicy {
  sitemaps: string[];
  disallows: string[];
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (!args) {
    console.error(
      [
        "usage: tsx packages/signal-scanner/scripts/scan.ts crawl [options] <url...>",
        "       tsx packages/signal-scanner/scripts/scan.ts files [options] <path...>",
        "",
        "crawl options:",
        "  --no-robots                 do not fetch or obey robots.txt",
        "  --parallel, -n <count>      concurrent fetches, default 10",
        "  --max-urls <count>          max globally deduped crawl URLs, default 128",
        "  --max-depth <count>         max link-follow depth, default 2",
        "  --max-bytes <bytes>         max bytes per response, default 524288",
        "  --max-total-bytes <bytes>   max bytes across crawl, default 33554432",
        "  --max-sitemap-urls <count>  max URLs accepted from sitemaps, default 512",
        "  --timeout-ms <ms>           request timeout, default 10000",
        "  --user-agent <value>        custom user-agent",
        "",
        "file options:",
        "  --max-file-bytes <bytes>    max bytes per file, default 524288"
      ].join("\n")
    );
    process.exit(2);
  }

  const reports = args.mode === "crawl"
    ? await crawlTargets(args.targets, args.crawl)
    : await scanFileTargets(args.targets, args.files);
  printSummary(reports);
}

export async function crawlTargets(startUrls: string[], options: CrawlOptions): Promise<TargetReport[]> {
  const reports: TargetReport[] = [];
  const queue: QueueItem[] = [];
  const queued = new Set<string>();
  const seen = new Set<string>();
  const seenFinal = new Set<string>();
  const allowedDomains = new Set(startUrls.map((url) => normalizeUrl(url)?.registrableDomain).filter((domain): domain is string => !!domain));
  const allowedHosts = new Set(startUrls.map((url) => hostFor(url)).filter((host): host is string => !!host));
  const robotsByDomain = new Map<string, RobotsPolicy>();
  let totalBytes = 0;

  const enqueue = (url: string, depth: number, source: QueueItem["source"]): void => {
    const normalized = normalizeUrl(url);
    if (!normalized || !isAllowed(normalized.normalized, allowedDomains, allowedHosts)) return;
    if (queued.has(normalized.normalized) || seen.has(normalized.normalized)) return;
    if (queued.size + seen.size >= options.maxUrls) return;
    queue.push({ url: normalized.normalized, depth, source });
    queued.add(normalized.normalized);
  };

  for (const start of startUrls) enqueue(start, 0, "start");
  for (const start of startUrls) {
    const normalized = normalizeUrl(start);
    if (!normalized || !isAllowed(normalized.normalized, allowedDomains, allowedHosts)) continue;
    const origin = new URL(normalized.normalized).origin;
    const robots = options.robots ? await fetchRobots(origin, options) : { sitemaps: [], disallows: [] };
    robotsByDomain.set(boundKey(normalized.normalized), robots);
    for (const sitemapUrl of await discoverSitemapEntries(origin, robots.sitemaps, allowedDomains, allowedHosts, options)) enqueue(sitemapUrl, 0, "sitemap");
  }

  async function worker(): Promise<void> {
    while (queue.length && seen.size < options.maxUrls && totalBytes < options.maxTotalBytes) {
      const item = queue.shift()!;
      queued.delete(item.url);
      if (seen.has(item.url)) continue;
      seen.add(item.url);
      const normalized = normalizeUrl(item.url);
      if (!normalized || !isAllowed(normalized.normalized, allowedDomains, allowedHosts)) continue;
      if (options.robots && item.source !== "start" && isDisallowed(item.url, robotsByDomain.get(boundKey(normalized.normalized)))) continue;

      const targetReport = await scanUrl(item.url, options);
      totalBytes += targetReport.bytes;
      const finalNormalized = normalizeUrl(targetReport.target)?.normalized;
      if (finalNormalized && seenFinal.has(finalNormalized)) continue;
      if (finalNormalized) seenFinal.add(finalNormalized);
      reports.push(targetReport);
      if (targetReport.error || item.depth >= options.maxDepth) continue;
      for (const extracted of targetReport.report.urls) {
        if (seen.size + queued.size >= options.maxUrls) break;
        enqueue(extracted.normalized, item.depth + 1, "page");
      }
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, options.parallel) }, () => worker()));
  return reports;
}

async function scanUrl(url: string, options: CrawlOptions): Promise<TargetReport> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  const scanner = createScanner({ source: { url } });
  let bytes = 0;
  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: { "user-agent": options.userAgent },
      signal: controller.signal
    });
    const responseScanner = createScanner({
      source: {
        url,
        finalUrl: response.url || url,
        contentType: response.headers.get("content-type")
      }
    });
    const reader = response.body?.getReader();
    const collected: Uint8Array[] = [];
    if (reader) {
      while (bytes < options.maxBytes) {
        const next = await reader.read();
        if (next.done) break;
        const chunk = next.value.slice(0, Math.max(0, options.maxBytes - bytes));
        bytes += chunk.byteLength;
        responseScanner.feed(chunk);
        collected.push(chunk);
        if (chunk.byteLength < next.value.byteLength) break;
      }
      await reader.cancel().catch(() => undefined);
    } else {
      const body = new Uint8Array(await response.arrayBuffer());
      const chunk = body.slice(0, options.maxBytes);
      bytes = chunk.byteLength;
      responseScanner.feed(chunk);
      collected.push(chunk);
    }
    const finalUrl = response.url || url;
    const report = responseScanner.finish();
    applyDynamicAnalysis(report, collected, finalUrl);
    return { target: finalUrl, kind: "url", status: response.status, bytes, report };
  } catch (error) {
    return {
      target: url,
      kind: "url",
      bytes,
      report: scanner.finish(),
      error: error instanceof Error ? `${error.name}: ${error.message}` : String(error)
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function scanFileTargets(paths: string[], options: FileOptions): Promise<TargetReport[]> {
  const files: string[] = [];
  for (const path of paths) await collectFiles(resolve(path), files);
  const reports: TargetReport[] = [];
  for (const file of files) reports.push(await scanFile(file, options));
  return reports;
}

async function collectFiles(path: string, output: string[]): Promise<void> {
  const info = await stat(path);
  if (info.isDirectory()) {
    for (const entry of await readdir(path)) {
      if (/^(?:node_modules|\.git|dist|coverage)$/.test(entry)) continue;
      await collectFiles(join(path, entry), output);
    }
    return;
  }
  if (!/\.(?:ts|tsx|js|mjs|cjs|json|html|css|svg|md|txt|yml|yaml)$/.test(path)) return;
  output.push(path);
}

async function scanFile(path: string, options: FileOptions): Promise<TargetReport> {
  const scanner = createScanner({ source: { filename: path } });
  let bytes = 0;
  await new Promise<void>((resolvePromise, reject) => {
    const stream = createReadStream(path, { highWaterMark: 64 * 1024 });
    stream.on("data", (chunk: Buffer) => {
      if (bytes >= options.maxFileBytes) return;
      const view = chunk.subarray(0, Math.max(0, options.maxFileBytes - bytes));
      bytes += view.byteLength;
      scanner.feed(view);
      if (view.byteLength < chunk.byteLength) stream.destroy();
    });
    stream.on("error", reject);
    stream.on("close", resolvePromise);
    stream.on("end", resolvePromise);
  });
  return { target: path, kind: "file", bytes, report: scanner.finish() };
}

function printSummary(reports: TargetReport[]): void {
  const aggregate = scoreAggregate(reports);
  console.log(JSON.stringify({
    aggregate,
    scanned: reports.length,
    summary: summarizeReports(reports),
    targets: reports.map((item) => ({
      target: item.target,
      kind: item.kind,
      status: item.status,
      bytes: item.bytes,
      error: item.error,
      contentKind: item.report.contentKind,
      score: item.report.score,
      disposition: item.report.disposition,
      findings: summarizeFindings(item.report.findings)
    }))
  }, null, 2));
}

function summarizeReports(reports: TargetReport[]): {
  dispositions: Record<string, number>;
  contentKinds: Record<string, number>;
  errors: Record<string, number>;
  rules: Record<string, number>;
} {
  const dispositions: Record<string, number> = {};
  const contentKinds: Record<string, number> = {};
  const errors: Record<string, number> = {};
  const rules: Record<string, number> = {};
  for (const report of reports) {
    dispositions[report.report.disposition] = (dispositions[report.report.disposition] ?? 0) + 1;
    contentKinds[report.report.contentKind] = (contentKinds[report.report.contentKind] ?? 0) + 1;
    if (report.error) errors[report.error.split(":")[0]] = (errors[report.error.split(":")[0]] ?? 0) + 1;
    for (const finding of report.report.findings) rules[finding.ruleId] = (rules[finding.ruleId] ?? 0) + 1;
  }
  return { dispositions, contentKinds, errors, rules };
}

function summarizeFindings(findings: Finding[]): Array<{ ruleId: string; severity: string; confidence: string; count: number; sample: string }> {
  const groups = new Map<string, { finding: Finding; count: number }>();
  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.severity}:${finding.confidence}`;
    const group = groups.get(key);
    if (group) group.count += 1;
    else groups.set(key, { finding, count: 1 });
  }
  return [...groups.values()]
    .sort((left, right) => right.finding.score - left.finding.score || right.count - left.count)
    .slice(0, 12)
    .map(({ finding, count }) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      confidence: finding.confidence,
      count,
      sample: finding.locationValue.slice(0, 160)
    }));
}

function scoreAggregate(reports: TargetReport[]): { score: number; disposition: string; sha256: string } {
  const findings = reports.flatMap((item) => item.report.findings);
  const baseScore = Math.max(...reports.map((item) => item.report.score), 0);
  const bonusScore = Math.min(100, baseScore + (baseScore >= 50 && new Set(findings.map((finding) => finding.ruleId)).size >= 4 ? 8 : 0));
  const score = baseScore >= 75 ? bonusScore : Math.min(74, bonusScore);
  const disposition = score >= 75 ? "block" : score >= 50 ? "review" : score >= 25 ? "warn" : "allow";
  const sha256 = createHash("sha256").update(JSON.stringify(reports.map((item) => [item.target, item.report.score, item.report.findings.map((finding) => finding.ruleId)]))).digest("hex");
  return { score, disposition, sha256 };
}

async function fetchRobots(origin: string, options: CrawlOptions): Promise<RobotsPolicy> {
  const text = await fetchTextBounded(`${origin}/robots.txt`, options, 128 * 1024).catch(() => "");
  return parseRobots(text);
}

function parseRobots(text: string): RobotsPolicy {
  const sitemaps: string[] = [];
  const disallows: string[] = [];
  let active = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, "").trim();
    const [rawKey, ...rest] = line.split(":");
    if (!rawKey || rest.length === 0) continue;
    const key = rawKey.trim().toLowerCase();
    const value = rest.join(":").trim();
    if (key === "sitemap" && value) sitemaps.push(value);
    if (key === "user-agent") active = value === "*" || value.toLowerCase() === USER_AGENT.toLowerCase();
    if (active && key === "disallow" && value) disallows.push(value);
  }
  return { sitemaps, disallows };
}

async function discoverSitemapEntries(
  origin: string,
  robotsSitemaps: string[],
  allowedDomains: Set<string>,
  allowedHosts: Set<string>,
  options: CrawlOptions
): Promise<string[]> {
  const sitemapUrls = new Set([
    ...robotsSitemaps,
    `${origin}/sitemap.xml`,
    `${origin}/sitemap_index.xml`,
    `${origin}/sitemap-index.xml`
  ]);
  const discovered = new Set<string>();
  const pending = [...sitemapUrls];
  const seenSitemaps = new Set<string>();
  while (pending.length && discovered.size < options.maxSitemapUrls) {
    const sitemap = pending.shift()!;
    const normalizedSitemap = normalizeUrl(sitemap);
    if (!normalizedSitemap || seenSitemaps.has(normalizedSitemap.normalized)) continue;
    if (!isAllowed(normalizedSitemap.normalized, allowedDomains, allowedHosts)) continue;
    seenSitemaps.add(normalizedSitemap.normalized);
    const text = await fetchTextBounded(normalizedSitemap.normalized, options, options.maxBytes).catch(() => "");
    for (const loc of extractSitemapLocs(text)) {
      const normalized = normalizeUrl(loc, normalizedSitemap.normalized);
      if (!normalized || !isAllowed(normalized.normalized, allowedDomains, allowedHosts)) continue;
      if (/sitemap/i.test(new URL(normalized.normalized).pathname) && seenSitemaps.size < 32) pending.push(normalized.normalized);
      else discovered.add(normalized.normalized);
      if (discovered.size >= options.maxSitemapUrls) break;
    }
  }
  return [...discovered];
}

async function fetchTextBounded(url: string, options: CrawlOptions, maxBytes: number): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: { "user-agent": options.userAgent },
      signal: controller.signal
    });
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    if (!reader) return "";
    while (bytes < maxBytes) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = next.value.slice(0, Math.max(0, maxBytes - bytes));
      bytes += chunk.byteLength;
      chunks.push(chunk);
      if (chunk.byteLength < next.value.byteLength) break;
    }
    await reader.cancel().catch(() => undefined);
    const merged = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(merged);
  } finally {
    clearTimeout(timeout);
  }
}

function extractSitemapLocs(text: string): string[] {
  const locs: string[] = [];
  for (const match of text.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) locs.push(decodeXml(match[1].trim()));
  return locs;
}

function isDisallowed(url: string, policy?: RobotsPolicy): boolean {
  if (!policy?.disallows.length) return false;
  const path = new URL(url).pathname;
  return policy.disallows.some((rule) => rule === "/" || path.startsWith(rule));
}

function decodeXml(value: string): string {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'");
}

function isAllowed(url: string, allowedDomains: Set<string>, allowedHosts: Set<string>): boolean {
  const normalized = normalizeUrl(url);
  if (!normalized) return false;
  const host = hostFor(normalized.normalized);
  return (!!normalized.registrableDomain && allowedDomains.has(normalized.registrableDomain)) || (!!host && allowedHosts.has(host));
}

function hostFor(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function boundKey(url: string): string {
  return normalizeUrl(url)?.registrableDomain ?? hostFor(url) ?? url;
}

function parseArgs(argv: string[]): ParsedArgs | null {
  if (argv.includes("--help") || argv.includes("-h")) return null;
  const mode = argv.shift();
  if (mode !== "crawl" && mode !== "files") return null;
  const crawl: CrawlOptions = {
    parallel: DEFAULT_PARALLEL,
    maxUrls: MAX_CRAWL_URLS,
    maxDepth: MAX_CRAWL_DEPTH,
    maxBytes: MAX_FETCH_BYTES,
    maxTotalBytes: MAX_TOTAL_BYTES,
    maxSitemapUrls: MAX_SITEMAP_URLS,
    timeoutMs: REQUEST_TIMEOUT_MS,
    robots: true,
    userAgent: USER_AGENT
  };
  const files: FileOptions = { maxFileBytes: MAX_FILE_BYTES };
  const targets: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = (): string => {
      const value = argv[index + 1];
      if (!value) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };
    if (arg === "--no-robots") crawl.robots = false;
    else if (arg === "--parallel" || arg === "-n") crawl.parallel = positiveInt(next(), arg);
    else if (arg === "--max-urls") crawl.maxUrls = positiveInt(next(), arg);
    else if (arg === "--max-depth") crawl.maxDepth = nonNegativeInt(next(), arg);
    else if (arg === "--max-bytes") crawl.maxBytes = positiveInt(next(), arg);
    else if (arg === "--max-total-bytes") crawl.maxTotalBytes = positiveInt(next(), arg);
    else if (arg === "--max-sitemap-urls") crawl.maxSitemapUrls = nonNegativeInt(next(), arg);
    else if (arg === "--timeout-ms") crawl.timeoutMs = positiveInt(next(), arg);
    else if (arg === "--user-agent") crawl.userAgent = next();
    else if (arg === "--max-file-bytes") files.maxFileBytes = positiveInt(next(), arg);
    else targets.push(arg);
  }
  if (targets.length === 0) return null;
  return { mode, targets, crawl, files };
}

function positiveInt(value: string, name: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function nonNegativeInt(value: string, name: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${name} must be a non-negative integer`);
  return parsed;
}

// Only run the CLI when invoked directly, not when imported (e.g. by eval.ts).
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
