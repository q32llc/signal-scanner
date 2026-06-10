// Eval harness: run the homegrown scanner over a labeled corpus of known-good
// and known-bad sites and measure how well it separates them.
//
//   npm run eval               # reuse cached bad list if fresh (<6h)
//   npm run eval -- --refresh  # re-pull a fresh live bad list
//
// Known-good is the curated corpus/good.txt. Known-bad is pulled live from
// OpenPhish + URLhaus (they go offline fast), probed for reachability, and
// cached to corpus/.bad-cache.txt. The scan path is CLI heuristics only
// (structural + content + dynamic JS) — NO threat-intel feeds — so this measures
// the homegrown detector's own discriminative power, not feed lookups.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { crawlTargets, DEFAULT_CRAWL_OPTIONS, type CrawlOptions } from "./scan";
import { dispositionForScore } from "../src/index";

const FLAG_THRESHOLD = 50; // score >= 50 => product surfaces suspicious/malicious
const TARGET_BAD = 80;
const SITE_CONCURRENCY = 6;
const CACHE_PATH = resolve("corpus/.bad-cache.txt");
const PHISHING_CACHE_PATH = resolve("corpus/.bad-phishing-cache.txt");
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_FP_RATE = 0.05; // gate: at most 5% of good sites may be flagged

// Bounded per-site crawl: landing page + a shallow hop is enough to judge, and
// keeps a 160-site sweep tractable.
const CRAWL: CrawlOptions = {
  ...DEFAULT_CRAWL_OPTIONS,
  maxUrls: 10,
  maxDepth: 1,
  parallel: 4,
  robots: false,
  timeoutMs: 8000
};

const BROWSER_UA = DEFAULT_CRAWL_OPTIONS.userAgent;

interface SiteResult {
  url: string;
  label: "good" | "bad";
  score: number;
  disposition: string;
  pagesScanned: number;
  topFindings: Array<{ ruleId: string; score: number }>;
  unreachable: boolean;
}

// The dynamic-analysis sandbox runs untrusted page JS; a stray rejection or
// throw from one site must never abort a 160-site sweep. Per-site scanning is
// already best-effort, so swallow these and keep going.
process.on("unhandledRejection", () => {});
process.on("uncaughtException", (error) => {
  console.error("  (ignored uncaught error from sandbox):", error instanceof Error ? error.message : error);
});

async function main(): Promise<void> {
  const refresh = process.argv.includes("--refresh");
  // --phishing pulls a phishing-ONLY bad corpus (OpenPhish + Phishing.Database
  // active links, no URLhaus malware binaries) to measure catch rate on
  // malicious PAGES — where the web heuristics (credential forms, brand
  // impersonation, cloaking) should actually shine.
  const phishingOnly = process.argv.includes("--phishing");
  // Egress: set EVAL_PROXY_URL (e.g. an unfiltered residential proxy) so the
  // crawl + reachability probe leave via that proxy instead of the local
  // network — necessary when an ISP filter (e.g. Spectrum Security Shield)
  // intercepts known-malicious URLs and serves a block page, which would
  // otherwise make every bad site look benign. The npm script maps it onto
  // HTTP(S)_PROXY with NODE_USE_ENV_PROXY=1 (read at startup by node's fetch).
  const proxy = process.env.EVAL_PROXY_URL || process.env.HTTPS_PROXY || "";
  console.error(`egress: ${proxy ? "proxy " + redactProxy(proxy) : "direct (local network)"}`);

  const good = await loadList("corpus/good.txt");
  const bad = await loadBad(refresh, phishingOnly);
  console.error(`corpus: ${good.length} good, ${bad.length} bad (live, ${phishingOnly ? "phishing-only" : "mixed"})`);

  const labeled: Array<{ url: string; label: "good" | "bad" }> = [
    ...good.map((url) => ({ url, label: "good" as const })),
    ...bad.map((url) => ({ url, label: "bad" as const }))
  ];

  const results: SiteResult[] = [];
  let done = 0;
  await pool(labeled, SITE_CONCURRENCY, async ({ url, label }) => {
    const result = await scanSite(url, label);
    results.push(result);
    done += 1;
    if (done % 10 === 0) console.error(`  scanned ${done}/${labeled.length}`);
  });

  report(results);
}

async function scanSite(url: string, label: "good" | "bad"): Promise<SiteResult> {
  try {
    const reports = await crawlTargets([url], CRAWL);
    const scored = reports.filter((r) => !r.error && r.report);
    if (!scored.length) {
      return { url, label, score: 0, disposition: "allow", pagesScanned: 0, topFindings: [], unreachable: true };
    }
    const worst = scored.reduce((a, b) => (b.report.score > a.report.score ? b : a));
    const score = worst.report.score;
    const topFindings = [...worst.report.findings]
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
      .slice(0, 3)
      .map((f) => ({ ruleId: f.ruleId, score: f.score ?? 0 }));
    return { url, label, score, disposition: dispositionForScore(score), pagesScanned: scored.length, topFindings, unreachable: false };
  } catch {
    return { url, label, score: 0, disposition: "allow", pagesScanned: 0, topFindings: [], unreachable: true };
  }
}

function report(results: SiteResult[]): void {
  const reachable = results.filter((r) => !r.unreachable);
  const good = reachable.filter((r) => r.label === "good");
  const bad = reachable.filter((r) => r.label === "bad");
  const flagged = (r: SiteResult) => r.score >= FLAG_THRESHOLD;

  const fp = good.filter(flagged); // good, flagged => false positive
  const tn = good.filter((r) => !flagged(r));
  const tp = bad.filter(flagged); // bad, flagged => caught
  const fn = bad.filter((r) => !flagged(r)); // bad, missed

  const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(1)}%` : "n/a");

  const proxy = process.env.EVAL_PROXY_URL || process.env.HTTPS_PROXY || "";
  console.log("\n================ SCANNER EVAL ================");
  console.log(`egress: ${proxy ? "proxy " + redactProxy(proxy) : "direct (local network)"}`);
  console.log(`unreachable (excluded): ${results.filter((r) => r.unreachable).length} / ${results.length}`);
  console.log(`\nGood sites: ${good.length} reachable`);
  console.log(`  flagged (FALSE POSITIVE): ${fp.length}  [${pct(fp.length, good.length)}]`);
  console.log(`  clean (true negative):    ${tn.length}`);
  console.log(`\nBad sites: ${bad.length} reachable`);
  console.log(`  flagged (caught):         ${tp.length}  [recall ${pct(tp.length, bad.length)}]`);
  console.log(`  missed (false negative):  ${fn.length}`);

  console.log("\nScore distribution (count by band):");
  console.log(`  band        good   bad`);
  for (const [lo, hi] of [[0, 9], [10, 24], [25, 49], [50, 74], [75, 100]]) {
    const g = good.filter((r) => r.score >= lo && r.score <= hi).length;
    const b = bad.filter((r) => r.score >= lo && r.score <= hi).length;
    const mark = lo >= FLAG_THRESHOLD ? " <-flag" : "";
    console.log(`  ${String(lo).padStart(3)}-${String(hi).padEnd(3)}   ${String(g).padStart(5)} ${String(b).padStart(5)}${mark}`);
  }
  console.log(`  good: median ${median(good.map((r) => r.score))}, p90 ${percentile(good.map((r) => r.score), 90)}`);
  console.log(`  bad:  median ${median(bad.map((r) => r.score))}, p90 ${percentile(bad.map((r) => r.score), 90)}`);

  if (fp.length) {
    console.log("\nFALSE POSITIVES (good sites flagged) — fix these:");
    for (const r of fp.sort((a, b) => b.score - a.score)) {
      console.log(`  [${r.score}] ${r.url}  ${r.topFindings.map((f) => `${f.ruleId}(${f.score})`).join(", ")}`);
    }
  }
  if (fn.length) {
    console.log("\nMISSED bad sites (score < flag threshold):");
    for (const r of fn.sort((a, b) => b.score - a.score).slice(0, 25)) {
      console.log(`  [${r.score}] ${r.url}  ${r.topFindings.map((f) => `${f.ruleId}(${f.score})`).join(", ") || "(no signal)"}`);
    }
    if (fn.length > 25) console.log(`  ... and ${fn.length - 25} more`);
  }

  const fpRate = good.length ? fp.length / good.length : 0;
  const pass = fpRate <= MAX_FP_RATE;
  console.log(`\nGATE: false-positive rate ${pct(fp.length, good.length)} (max ${MAX_FP_RATE * 100}%) => ${pass ? "PASS" : "FAIL"}`);
  console.log("=============================================\n");
  if (!pass) process.exitCode = 1;
}

// ---- known-bad corpus (live) --------------------------------------------

async function loadBad(refresh: boolean, phishingOnly: boolean): Promise<string[]> {
  const cachePath = phishingOnly ? PHISHING_CACHE_PATH : CACHE_PATH;
  if (!refresh) {
    const cached = await readCacheIfFresh(cachePath);
    if (cached) {
      console.error(`using cached bad list (${cached.length} urls)`);
      return cached;
    }
  }
  console.error(`pulling live bad URLs (${phishingOnly ? "phishing-only" : "mixed"}) ...`);
  const candidates = shuffle(dedupe(await fetchBadCandidates(phishingOnly)));
  console.error(`  ${candidates.length} candidates; probing reachability ...`);
  const live = await probeReachable(candidates, TARGET_BAD);
  await writeFile(cachePath, `# pulled ${new Date().toISOString()}\n${live.join("\n")}\n`, "utf8");
  return live;
}

async function readCacheIfFresh(cachePath: string): Promise<string[] | null> {
  try {
    const text = await readFile(cachePath, "utf8");
    const stamp = text.match(/# pulled (.+)/)?.[1];
    if (!stamp || Date.now() - Date.parse(stamp) > CACHE_TTL_MS) return null;
    const urls = parseList(text);
    return urls.length ? urls : null;
  } catch {
    return null;
  }
}

async function fetchBadCandidates(phishingOnly: boolean): Promise<string[]> {
  const urls: string[] = [];
  // OpenPhish community feed (public, ~hundreds of fresh phishing URLs).
  try {
    const res = await fetch("https://openphish.com/feed.txt", { signal: AbortSignal.timeout(15000) });
    if (res.ok) urls.push(...parseList(await res.text()));
  } catch (error) {
    console.error("  openphish fetch failed:", error instanceof Error ? error.message : error);
  }
  if (phishingOnly) {
    // Phishing.Database active links (public, large list of currently-active
    // phishing URLs) — sampled, no auth.
    try {
      const res = await fetch("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt", { signal: AbortSignal.timeout(30000) });
      if (res.ok) urls.push(...parseList(await res.text()).filter((u) => u.startsWith("http")).slice(0, 4000));
    } catch (error) {
      console.error("  phishing.database fetch failed:", error instanceof Error ? error.message : error);
    }
    return urls;
  }
  // URLhaus online URLs (malware distribution). Auth-Key used if present.
  try {
    const headers: Record<string, string> = {};
    if (process.env.ABUSE_CH_AUTH_KEY) headers["Auth-Key"] = process.env.ABUSE_CH_AUTH_KEY;
    const res = await fetch("https://urlhaus.abuse.ch/downloads/csv_online/", { headers, signal: AbortSignal.timeout(20000) });
    if (res.ok) {
      for (const line of (await res.text()).split("\n")) {
        if (line.startsWith("#") || !line.trim()) continue;
        const fields = line.split('","').map((f) => f.replace(/^"|"$/g, ""));
        if (fields[3] === "online" && fields[2]?.startsWith("http")) urls.push(fields[2]);
      }
    }
  } catch (error) {
    console.error("  urlhaus fetch failed:", error instanceof Error ? error.message : error);
  }
  return urls;
}

async function probeReachable(candidates: string[], target: number): Promise<string[]> {
  const live: string[] = [];
  let i = 0;
  await pool(candidates, 12, async (url) => {
    if (live.length >= target) return;
    try {
      const res = await fetch(url, { headers: { "user-agent": BROWSER_UA }, redirect: "follow", signal: AbortSignal.timeout(8000) });
      if (res.status < 400) {
        const body = await res.text();
        if (body.length > 200 && live.length < target) live.push(url);
      }
    } catch {
      // dead/unreachable — skip
    }
    i += 1;
  });
  return live.slice(0, target);
}

// ---- helpers -------------------------------------------------------------

async function loadList(path: string): Promise<string[]> {
  return parseList(await readFile(resolve(path), "utf8"));
}
function parseList(text: string): string[] {
  return text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
}
function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}
function redactProxy(url: string): string {
  try {
    const u = new URL(url);
    return `${u.hostname}:${u.port}`;
  } catch {
    return "set";
  }
}
function shuffle<T>(values: T[]): T[] {
  // Index-based jitter (no Math.random dependency needed for a rough mix).
  return values
    .map((v, i) => ({ v, k: (i * 2654435761) % values.length }))
    .sort((a, b) => a.k - b.k)
    .map((x) => x.v);
}
function median(values: number[]): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}
function percentile(values: number[], p: number): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
}
async function pool<T>(items: T[], concurrency: number, worker: (item: T) => Promise<void>): Promise<void> {
  let index = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (index < items.length) {
      const item = items[index++];
      await worker(item);
    }
  });
  await Promise.all(runners);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
