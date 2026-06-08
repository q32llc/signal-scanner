// URL threat-intelligence correlation for the signal scanner.
//
// Runtime-agnostic: depends only on the WHATWG `fetch`, `URL`, and standard
// timers, so it runs unchanged in Node and in Cloudflare Workers. Everything
// environment-specific (the fetch implementation, API keys, bounds) is injected
// through `UrlIntelConfig` — there are no `process.env` or node imports here.
//
// It takes the URLs/hosts a scan discovered, correlates them against open and
// keyed reputation sources, and returns both normalized scanner `Finding`s and a
// per-source result so callers can show which feeds ran, matched, or failed.

import type { Finding, Severity, Confidence } from "./index";
import type { RuleScoreModel } from "./rules/types";

export interface UrlIntelConfig {
  /** Fetch implementation. Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Google Safe Browsing API key. When absent, that source reports an error. */
  googleSafeBrowsingKey?: string;
  /** Skip all network calls and return no sources (e.g. non-production). */
  disabled?: boolean;
  /** Max distinct hosts queried per host-based source. Default 100. */
  maxHosts?: number;
  /** Max distinct URLs queried per URL-based source. Default 100. */
  maxUrls?: number;
  /** Per-request timeout in milliseconds. Default 4000. */
  timeoutMs?: number;
  /** User-Agent sent with feed requests. */
  userAgent?: string;
}

export type IntelSourceStatus = "match" | "clean" | "error";

export interface IntelMatch {
  /** Stable source id, e.g. "urlhaus", "threatfox", "google-safebrowsing". */
  source: string;
  /** Human-readable provider name. */
  provider: string;
  url?: string;
  host?: string;
  detail: Record<string, unknown>;
}

export interface IntelSourceResult {
  source: string;
  provider: string;
  status: IntelSourceStatus;
  reason?: string;
  urlsChecked: number;
  hostsChecked: number;
  matches: IntelMatch[];
}

export interface UrlIntelReport {
  sources: IntelSourceResult[];
  matches: IntelMatch[];
  findings: Finding[];
}

export interface UrlIntelInput {
  urls?: string[];
  hosts?: string[];
}

interface IntelContext {
  fetch: typeof fetch;
  timeoutMs: number;
  userAgent: string;
  googleSafeBrowsingKey?: string;
}

interface IntelSource {
  source: string;
  provider: string;
  run(input: { urls: string[]; hosts: string[] }, ctx: IntelContext): Promise<IntelSourceResult>;
}

const DEFAULT_MAX_HOSTS = 100;
const DEFAULT_MAX_URLS = 100;
const DEFAULT_TIMEOUT_MS = 4000;
const DEFAULT_USER_AGENT = "q32-signal-scanner/0.1";

/**
 * Correlate discovered URLs/hosts against threat-intelligence sources.
 * Never throws for individual source failures — a failed source is reported
 * with `status: "error"` so callers can surface it instead of treating a feed
 * outage as a clean result.
 */
export async function checkUrlIntel(input: UrlIntelInput, config: UrlIntelConfig = {}): Promise<UrlIntelReport> {
  const maxHosts = config.maxHosts ?? DEFAULT_MAX_HOSTS;
  const maxUrls = config.maxUrls ?? DEFAULT_MAX_URLS;
  const urls = dedupe(input.urls ?? []).slice(0, maxUrls);
  const hosts = dedupe([...(input.hosts ?? []), ...hostsFromUrls(urls)]).slice(0, maxHosts);

  if (config.disabled) {
    return { sources: [], matches: [], findings: [] };
  }

  const ctx: IntelContext = {
    fetch: config.fetchImpl ?? globalThis.fetch,
    timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    userAgent: config.userAgent ?? DEFAULT_USER_AGENT,
    googleSafeBrowsingKey: config.googleSafeBrowsingKey
  };

  const sources = await Promise.all(INTEL_SOURCES.map((source) => source.run({ urls, hosts }, ctx)));
  const matches = sources.flatMap((source) => source.matches);
  const findings = matches.map((match, index) => findingForMatch(match, index));
  return { sources, matches, findings };
}

/** Derive intel targets (urls + registrable hosts) from a scanner report's URL inventory. */
export function intelTargetsFromUrls(urls: Array<{ normalized: string }>): { urls: string[]; hosts: string[] } {
  const normalized = urls.map((url) => url.normalized).filter(Boolean);
  return { urls: dedupe(normalized), hosts: dedupe(hostsFromUrls(normalized)) };
}

const INTEL_SOURCES: IntelSource[] = [
  {
    source: "urlhaus",
    provider: "URLhaus",
    async run(input, ctx) {
      const base = { source: "urlhaus", provider: "URLhaus" };
      const matches: IntelMatch[] = [];
      let lastError: string | undefined;
      for (const host of input.hosts) {
        const r = await guarded(() => queryUrlhausHost(host, ctx));
        if (r.error) lastError = r.error;
        else if (r.value) matches.push(r.value);
      }
      for (const url of input.urls) {
        const r = await guarded(() => queryUrlhausUrl(url, ctx));
        if (r.error) lastError = r.error;
        else if (r.value) matches.push(r.value);
      }
      return settle(base, input.urls.length, input.hosts.length, matches, lastError);
    }
  },
  {
    source: "threatfox",
    provider: "ThreatFox",
    async run(input, ctx) {
      const base = { source: "threatfox", provider: "ThreatFox" };
      const matches: IntelMatch[] = [];
      let lastError: string | undefined;
      for (const host of input.hosts) {
        const r = await guarded(() => queryThreatFoxHost(host, ctx));
        if (r.error) lastError = r.error;
        else if (r.value) matches.push(r.value);
      }
      return settle(base, 0, input.hosts.length, matches, lastError);
    }
  },
  {
    source: "google-safebrowsing",
    provider: "Google Safe Browsing",
    async run(input, ctx) {
      const base = { source: "google-safebrowsing", provider: "Google Safe Browsing" };
      if (!ctx.googleSafeBrowsingKey) {
        return { ...base, status: "error", reason: "Google Safe Browsing key not configured", urlsChecked: input.urls.length, hostsChecked: 0, matches: [] };
      }
      const r = await guarded(() => queryGoogleSafeBrowsing(input.urls, ctx));
      if (r.error) {
        return { ...base, status: "error", reason: r.error, urlsChecked: input.urls.length, hostsChecked: 0, matches: [] };
      }
      const matches = (r.value as IntelMatch[] | null) ?? [];
      return settle(base, input.urls.length, 0, matches, undefined);
    }
  }
];

function settle(
  base: { source: string; provider: string },
  urlsChecked: number,
  hostsChecked: number,
  matches: IntelMatch[],
  errorReason: string | undefined
): IntelSourceResult {
  if (matches.length) return { ...base, status: "match", urlsChecked, hostsChecked, matches };
  if (errorReason) return { ...base, status: "error", reason: errorReason, urlsChecked, hostsChecked, matches: [] };
  return { ...base, status: "clean", urlsChecked, hostsChecked, matches: [] };
}

async function guarded<T>(query: () => Promise<T>): Promise<{ value?: T; error?: string }> {
  try {
    return { value: await query() };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "lookup failed" };
  }
}

// ---- Sources -------------------------------------------------------------

async function queryUrlhausHost(host: string, ctx: IntelContext): Promise<IntelMatch | null> {
  if (isPrivateOrLocalHost(host)) return null;
  const response = await postForm("https://urlhaus-api.abuse.ch/v1/host/", { host }, ctx);
  if (!response || response.query_status !== "ok") return null;
  return {
    source: "urlhaus",
    provider: "URLhaus",
    host,
    detail: {
      query_status: response.query_status,
      url_count: Array.isArray(response.urls) ? response.urls.length : 0,
      sample: Array.isArray(response.urls) ? response.urls.slice(0, 5) : []
    }
  };
}

async function queryUrlhausUrl(url: string, ctx: IntelContext): Promise<IntelMatch | null> {
  const host = hostOf(url);
  if (!host || isPrivateOrLocalHost(host)) return null;
  const response = await postForm("https://urlhaus-api.abuse.ch/v1/url/", { url }, ctx);
  if (!response || response.query_status !== "ok") return null;
  return {
    source: "urlhaus",
    provider: "URLhaus",
    url,
    host,
    detail: {
      query_status: response.query_status,
      threat: response.threat,
      url_status: response.url_status,
      tags: Array.isArray(response.tags) ? response.tags : []
    }
  };
}

async function queryThreatFoxHost(host: string, ctx: IntelContext): Promise<IntelMatch | null> {
  if (isPrivateOrLocalHost(host)) return null;
  const response = await postJson("https://threatfox-api.abuse.ch/api/v1/", { query: "search_ioc", search_term: host }, ctx);
  if (!response || response.query_status !== "ok") return null;
  return {
    source: "threatfox",
    provider: "ThreatFox",
    host,
    detail: {
      query_status: response.query_status,
      ioc_count: Array.isArray(response.data) ? response.data.length : 0,
      sample: Array.isArray(response.data) ? response.data.slice(0, 5) : []
    }
  };
}

// One batched request covers every discovered URL.
async function queryGoogleSafeBrowsing(urls: string[], ctx: IntelContext): Promise<IntelMatch[]> {
  const entries = urls.filter((url) => {
    const host = hostOf(url);
    return host && !isPrivateOrLocalHost(host);
  });
  if (!entries.length) return [];
  const response = await postJson(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(ctx.googleSafeBrowsingKey ?? "")}`,
    {
      client: { clientId: "q32-signal-scanner", clientVersion: "0.1" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: entries.slice(0, 500).map((url) => ({ url }))
      }
    },
    ctx
  );
  if (!response || !Array.isArray(response.matches)) return [];
  return response.matches.map((match: any) => ({
    source: "google-safebrowsing",
    provider: "Google Safe Browsing",
    url: typeof match?.threat?.url === "string" ? match.threat.url : undefined,
    host: hostOf(String(match?.threat?.url ?? "")) ?? undefined,
    detail: {
      threat_type: match?.threatType,
      platform_type: match?.platformType,
      cache_duration: match?.cacheDuration
    }
  }));
}

// ---- Findings ------------------------------------------------------------

const INTEL_SCORE: RuleScoreModel = { base: 95, tags: ["hosting", "url"] };

function findingForMatch(match: IntelMatch, index: number): Finding {
  const locationValue = match.url ?? match.host ?? "unknown";
  const ruleId = `intel.${match.source}`;
  return {
    id: `${ruleId}:${index}`,
    ruleId,
    severity: "high" as Severity,
    confidence: "high" as Confidence,
    score: INTEL_SCORE.base,
    scoreModel: INTEL_SCORE,
    title: `Known-bad ${match.url ? "URL" : "host"} flagged by ${match.provider}`,
    description: `${match.provider} threat intelligence matched a crawled ${match.url ? "URL" : "host"}.`,
    locationType: "url",
    locationValue,
    metadata: { intel_source: match.source, provider: match.provider, host: match.host, url: match.url, ...match.detail }
  };
}

// ---- HTTP + host helpers -------------------------------------------------

async function postForm(url: string, body: Record<string, string>, ctx: IntelContext): Promise<Record<string, any> | null> {
  const response = await ctx.fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": ctx.userAgent },
    body: new URLSearchParams(body),
    signal: AbortSignal.timeout(ctx.timeoutMs)
  });
  if (!response.ok) throw new Error(`${url} responded ${response.status}`);
  const parsed = await response.json();
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, any>) : null;
}

async function postJson(url: string, body: Record<string, unknown>, ctx: IntelContext): Promise<Record<string, any> | null> {
  const response = await ctx.fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": ctx.userAgent },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(ctx.timeoutMs)
  });
  if (!response.ok) throw new Error(`${url} responded ${response.status}`);
  const parsed = await response.json();
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, any>) : null;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function hostsFromUrls(urls: string[]): string[] {
  const hosts: string[] = [];
  for (const url of urls) {
    const host = hostOf(url);
    if (host) hosts.push(host);
  }
  return hosts;
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export function isPrivateOrLocalHost(host: string): boolean {
  const lower = host.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".localhost") || lower.endsWith(".local")) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(lower)) {
    const parts = lower.split(".").map(Number);
    return (
      parts[0] === 10 ||
      parts[0] === 127 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 169 && parts[1] === 254)
    );
  }
  return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80");
}
