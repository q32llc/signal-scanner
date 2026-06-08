// Cached blocklist-feed index for the signal scanner.
//
// Runtime-agnostic: all persistence goes through an injected `IntelStorage`
// (R2 in a Worker, the filesystem in a CLI, an in-memory map in tests). The
// scanner never knows where bytes live.
//
// Feeds can be millions of entries, far too large to hold in a Worker, so the
// index is sharded by a stable host bucket (`shardOf`) into small files. The
// match path fetches only the few shards a scan actually needs.
//
// Evidence strength is a numeric score (the lib's native currency), decided at
// ingest and encoded by which score-band shard family a host lands in — so
// shard files stay compact host arrays. Recent/active/evidence-backed entries
// get a high score; aged/weak entries a lower one. Matching returns the highest
// band a host appears in; the caller turns that score into a finding severity
// via the usual scoring helpers.

export interface IntelStorage {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, value: Uint8Array): Promise<void>;
  list(prefix: string): Promise<string[]>;
  delete?(key: string): Promise<void>;
}

export interface FeedEntry {
  host: string;
  score: number;
}

export interface FeedMeta {
  source?: string;
  generatedAt?: string;
}

export interface FeedRecord extends FeedMeta {
  version: string;
  /** Distinct score bands present in this version, and the host count in each. */
  bands: Record<string, number>;
}

export interface GlobalFeedManifest {
  feeds: Record<string, FeedRecord>;
}

export interface CachedFeedMatch {
  feedId: string;
  host: string;
  score: number;
  source?: string;
}

/** Default score bands. Callers may use any integer band; these are conventions. */
export const FEED_SCORE_ACTIVE = 90; // live / recent / evidence-backed
export const FEED_SCORE_AGED = 55; // historical / weak / unverified

const ROOT = "feeds";
const GLOBAL_MANIFEST_KEY = `${ROOT}/manifest.json`;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** All 256 shard prefixes ("00".."ff"); a staged build finalizes one per job. */
export const SHARD_PREFIXES: string[] = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

/** Stable, synchronous host -> shard bucket. FNV-1a low byte; loader and matcher must agree. */
export function shardOf(host: string): string {
  let hash = 0x811c9dc5;
  const lower = host.toLowerCase();
  for (let i = 0; i < lower.length; i++) {
    hash ^= lower.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return ((hash >>> 0) & 0xff).toString(16).padStart(2, "0");
}

/** Score a feed entry from its evidence: active/recent => high, else aged/weak. */
export function scoreFor(input: {
  active?: boolean;
  addedAt?: string | null;
  recencyDays?: number;
  now?: number;
  activeScore?: number;
  agedScore?: number;
}): number {
  const recencyDays = input.recencyDays ?? 90;
  const now = input.now ?? Date.parse(new Date().toISOString());
  const recent = input.addedAt ? now - Date.parse(input.addedAt) <= recencyDays * 86_400_000 : true;
  return input.active !== false && recent ? input.activeScore ?? FEED_SCORE_ACTIVE : input.agedScore ?? FEED_SCORE_AGED;
}

// ---- Small feeds: full rebuild in one pass --------------------------------

/** Rebuild a feed's shard index from a complete entry set (feeds that fit in memory). */
export async function rebuildFeed(
  storage: IntelStorage,
  feedId: string,
  version: string,
  entries: FeedEntry[],
  meta: FeedMeta = {}
): Promise<FeedRecord> {
  const buckets = bucketEntries(dedupeEntries(entries));
  const bands: Record<string, number> = {};
  for (const [band, prefixes] of buckets) {
    for (const [prefix, hosts] of prefixes) {
      await putJson(storage, shardKey(feedId, version, band, prefix), [...hosts]);
      bands[band] = (bands[band] ?? 0) + hosts.size;
    }
  }
  return finalizeFeed(storage, feedId, version, bands, meta);
}

// ---- Huge feeds: staged chunk + per-shard merge ---------------------------

/** Write one download chunk's parsed entries to staging. Safe to run many in parallel. */
export async function writeFeedChunk(
  storage: IntelStorage,
  feedId: string,
  version: string,
  chunkId: string,
  entries: FeedEntry[]
): Promise<void> {
  const buckets = bucketEntries(entries);
  for (const [band, prefixes] of buckets) {
    for (const [prefix, hosts] of prefixes) {
      await putJson(storage, stagingKey(feedId, version, chunkId, band, prefix), [...hosts]);
    }
  }
}

/** Merge every chunk's partials for one (band, prefix) into the final shard. One job per shard. */
export async function finalizeFeedShard(
  storage: IntelStorage,
  feedId: string,
  version: string,
  band: number,
  prefix: string
): Promise<number> {
  // Staging is keyed band/prefix/chunk, so this lists only the chunks for this
  // one shard rather than scanning the whole staging tree.
  const shardStaging = `${ROOT}/${feedId}/${version}/staging/${band}/${prefix}/`;
  const merged = new Set<string>();
  for (const key of await storage.list(shardStaging)) {
    for (const host of await readArray(storage, key)) merged.add(host);
  }
  if (merged.size) await putJson(storage, shardKey(feedId, version, String(band), prefix), [...merged]);
  return merged.size;
}

/** Publish the feed: write its manifest, register it globally, and sweep staging + old versions. */
export async function finalizeFeed(
  storage: IntelStorage,
  feedId: string,
  version: string,
  bands: Record<string, number>,
  meta: FeedMeta = {}
): Promise<FeedRecord> {
  const record: FeedRecord = {
    version,
    bands,
    source: meta.source,
    generatedAt: meta.generatedAt ?? new Date().toISOString()
  };
  await putJson(storage, `${ROOT}/${feedId}/${version}/manifest.json`, record);

  const manifest = (await readJson<GlobalFeedManifest>(storage, GLOBAL_MANIFEST_KEY)) ?? { feeds: {} };
  const previous = manifest.feeds[feedId]?.version;
  manifest.feeds[feedId] = record;
  await putJson(storage, GLOBAL_MANIFEST_KEY, manifest);

  await sweep(storage, `${ROOT}/${feedId}/${version}/staging/`);
  if (previous && previous !== version) await sweep(storage, `${ROOT}/${feedId}/${previous}/`);
  return record;
}

// ---- Match path -----------------------------------------------------------

/** Match candidate hosts against all published feeds, returning the highest score band per hit. */
export async function matchCachedFeeds(storage: IntelStorage, hosts: string[]): Promise<CachedFeedMatch[]> {
  const manifest = await readJson<GlobalFeedManifest>(storage, GLOBAL_MANIFEST_KEY);
  if (!manifest) return [];
  const uniqueHosts = [...new Set(hosts.map((host) => host.toLowerCase()).filter(Boolean))];
  const shardCache = new Map<string, Set<string>>();
  const matches: CachedFeedMatch[] = [];

  for (const [feedId, record] of Object.entries(manifest.feeds)) {
    const bands = Object.keys(record.bands)
      .map(Number)
      .sort((a, b) => b - a); // highest score first
    for (const host of uniqueHosts) {
      const prefix = shardOf(host);
      for (const band of bands) {
        const key = shardKey(feedId, record.version, String(band), prefix);
        let set = shardCache.get(key);
        if (!set) {
          set = new Set(await readArray(storage, key));
          shardCache.set(key, set);
        }
        if (set.has(host)) {
          matches.push({ feedId, host, score: band, source: record.source });
          break; // strongest band wins for this host
        }
      }
    }
  }
  return matches;
}

// ---- Parsers (lib owns the format; the app handles byte/line chunking) -----

/** Extract a lowercase host from a URL or bare host line; null for comments/blanks. */
export function hostFromLine(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!")) return null;
  const candidate = trimmed.includes("://") ? trimmed : `http://${trimmed.split(/\s+/)[0]}`;
  try {
    const host = new URL(candidate).hostname.toLowerCase();
    // Real domains/IPv4 always contain a dot; reject single-label junk lines.
    return host && host.includes(".") ? host : null;
  } catch {
    return null;
  }
}

/** OpenPhish community feed: one active phishing URL per line. */
export function parseOpenPhishFeed(text: string, score = FEED_SCORE_ACTIVE): FeedEntry[] {
  return dedupeEntries(linesOf(text).map(hostFromLine).filter(isHost).map((host) => ({ host, score })));
}

/** A bare domain/host blocklist (e.g. Phishing.Database lists) at a caller-chosen score. */
export function parseHostList(text: string, score: number): FeedEntry[] {
  return dedupeEntries(linesOf(text).map(hostFromLine).filter(isHost).map((host) => ({ host, score })));
}

/** URLhaus CSV (id,dateadded,url,url_status,...): online+recent scores high, else aged. */
export function parseUrlhausCsv(text: string, opts: { recencyDays?: number; now?: number } = {}): FeedEntry[] {
  const entries: FeedEntry[] = [];
  for (const line of linesOf(text)) {
    if (!line || line.startsWith("#")) continue;
    const cols = parseCsvRow(line);
    if (cols.length < 4) continue;
    const host = hostFromLine(cols[2]);
    if (!host) continue;
    entries.push({ host, score: scoreFor({ active: cols[3] === "online", addedAt: cols[1], recencyDays: opts.recencyDays, now: opts.now }) });
  }
  return dedupeEntries(entries);
}

// ---- internals ------------------------------------------------------------

function shardKey(feedId: string, version: string, band: string, prefix: string): string {
  return `${ROOT}/${feedId}/${version}/${band}/${prefix}.json`;
}

function stagingKey(feedId: string, version: string, chunkId: string, band: string, prefix: string): string {
  // band/prefix first so a single shard's chunks share a narrow list prefix.
  return `${ROOT}/${feedId}/${version}/staging/${band}/${prefix}/${chunkId}.json`;
}

// score band (string) -> shard prefix -> hosts
function bucketEntries(entries: FeedEntry[]): Map<string, Map<string, Set<string>>> {
  const buckets = new Map<string, Map<string, Set<string>>>();
  for (const entry of entries) {
    const host = entry.host.toLowerCase();
    if (!host) continue;
    const band = String(entry.score);
    let prefixes = buckets.get(band);
    if (!prefixes) buckets.set(band, (prefixes = new Map()));
    const prefix = shardOf(host);
    let set = prefixes.get(prefix);
    if (!set) prefixes.set(prefix, (set = new Set()));
    set.add(host);
  }
  return buckets;
}

function dedupeEntries(entries: FeedEntry[]): FeedEntry[] {
  // Keep the strongest score when a host appears more than once.
  const scoreByHost = new Map<string, number>();
  for (const { host, score } of entries) {
    scoreByHost.set(host, Math.max(scoreByHost.get(host) ?? 0, score));
  }
  return [...scoreByHost].map(([host, score]) => ({ host, score }));
}

function isHost(value: string | null): value is string {
  return typeof value === "string" && value.length > 0;
}

function linesOf(text: string): string[] {
  return text.split(/\r?\n/);
}

function parseCsvRow(line: string): string[] {
  const cols: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; } else inQuotes = !inQuotes;
    } else if (char === "," && !inQuotes) {
      cols.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  cols.push(current);
  return cols;
}

async function putJson(storage: IntelStorage, key: string, value: unknown): Promise<void> {
  await storage.put(key, encoder.encode(JSON.stringify(value)));
}

async function readJson<T>(storage: IntelStorage, key: string): Promise<T | null> {
  const bytes = await storage.get(key);
  if (!bytes) return null;
  try {
    return JSON.parse(decoder.decode(bytes)) as T;
  } catch {
    return null;
  }
}

async function readArray(storage: IntelStorage, key: string): Promise<string[]> {
  const value = await readJson<string[]>(storage, key);
  return Array.isArray(value) ? value : [];
}

async function sweep(storage: IntelStorage, prefix: string): Promise<void> {
  if (!storage.delete) return;
  for (const key of await storage.list(prefix)) await storage.delete(key);
}
