import {
  rebuildFeed,
  writeFeedChunk,
  finalizeFeedShard,
  finalizeFeed,
  matchCachedFeeds,
  shardOf,
  scoreFor,
  parseUrlhausCsv,
  parseOpenPhishFeed,
  FEED_SCORE_ACTIVE,
  FEED_SCORE_AGED,
  type IntelStorage
} from "../src/feeds";

function memStorage(): IntelStorage & { keys(): string[] } {
  const map = new Map<string, Uint8Array>();
  return {
    keys: () => [...map.keys()],
    async get(k) {
      return map.get(k) ?? null;
    },
    async put(k, v) {
      map.set(k, v);
    },
    async list(p) {
      return [...map.keys()].filter((k) => k.startsWith(p));
    },
    async delete(k) {
      map.delete(k);
    }
  };
}

test("shardOf is deterministic and bucketed to two hex chars", () => {
  expect(shardOf("bad.example")).toBe(shardOf("BAD.EXAMPLE"));
  expect(shardOf("bad.example")).toMatch(/^[0-9a-f]{2}$/);
});

test("rebuild then match returns the highest score band a host falls in", async () => {
  const storage = memStorage();
  await rebuildFeed(
    storage,
    "openphish",
    "v1",
    [
      { host: "active.example", score: FEED_SCORE_ACTIVE },
      { host: "aged.example", score: FEED_SCORE_AGED }
    ],
    { source: "OpenPhish" }
  );

  const matches = await matchCachedFeeds(storage, ["active.example", "aged.example", "clean.example"]);
  const byHost = Object.fromEntries(matches.map((m) => [m.host, m.score]));
  expect(byHost["active.example"]).toBe(FEED_SCORE_ACTIVE);
  expect(byHost["aged.example"]).toBe(FEED_SCORE_AGED);
  expect(byHost["clean.example"]).toBeUndefined();
  expect(matches.find((m) => m.host === "active.example")?.source).toBe("OpenPhish");
});

test("a host in both bands matches at the stronger score", async () => {
  const storage = memStorage();
  await rebuildFeed(storage, "f", "v1", [
    { host: "dual.example", score: FEED_SCORE_AGED },
    { host: "dual.example", score: FEED_SCORE_ACTIVE }
  ]);
  const matches = await matchCachedFeeds(storage, ["dual.example"]);
  expect(matches).toHaveLength(1);
  expect(matches[0].score).toBe(FEED_SCORE_ACTIVE);
});

test("staged chunk + per-shard finalize merges partials across chunks", async () => {
  const storage = memStorage();
  const host = "phish.example";
  const band = FEED_SCORE_ACTIVE;
  await writeFeedChunk(storage, "pdb", "v2", "chunk-0", [{ host, score: band }]);
  await writeFeedChunk(storage, "pdb", "v2", "chunk-1", [{ host: "other.example", score: band }]);

  const prefix = shardOf(host);
  const count = await finalizeFeedShard(storage, "pdb", "v2", band, prefix);
  expect(count).toBeGreaterThanOrEqual(1);
  await finalizeFeed(storage, "pdb", "v2", { [String(band)]: 2 }, { source: "Phishing.Database" });

  const matches = await matchCachedFeeds(storage, [host]);
  expect(matches[0]?.host).toBe(host);
  expect(matches[0]?.score).toBe(band);
  // staging is swept on finalize
  expect(storage.keys().some((k) => k.includes("/staging/"))).toBe(false);
});

test("publishing a new version sweeps the previous one", async () => {
  const storage = memStorage();
  await rebuildFeed(storage, "f", "v1", [{ host: "old.example", score: FEED_SCORE_ACTIVE }]);
  await rebuildFeed(storage, "f", "v2", [{ host: "new.example", score: FEED_SCORE_ACTIVE }]);
  expect(await matchCachedFeeds(storage, ["old.example"])).toEqual([]);
  expect((await matchCachedFeeds(storage, ["new.example"]))[0]?.host).toBe("new.example");
  expect(storage.keys().some((k) => k.includes("/f/v1/"))).toBe(false);
});

test("URLhaus CSV scores online+recent high and offline/old lower", () => {
  const now = Date.parse("2026-06-01T00:00:00Z");
  const csv = [
    "# comment",
    '1,"2026-05-20 10:00:00","https://fresh.example/x","online","malware_download"',
    '2,"2020-01-01 10:00:00","https://stale.example/y","offline","malware_download"'
  ].join("\n");
  const entries = parseUrlhausCsv(csv, { now });
  const byHost = Object.fromEntries(entries.map((e) => [e.host, e.score]));
  expect(byHost["fresh.example"]).toBe(FEED_SCORE_ACTIVE);
  expect(byHost["stale.example"]).toBe(FEED_SCORE_AGED);
});

test("OpenPhish parser extracts hosts at the active score", () => {
  const entries = parseOpenPhishFeed("https://evil.example/login\n# x\nnot a url\nhttp://evil.example/2");
  expect(entries).toEqual([{ host: "evil.example", score: FEED_SCORE_ACTIVE }]);
  expect(scoreFor({ active: true })).toBe(FEED_SCORE_ACTIVE);
  expect(scoreFor({ active: false })).toBe(FEED_SCORE_AGED);
});
