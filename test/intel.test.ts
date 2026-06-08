import { checkUrlIntel, isPrivateOrLocalHost, intelTargetsFromUrls } from "../src/intel";

// A fetch stub keyed by URL substring so the suite is fully offline and
// runtime-agnostic — the same code path runs in Node and in a Worker.
function stubFetch(handlers: Array<{ match: string; status?: number; json: unknown }>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    const handler = handlers.find((h) => url.includes(h.match));
    if (!handler) return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify(handler.json), {
      status: handler.status ?? 200,
      headers: { "content-type": "application/json" }
    });
  }) as typeof fetch;
}

test("flags a known-bad host via URLhaus and produces a high-severity finding", async () => {
  const report = await checkUrlIntel(
    { urls: ["https://bad.example/payload.exe"] },
    {
      fetchImpl: stubFetch([
        { match: "urlhaus-api.abuse.ch/v1/host", json: { query_status: "ok", urls: [{ url: "https://bad.example/payload.exe" }] } },
        { match: "urlhaus-api.abuse.ch/v1/url", json: { query_status: "ok", threat: "malware_download", url_status: "online" } },
        { match: "threatfox-api.abuse.ch", json: { query_status: "no_result" } },
        { match: "safebrowsing.googleapis.com", json: {} }
      ]),
      googleSafeBrowsingKey: "test-key"
    }
  );

  const urlhaus = report.sources.find((s) => s.source === "urlhaus");
  expect(urlhaus?.status).toBe("match");
  expect(report.matches.length).toBeGreaterThan(0);
  expect(report.findings[0].severity).toBe("high");
  expect(report.findings[0].ruleId).toBe("intel.urlhaus");
  // Safe Browsing returns no matches here => clean, not error (key present).
  expect(report.sources.find((s) => s.source === "google-safebrowsing")?.status).toBe("clean");
});

test("reports Google Safe Browsing as an error when no key is configured", async () => {
  const report = await checkUrlIntel(
    { urls: ["https://example.com/"] },
    { fetchImpl: stubFetch([{ match: "abuse.ch", json: { query_status: "no_result" } }]) }
  );
  const gsb = report.sources.find((s) => s.source === "google-safebrowsing");
  expect(gsb?.status).toBe("error");
  expect(gsb?.reason).toMatch(/not configured/i);
});

test("surfaces a feed outage as an error rather than a clean result", async () => {
  const report = await checkUrlIntel(
    { hosts: ["host.example"] },
    {
      fetchImpl: (async () => new Response("boom", { status: 503 })) as typeof fetch,
      googleSafeBrowsingKey: "k"
    }
  );
  expect(report.sources.find((s) => s.source === "urlhaus")?.status).toBe("error");
  expect(report.matches).toEqual([]);
});

test("returns nothing when disabled and never calls fetch", async () => {
  let called = false;
  const report = await checkUrlIntel(
    { urls: ["https://example.com/"] },
    { disabled: true, fetchImpl: (async () => { called = true; return new Response("{}"); }) as typeof fetch }
  );
  expect(report.sources).toEqual([]);
  expect(report.findings).toEqual([]);
  expect(called).toBe(false);
});

test("skips private/local hosts and derives targets from a url inventory", () => {
  expect(isPrivateOrLocalHost("127.0.0.1")).toBe(true);
  expect(isPrivateOrLocalHost("10.2.3.4")).toBe(true);
  expect(isPrivateOrLocalHost("example.com")).toBe(false);
  const targets = intelTargetsFromUrls([{ normalized: "https://a.example/x" }, { normalized: "https://a.example/y" }]);
  expect(targets.hosts).toEqual(["a.example"]);
  expect(targets.urls.length).toBe(2);
});
