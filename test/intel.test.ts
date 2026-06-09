import { checkUrlIntel, isPrivateOrLocalHost, isMultiTenantHost, intelTargetsFromUrls } from "../src/intel";

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

const recentDate = new Date(Date.now() - 5 * 86_400_000).toISOString();
const agedDate = "2023-01-15 09:00:00 UTC";

test("flags a known-bad host via URLhaus and produces a high-severity finding", async () => {
  const report = await checkUrlIntel(
    { urls: ["https://bad.example/payload.exe"] },
    {
      fetchImpl: stubFetch([
        // A live, recently-listed URL on the host is a strong conviction.
        { match: "urlhaus-api.abuse.ch/v1/host", json: { query_status: "ok", urls: [{ url: "https://bad.example/payload.exe", url_status: "online", date_added: recentDate }] } },
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

test("a dead, years-old URLhaus listing on a host is weak signal, not a conviction", async () => {
  const report = await checkUrlIntel(
    { hosts: ["www.google.com"] },
    {
      fetchImpl: stubFetch([
        // An offline URL added years ago (e.g. an abused open redirect) must not
        // convict an otherwise-legitimate host.
        { match: "urlhaus-api.abuse.ch/v1/host", json: { query_status: "ok", urls: [{ url: "https://www.google.com/url?q=https://bad.example/x", url_status: "offline", date_added: agedDate }] } },
        { match: "threatfox-api.abuse.ch", json: { query_status: "no_result" } },
        { match: "safebrowsing.googleapis.com", json: {} }
      ]),
      googleSafeBrowsingKey: "k"
    }
  );
  const match = report.matches.find((m) => m.source === "urlhaus");
  expect(match?.score).toBeLessThan(40);
  expect(match?.detail.score_basis).toBe("offline_aged");
  // No finding should be high/medium severity off this weak evidence.
  expect(report.findings.every((f) => f.severity === "low" || f.severity === "info")).toBe(true);
});

test("ThreatFox substring hits on a famous brand do not convict the brand host", async () => {
  const data = [
    { ioc: "guard-google.com", ioc_type: "domain", malware_printable: "IClickFix" },
    { ioc: "google.com-x18-206-188-196-165.sslip.io", ioc_type: "domain", malware_printable: "MintsLoader" },
    { ioc: "https://drive.google.com/uc?export=download&id=abc", ioc_type: "url", malware_printable: "GuLoader" }
  ];
  const report = await checkUrlIntel(
    { hosts: ["google.com"] },
    {
      fetchImpl: stubFetch([
        { match: "urlhaus-api.abuse.ch/v1/host", json: { query_status: "no_result" } },
        { match: "threatfox-api.abuse.ch", json: { query_status: "ok", data } },
        { match: "safebrowsing.googleapis.com", json: {} }
      ]),
      googleSafeBrowsingKey: "k"
    }
  );
  // None of the IOCs are exactly google.com, so ThreatFox is clean.
  expect(report.sources.find((s) => s.source === "threatfox")?.status).toBe("clean");
  expect(report.matches.filter((m) => m.source === "threatfox")).toEqual([]);
});

test("ThreatFox convicts when a domain IOC exactly matches the queried host", async () => {
  const data = [{ ioc: "evil.example", ioc_type: "domain", malware_printable: "Cobalt Strike" }];
  const report = await checkUrlIntel(
    { hosts: ["evil.example"] },
    {
      fetchImpl: stubFetch([
        { match: "urlhaus-api.abuse.ch/v1/host", json: { query_status: "no_result" } },
        { match: "threatfox-api.abuse.ch", json: { query_status: "ok", data } },
        { match: "safebrowsing.googleapis.com", json: {} }
      ]),
      googleSafeBrowsingKey: "k"
    }
  );
  const tf = report.sources.find((s) => s.source === "threatfox");
  expect(tf?.status).toBe("match");
  expect(tf?.matches[0]?.detail.ioc_count).toBe(1);
});

test("a malicious object in a shared bucket does not convict a site that loads from it", async () => {
  let hostQueried = false;
  const report = await checkUrlIntel(
    // The site loads an asset from a shared bucket; it does NOT load the bad object.
    { hosts: ["storage.googleapis.com"], urls: ["https://storage.googleapis.com/acme-assets/app.js"] },
    {
      fetchImpl: stubFetch([
        // If queried by host, the bucket looks live-malicious (another tenant's object).
        { match: "urlhaus-api.abuse.ch/v1/host", json: { query_status: "ok", urls: [{ url: "https://storage.googleapis.com/evil-bucket/payload.exe", url_status: "online", date_added: recentDate }] } },
        // The exact asset the site loads is clean.
        { match: "urlhaus-api.abuse.ch/v1/url", json: { query_status: "no_result" } },
        { match: "threatfox-api.abuse.ch", json: { query_status: "no_result" } },
        { match: "safebrowsing.googleapis.com", json: {} }
      ]),
      googleSafeBrowsingKey: "k"
    }
  );
  expect(isMultiTenantHost("storage.googleapis.com")).toBe(true);
  expect(isMultiTenantHost("d111.cloudfront.net")).toBe(true);
  expect(isMultiTenantHost("evil.example")).toBe(false);
  // No host-level conviction off the shared bucket; the exact loaded URL was clean.
  expect(report.matches.filter((m) => m.source === "urlhaus")).toEqual([]);
  expect(report.sources.find((s) => s.source === "urlhaus")?.status).toBe("clean");
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
