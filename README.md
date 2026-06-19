# @q32/signal-scanner

Static web signal scanner with bounded streaming analyzers, URL extraction,
rule packs, scoring, and normalized JSON reports.

`@q32/signal-scanner` is a library first. It scans HTML, JavaScript, CSS, text,
SVG, JSON, archives, and selected binary content without requiring a browser or a
complete file in memory. Applications provide bytes and optional source metadata;
the scanner returns findings, extracted URLs, decoded artifacts, counters, a
score, and a disposition.

## Install

```bash
npm install @q32/signal-scanner
```

## Library Usage

```ts
import { createScanner } from "@q32/signal-scanner";

const scanner = createScanner({
  source: {
    url: "https://example.com/login",
    contentType: "text/html"
  }
});

scanner.feed(chunk);
const report = scanner.finish();
```

The scanner keeps bounded state: rolling text windows, line/column tracking,
tag/script context, URL/domain inventory, decoded artifact lineage, entropy
windows, and signal counters.

The default scanner does not submit forms, set cookies, open network
connections, or import Node-only modules.

## Report Shape

`scanner.finish()` returns:

```ts
interface ScannerReport {
  contentKind: "html" | "javascript" | "css" | "json" | "svg" | "text" | "unknown" | "archive" | "executable";
  findings: Finding[];
  urls: ExtractedUrl[];
  artifacts: ArtifactRecord[];
  score: number;
  disposition: "allow" | "warn" | "review" | "block";
  counters: Record<string, number>;
}
```

Findings include rule id, severity, confidence, score, title, description,
location, and rule metadata.

## Runtime Integration

The core library is runtime-portable. It is suitable for Node, Workers, queues,
crawlers, upload pipelines, and other systems that can feed bytes into the
scanner.

Cloudflare is only relevant if you choose to embed the library in a Cloudflare
runtime. The package does not require Cloudflare, and the Node CLI does not use
Cloudflare.

### TLS Metadata

TLS analysis belongs to the scanner, but TLS collection depends on the host
runtime. Pass collected metadata through `source.tls` when creating a scanner:

```ts
const scanner = createScanner({
  source: {
    url: "https://example.com",
    contentType: "text/html",
    tls: {
      authorized: true,
      issuer: "O=Google Trust Services, CN=WE1",
      subject: "CN=example.com",
      validFrom: "Jan 1 00:00:00 2026 GMT",
      validTo: "Mar 31 23:59:59 2026 GMT"
    }
  }
});
```

Node-compatible runtimes can use the optional helper:

```ts
import { collectTlsMetadata } from "@q32/signal-scanner/node-tls";

const tls = await collectTlsMetadata("https://example.com", { timeoutMs: 5000 });
```

The default scanner export does not import `node:tls`, so streaming analysis
stays portable to runtimes that only provide fetch/body streams.

## Dynamic Rendering

The library includes optional dynamic analysis helpers for rendering HTML with
`linkedom`, instrumenting browser-like APIs, recording behavior, and rescanning
the rendered DOM.

```ts
import { renderAndScan } from "@q32/signal-scanner/render";
```

`renderAndScan` runs in-process by default and is intended for trusted or
synthetic inputs unless you provide an isolate. The included Node CLI runs this
render step in `isolated-vm`, so untrusted page JavaScript cannot reach host
`fetch`, `process`, or `fs`.

Cloudflare users can provide their own isolate or Worker-based invocation when
embedding the library, but that is separate from the CLI.

## Node CLI

The package ships a `signal-scanner` binary for local URL checks, bounded
crawling, and artifact/file scanning.

```bash
npx @q32/signal-scanner crawl https://example.com
npx @q32/signal-scanner crawl --no-robots --parallel 10 --max-urls 50 --max-depth 2 https://example.com
npx @q32/signal-scanner files ./samples
```

After a global install (`npm i -g @q32/signal-scanner`) the same commands are
available as `signal-scanner crawl …`. Inside this repo, `npm run scan -- …`
runs the CLI from source.

The CLI uses Node APIs for fetching and file IO. Dynamic rendering runs page
JavaScript inside `isolated-vm`; `isolated-vm` and `esbuild` are
**optional dependencies**. A default `npm install` pulls them in, but if they
are unavailable (e.g. installed with `--no-optional`, or a build toolchain for
the `isolated-vm` native addon is missing) the CLI logs a notice and continues
with static analysis only.

Crawler behavior:

- GET requests only.
- Bounded redirects through `fetch`.
- Bounded bytes per response and bounded total bytes.
- Global URL dedupe.
- Registrable-domain crawl bounds for hostnames.
- Exact-host crawl bounds for IP-literal targets.
- Robots.txt and sitemap support by default.

CLI options:

- `--no-robots` skips fetching and obeying `robots.txt`. Root sitemap probes still run.
- `--parallel, -n <count>` sets bounded concurrent fetches. Default: `10`.
- `--max-urls <count>` caps globally deduped crawl URLs. Default: `128`.
- `--max-depth <count>` caps link-follow depth. Default: `2`.
- `--max-bytes <bytes>` caps bytes per response. Default: `524288`.
- `--max-total-bytes <bytes>` caps aggregate crawl bytes. Default: `33554432`.
- `--max-sitemap-urls <count>` caps accepted sitemap URLs. Default: `512`.
- `--timeout-ms <ms>` caps each request. Default: `10000`.
- `--user-agent <value>` sets the crawler user agent.
- `--max-file-bytes <bytes>` caps bytes per file in `files` mode.

The CLI prints a normalized JSON summary to stdout.

## Rule Coverage

- HTML signals for forms, password/payment fields, scripts, links, iframes,
  meta refresh redirects, hidden iframe patterns, login/payment language,
  page-model screenshot/login cues, crypto/DeFi landing language,
  trademark-stuffed SEO titles, and technology/dependency fingerprints.
- JavaScript text signals for dynamic execution, DOM injection sinks, dynamic
  script creation, decoder APIs, request APIs, redirect APIs, storage/cookie/
  clipboard access, wallet APIs, payment input hooks, and exfiltration
  candidates.
- CSS signals for remote imports/URLs, hidden/offscreen content, opacity tricks,
  invisible overlays, and unicode-bidi tricks.
- URL signals for punycode login URLs, URL shorteners, private/local targets,
  shared-hosting subdomains, suspicious TLDs, brand impersonation, generated
  landing URLs, and download-like targets.
- Decoder signals for bounded base64, JavaScript hex/unicode escapes, and
  `String.fromCharCode` literal artifacts, with recursive rescanning.
- Binary static signals for executable magic, declared content-type mismatch,
  executable-stack ELF headers, IoT botnet strings, router exploit strings,
  dropper commands, and DHT/CNC protocol strings.

## Scoring

Every rule has an explicit score model:

```ts
score: {
  base: 34,
  tags: ["credential", "phishing"],
  repeatMultiplier: 0.25,
  maxRepeats: 3
}
```

`severity` and `confidence` are report/display metadata. They do not drive
scoring. The scorer sums each rule's explicit `base`, applies each rule's repeat
policy, and then applies explicit tag-based context multipliers such as
credential plus suspicious hosting, wallet/payment plus exfiltration/redirect,
decoded artifact plus script behavior, or binary plus URL evidence.

## Development

Build and test:

```bash
npm run build
npm test
npm run coverage   # enforces an 80% line-coverage gate
```

The eval harness (`npm run eval`) measures the detector against a labeled corpus
of live known-good and known-bad sites. It is dev-only and not shipped in the
package. Because many ISPs intercept known-bad hosts (which tanks recall), it
can route its crawl through an outbound proxy configured via a local `.env`.
Copy `.env.example` to `.env` and fill in proxy credentials if you need this;
leave it unset to crawl directly. `.env` is gitignored — never commit
credentials.

## License

[GNU Lesser General Public License v3.0 or later](COPYING.LESSER) (LGPL-3.0-or-later).

Application code may link and use this library without itself becoming
LGPL/GPL; modifications to the library must be released under the LGPL. The
LGPL builds on the [GPL-3.0](COPYING); both license texts ship with the
package.
