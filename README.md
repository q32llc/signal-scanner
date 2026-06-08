# @q32/signal-scanner

Open-source static web and source-code signal scanner with bounded streaming analyzers, extractors, rule packs, scoring, and normalized reports.

This package is intentionally independent from testvirus.org orchestration, uploads, Fly machines, D1, R2, and Cloudflare Workers. It is the scanner. Applications can embed it in crawlers, file pipelines, queues, Workers, CLIs, or other fetch systems.

## Architecture

Plain pipeline:

```text
Fetcher -> Content Detector -> Stream Scanner -> Extractors -> Normalizers -> Rule Engine -> Scorer -> Reporter
```

Crawler pipeline:

```text
Start URL -> fetch page -> stream HTML scanner -> extract links/scripts/forms/iframes/redirects -> enqueue allowed assets -> scan each asset -> aggregate findings by site
```

File pipeline:

```text
File or archive -> detect file type -> stream content -> scan -> extract referenced URLs -> aggregate findings
```

## Current API

```ts
import { createScanner } from "@q32/signal-scanner";

const scanner = createScanner({
  source: { url: "https://example.com/login", contentType: "text/html" }
});

scanner.feed(chunk);
const report = scanner.finish();
```

The scanner keeps bounded state: rolling text windows, line/column tracking, tag/script context, URL/domain inventory, decoded artifact lineage, entropy windows, and signal counters.

It does not submit forms, execute JavaScript, set cookies, or require a full file.

## Node CLI

The package includes a small Node CLI for local checks and corpus testing. It is intentionally separate from any Worker queue, upload, R2, D1, or Fly-machine orchestration.

```bash
npx tsx scripts/scan.ts crawl https://example.com
npx tsx scripts/scan.ts crawl --no-robots --parallel 10 --max-urls 50 --max-depth 2 https://example.com
npx tsx scripts/scan.ts files ./src
```

The crawler is static: GET requests only, no JavaScript execution, no cookies, bounded redirects through `fetch`, bounded bytes per response, bounded total bytes, and global URL dedupe. Crawls are bounded to the registrable domain of the submitted URL, with exact-host bounds for IP-literal targets.

Crawler options:

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

When robots are enabled, the crawler reads `Sitemap:` directives and also probes common root sitemap paths: `/sitemap.xml`, `/sitemap_index.xml`, and `/sitemap-index.xml`.

## Implemented Components

- Content detector for HTML, JavaScript, CSS, JSON, SVG, text, unknown, and archive content.
- URL/domain extractor with normalization, relative URL resolution, registrable-domain comparison, scheme classification, IP/private-host detection, punycode flags, shortener flags, suspicious-TLD flags, and download-like path flags.
- HTML analyzer for forms, password/payment fields, scripts, links, iframes, meta refresh redirects, hidden iframe patterns, login/payment language, and technology/dependency surface fingerprints.
- JavaScript text analyzer for dynamic execution, DOM injection sinks, dynamic script creation, decoder APIs, request APIs, redirect APIs, storage/cookie/clipboard access, wallet APIs, payment input hooks, and exfiltration candidates.
- CSS analyzer for remote imports/URLs, hidden/offscreen content, opacity tricks, invisible overlays, and unicode-bidi tricks.
- Normalizer/decoder for high-confidence bounded base64, JavaScript hex/unicode escapes, and `String.fromCharCode` literal artifacts, with recursive rescanning.
- Binary static analyzer for executable magic, declared content-type mismatch, executable-stack ELF headers, and IoT botnet/dropper strings.
- Source-code rule signals for hardcoded secret candidates, webhook URLs, child process execution, curl-pipe-shell, install lifecycle scripts, non-literal require/RegExp, sensitive file reads, private key material, weak crypto, and template escaping disabled.
- Rule/scoring/report output with severity, confidence, score, disposition, findings, extracted URLs, decoded artifacts, and counters.

## Rule Packs

Rules live under `src/rules/packs/`:

- `html.ts` for phishing, credential forms, payment forms, iframes, external scripts, mixed content, meta refresh redirects, dependency fingerprints, and web technology fingerprints.
- `script-risk.ts` for dynamic execution, DOM injection sinks, dynamic script loading, redirect APIs, request APIs, browser storage/cookie access, decoder APIs, wallet APIs, payment hooks, and composite script risks.
- `source-code.ts` for source-code risk signals such as hardcoded secret candidates, webhook URLs, child process execution, curl-pipe-shell, install scripts, non-literal require/RegExp, sensitive file reads, private keys, weak crypto, and template escaping disabled.
- `css.ts` for remote imports, hidden/offscreen content, invisible overlays, and unicode-bidi tricks.
- `urls.ts` for punycode login URLs, URL shorteners, private/local target URLs, suspicious TLDs, brand impersonation, generated landing URLs, and download-like target URLs.
- `decoders.ts` for decoded base64, JavaScript escapes, and `String.fromCharCode` artifacts.
- `binary.ts` for executable magic, content-type/magic mismatch, ELF stack flags, IoT botnet strings, router exploit strings, dropper commands, and DHT/CNC protocol strings.

Complete-file tools such as ClamAV, capa, FLOSS, and normal binary YARA workflows can be routed by applications when a full file is materialized. They are not faked in the streaming hot path.
