# Changelog

All notable changes to `@q32/signal-scanner` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0 ([SemVer](https://semver.org/) `0.x`): the public API may
change between minor versions until `1.0.0`.

## [0.2.1] — 2026-06-19

### Fixed
- The CLI no longer crashes on startup when the optional render dependencies are
  absent (e.g. installed with `--no-optional`, or `isolated-vm` can't build).
  `punycode` was resolved at module load time in the render executor, throwing
  before any work began — it is now resolved lazily inside the render path, so
  the static scan/crawl path runs regardless. Found by installing the published
  `0.2.0` tarball with `--no-optional` and running the `signal-scanner` bin.

## [0.2.0] — 2026-06-19

Launch-readiness pass: the package now installs, exposes a working CLI, and is
correctly licensed and tested.

### Added
- `signal-scanner` executable (`bin`), runnable via `npx @q32/signal-scanner` or
  a global install.
- Integration test for the production dynamic-render path
  (`npm run test:isolate`): verifies DOM materialization, behavior/network
  recording, and that untrusted page JavaScript cannot reach the Node host
  (`process`/`require`) inside the `isolated-vm` sandbox. Runs under Node against
  built `dist/` because `isolated-vm`'s native addon cannot load under Bun.
- CI workflow (`.github/workflows/ci.yml`) running the coverage gate and the
  isolate test on every push and pull request (previously CI ran only on release
  tags).
- Documentation: `docs/rule-packs.md` (rule model, score/tag system, context
  multipliers, how to add a rule) and `CONTRIBUTING.md`.
- `.env.example` documenting the optional eval-harness proxy config.
- `engines` field requiring Node `>=20.11`.

### Changed
- **License: MIT → LGPL-3.0-or-later.** Ships `COPYING` (GPL-3.0) and
  `COPYING.LESSER` (LGPL-3.0). Applications may link and use the library without
  becoming LGPL/GPL; modifications to the library stay under the LGPL.
- Relocated the CLI and `isolated-vm` render executor into `src/` so they compile
  to `dist/`. The published CLI no longer imports an unshipped source tree.
- `isolated-vm` and `esbuild` are now `optionalDependencies`, lazily loaded by
  the render path. A base install scans statically and degrades gracefully (with
  a notice) when the native addon is unavailable.
- Dropped the dev-only `scripts/` directory from the published package; punycode
  is resolved hoist-safely via `createRequire`.

## [0.1.1] — 2026-06-19

### Fixed
- Publish compiled package exports so installs resolve the declared types and
  entry points from `dist/`.

### Changed
- CI: updated publish-workflow action versions.

## [0.1.0] — 2026-06-19

Initial public release. A runtime-portable static + dynamic web signal scanner.

### Added
- **Streaming static scanner** with bounded state, explicit per-rule scoring
  (`base` + `tags` + context multipliers, `maxGroup` de-duplication,
  repeat policy) and `allow`/`warn`/`review`/`block` dispositions. HTML is
  tokenized with `htmlparser2`.
- **Rule packs** for phishing/credential capture, URL risk, redirects, technology
  and dependency fingerprints, script risk, obfuscation/decoders, exfiltration,
  wallet, payment, SEO spam, source code, and binary-static signals.
- **Dynamic analysis (the core capability):**
  - Record-and-rescan JavaScript behavior analysis with an isolate-agnostic
    evaluator seam and a Dynamic-Worker sandbox export.
  - `linkedom` render-and-scan (`@q32/signal-scanner/render`):
    `document.write`/`writeln` materialization, cross-origin forced-navigation
    following, and DOM-query injection capture feeding the crawler.
  - CLI renders pages inside a real `isolated-vm` isolate, closing the
    external-script-injection gap that inline-only analysis misses.
  - Dynamic-code-execution family scored as a max, not a sum.
- **URL threat-intel** module (runtime-agnostic) with a cached blocklist-feed
  index keyed by band/prefix and abuse.ch URLhaus/ThreatFox support.
- **Phishing heuristics:** brand impersonation by host and by content, leetspeak
  typosquatting, browser-UA decloaking, formless credential capture, and
  shared-host / off-site-redirect classifiers.
- **Optional Node TLS metadata** helper (`@q32/signal-scanner/node-tls`).
- **Eval harness** over a labeled good/bad corpus, with calibration passes that
  cut false positives (28.8% → 3.8%) and lifted the phishing catch rate
  (11% → 44%).
- Initial packaging: restricted published files, normalized repository metadata,
  npm trusted-publishing (OIDC) workflow, and runtime documentation.

[Unreleased]: https://github.com/q32llc/signal-scanner/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/q32llc/signal-scanner/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/q32llc/signal-scanner/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/q32llc/signal-scanner/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/q32llc/signal-scanner/releases/tag/v0.1.0
