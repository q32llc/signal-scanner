# Contributing

Thanks for your interest in `@q32/signal-scanner`. This is a security-analysis
library, so the bar is correctness and low false-positive rates — not feature
count.

## What the project is

A runtime-portable scanner that takes bytes + source metadata and returns
findings, extracted URLs, decoded artifacts, a score, and a disposition. The
core has **no Node-only imports** and opens no network connections; hosts feed it
data. The most valuable surface is the **dynamic-render path** — rendering a page
in a real DOM, executing its scripts under instrumentation inside an
`isolated-vm` sandbox, and scanning the result. Contributions that strengthen
detection there are especially welcome.

## Setup

```bash
bun install        # or: npm install
npm run build      # tsc -> dist/
```

Node ≥ 20.11 is required (global `fetch`, web streams, `import.meta.dirname`).
`isolated-vm` and `esbuild` are optional dependencies used only by the dynamic
render path; a default install pulls them in.

## Tests

```bash
npm test            # bun test — analyzers, rule packs, in-process render
npm run coverage    # the above + an enforced 80% line-coverage gate (CI runs this)
npm run test:isolate # builds, then runs the isolated-vm render path under Node
```

Why two runners: the unit suite runs under `bun test`, but `isolated-vm` ships a
native addon Bun cannot load, so the real sandbox path is tested under Node
against built `dist/` (`test/integration/isolate.mjs`). CI runs both. If you
touch `src/render*.ts` or `src/render-isolate/*`, run `npm run test:isolate`
locally — `bun test` does **not** exercise the actual sandbox.

Every change to detection should add both a **positive** fixture (the signal is
caught) and a **negative** one (a benign page is not flagged). False positives
are the costly failure mode for this kind of tool.

## The eval harness

`npm run eval` measures how well the detector separates a labeled corpus of live
known-good and known-bad sites (no threat-intel feeds — just the homegrown
heuristics). It enforces a max false-positive rate on the good corpus. Run it
before/after changes to rules or scoring to confirm you haven't regressed the
separation. It is dev-only and not shipped. See `.env.example` for the optional
proxy config (some ISPs intercept known-bad hosts and tank recall). Never commit
credentials — `.env` is gitignored.

## Working on rules

Read [`docs/rule-packs.md`](docs/rule-packs.md). In short: rule `id`s are stable
API; `severity`/`confidence` are display-only and do not affect scoring; the
`score` model (`base`, `tags`, `repeatMultiplier`/`maxRepeats`, `maxGroup`) is
what matters. Prefer letting tag-based context multipliers escalate "this + that"
combinations over inflating a single rule's `base`.

## Conventions

- TypeScript, ES modules, `NodeNext` resolution — relative imports need explicit
  `.js` extensions (e.g. `import { x } from "./index.js"`).
- Match the surrounding code's style and comment density. Comments explain
  *why*, especially the adversarial reasoning behind a rule.
- Keep the core portable: no `node:` imports in the default scanner path. Node
  helpers belong behind their own subpath export (e.g. `node-tls`) or in the CLI.

## Pull requests

1. Branch from `main`.
2. Make sure `npm run coverage` and `npm run test:isolate` pass.
3. For detection changes, include fixtures (positive + negative) and note any
   eval-harness impact.
4. Keep PRs focused; describe the threat or behavior the change addresses.

## License

By contributing you agree your contributions are licensed under the project's
[LGPL-3.0-or-later](COPYING.LESSER).
