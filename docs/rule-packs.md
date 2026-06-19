# Rule Packs

Rules are the unit of detection. Each rule describes one observable signal, ties
it to a score, and tags it so the scorer can apply context. Rules are grouped
into named **packs** (`phishing`, `obfuscation`, `exfiltration`, …) for reporting
and selection. This document explains the rule model and how to add one.

The interesting detection happens in the **dynamic-render path** (see the README
"Dynamic Rendering" section): a page is rendered in a real DOM with its scripts
executed under instrumentation, and the rendered output plus recorded behaviors
are scanned with these same rules. Static crawling/URL extraction is the thinner,
less interesting layer that feeds bytes in.

## The two rule shapes

Both shapes live in [`src/rules/types.ts`](../src/rules/types.ts).

### `PatternRule` — regex over a content stream

A self-contained rule: a regex matched against a bounded text window for a
content kind. Used by the script-risk packs. The scanner walks `scriptRiskRules`
and emits a finding when `rule.pattern.test(text)` is true
(see `src/index.ts`).

```ts
{
  id: "eval_dynamic_execution",
  pack: "obfuscation",
  severity: "high",
  confidence: "medium",
  title: "Dynamic code execution",
  description: "Script calls eval()/new Function() on runtime-built strings.",
  locationType: "javascript",
  pattern: /\beval\s*\(/,
  score: { base: 30, tags: ["script", "obfuscation"], maxGroup: "dynamic-exec" }
}
```

### `RuleDefinition` — emitted by analyzer logic

No regex. The rule is a labeled scoring record that analyzer code emits via
`addRuleFinding(state, rule, location, meta)` once it has decided the signal is
present. Used where detection needs structured context a regex can't express —
URL relationships, cross-field correlation, rendered-DOM facts, TLS, decoded
artifacts. Example: `urlRules.brand_impersonation_url` is emitted only after the
URL analyzer confirms a brand token appears in the host while the registrable
domain doesn't belong to that brand.

```ts
{
  id: "brand_impersonation_url",
  pack: "phishing",
  severity: "high",
  confidence: "high",
  title: "Brand name in host of an unrelated domain",
  description: "A well-known brand appears in the hostname while the registrable domain does not belong to that brand.",
  locationType: "url",
  score: { base: 68, tags: ["phishing", "url"] }
}
```

## Fields

| Field | Meaning |
|---|---|
| `id` | Stable, unique identifier. Appears in reports and tests — treat as API. |
| `pack` | The pack this rule belongs to (see below). |
| `severity` / `confidence` | **Display metadata only.** They do *not* drive scoring. |
| `title` / `description` | Human-readable, shown in findings. |
| `locationType` | What the finding points at: `url`, `html`, `javascript`, `css`, `source`, `binary`, `decoded_artifact`, `aggregate`. |
| `pattern` | (`PatternRule` only) the regex. |
| `counter` | (optional) a named counter incremented on each match. |
| `score` | The score model — the part that actually matters (below). |

## The score model

`severity`/`confidence` are for humans. The number comes entirely from `score`
([`RuleScoreModel`](../src/rules/types.ts)) and is computed by `scoreFindings`
in `src/index.ts`:

- **`base`** — points the rule contributes once.
- **`tags`** — `ScoreTag[]` describing *what kind* of signal this is
  (`credential`, `phishing`, `exfiltration`, `wallet`, `payment`, `redirect`,
  `decoded`, `obfuscation`, `script`, `url`, `hosting`, `binary`, …). Tags drive
  context multipliers — see below.
- **`repeatMultiplier` / `maxRepeats`** — repeated hits of the same rule add
  `base × repeatMultiplier` each, capped at `maxRepeats` extra. Default: a rule
  scores once no matter how many times it fires.
- **`maxGroup`** — rules sharing a `maxGroup` describe the *same underlying
  behavior observed different ways* (e.g. `eval` / `new Function` / runtime
  eval all mean "uses dynamic code"). Only the single highest-scoring member of
  a group contributes, so a legitimately JS-heavy page isn't charged N times for
  one behavior.

### Context multipliers

After per-rule scores are summed, the set of all tags present on the page
applies multipliers (`scoreMultiplier` in `src/index.ts`). This is how the
scanner rewards *combinations* that are individually weak but jointly damning:

| When these tags co-occur | Multiplier |
|---|---|
| `credential` + (`hosting` \| `redirect` \| `url`) | ×1.2 |
| (`payment` \| `wallet`) + (`exfiltration` \| `redirect`) | ×1.15 |
| `decoded` + (`script` \| `exfiltration`) | ×1.15 |
| `binary` + `url` | ×1.1 |

The final score is clamped to `0–100`, then mapped to a disposition by
`dispositionForScore`: `≥75 block`, `≥50 review`, `≥25 warn`, else `allow`.

## Packs

Packs are named groups of rules, assembled in
[`src/rules/packs/index.ts`](../src/rules/packs/index.ts) as `rulePacks`. A rule's
`pack` field is its primary home, but a pack entry can also pull rules from other
files (e.g. the `obfuscation` pack gathers decoder rules, the obfuscation-tagged
script rules, a composite rule, and a CSS bidi rule). Packs are how the report
groups findings and how callers can reason about coverage.

Current packs: `phishing`, `redirects`, `url-risk`, `technology-fingerprint`,
`dependency-fingerprint`, `script-risk`, `obfuscation`, `exfiltration`, `wallet`,
`payment`, `seo-spam`, `source-code`, `binary-static`.

## Adding a rule

1. **Pick the shape.** Pure text signal → `PatternRule` in the relevant
   `src/rules/packs/*.ts` (usually `script-risk.ts`). Needs cross-field or
   structural context → `RuleDefinition`, emitted from the analyzer in
   `src/index.ts` (or `render.ts`/`dynamic.ts` for rendered-DOM/behavior
   signals).
2. **Choose `base` and `tags` deliberately.** Tags are not decoration — they
   gate the context multipliers above. A rule with no useful tags can never
   participate in a combination bonus. Keep `base` proportionate: a lone weak
   indicator should be small (`6–25`); a near-certain phishing tell can be high
   (`66–78`). Let multipliers do the "this plus that" escalation rather than
   inflating `base`.
3. **Use `maxGroup`** if your rule is another way of observing a behavior an
   existing rule already covers, so they don't stack.
4. **Register it** in the appropriate `rulePacks` entry if it isn't pulled in
   automatically.
5. **Add a test.** Assert your `id` appears for a positive fixture and — just as
   important — does *not* appear for a benign one (false positives are the
   expensive failure here). See `test/scanner.test.ts` and `test/render.test.ts`.
6. **Run the eval harness** (`npm run eval`) to confirm you haven't regressed the
   good/bad separation on the live corpus.
