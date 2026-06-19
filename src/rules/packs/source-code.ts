import type { PatternRule } from "../types.js";

export const sourceCodeRules: PatternRule[] = [
  {
    id: "hardcoded_secret_candidate",
    pack: "source-code",
    severity: "high",
    confidence: "medium",
    title: "Hardcoded secret candidate",
    description: "Source text matched a risky secret-like token pattern.",
    locationType: "source",
    pattern: /(?:AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9-]{20,}|ghp_[a-zA-Z0-9]{20,})/,
    score: { base: 62, tags: ["source"] }
  },
  {
    id: "webhook_url_candidate",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Webhook URL candidate",
    description: "Source text contains a webhook URL candidate.",
    locationType: "source",
    pattern: /https:\/\/(?:hooks\.slack\.com\/services\/|discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot)[A-Za-z0-9/_:.-]+/,
    score: { base: 35, tags: ["source", "url"] }
  },
  {
    id: "dangerous_child_process",
    pack: "source-code",
    severity: "high",
    confidence: "medium",
    title: "Dangerous child process use",
    description: "Source text references command execution through child_process.",
    locationType: "source",
    pattern: /\bchild_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\b|require\s*\(\s*['"]child_process['"]\s*\)\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\b|import\s*\{[^}]*\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\b[^}]*\}\s*from\s*['"]node:child_process['"]/,
    score: { base: 50, tags: ["source"] }
  },
  {
    id: "shell_execution_import",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Shell execution import",
    description: "Source text imports Node child_process command execution APIs.",
    locationType: "source",
    pattern: /\b(?:import|require)\b[^;\n]{0,120}\bchild_process\b/,
    score: { base: 24, tags: ["source"] }
  },
  {
    id: "curl_pipe_shell",
    pack: "source-code",
    severity: "high",
    confidence: "medium",
    title: "curl pipe shell",
    description: "Source text pipes a downloaded script into a shell.",
    locationType: "source",
    pattern: /\bcurl\b[^|]{0,120}\|\s*(?:sh|bash)/,
    score: { base: 70, tags: ["source", "url"] }
  },
  {
    id: "postinstall_script",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Postinstall script",
    description: "Package metadata defines a postinstall script.",
    locationType: "source",
    pattern: /"postinstall"\s*:/,
    score: { base: 20, tags: ["source"] }
  },
  {
    id: "preinstall_script",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Preinstall script",
    description: "Package metadata defines a preinstall script.",
    locationType: "source",
    pattern: /"preinstall"\s*:/,
    score: { base: 20, tags: ["source"] }
  },
  {
    id: "install_script_network_fetch",
    pack: "source-code",
    severity: "high",
    confidence: "medium",
    title: "Install script performs network fetch",
    description: "Install lifecycle script appears to fetch network content.",
    locationType: "source",
    pattern: /"(?:preinstall|install|postinstall)"\s*:\s*"[^"]*(?:curl|wget|fetch|https?:\/\/)/,
    score: { base: 66, tags: ["source", "url"] }
  },
  {
    id: "non_literal_require",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Non-literal require candidate",
    description: "Source text calls require() with an expression instead of a string literal.",
    locationType: "source",
    pattern: /\brequire\s*\(\s*(?!['"`])/,
    score: { base: 18, tags: ["source"] }
  },
  {
    id: "non_literal_regexp",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Non-literal RegExp candidate",
    description: "Source text constructs a RegExp from a non-literal expression.",
    locationType: "source",
    pattern: /\bnew\s+RegExp\s*\(\s*(?!['"`])|\bRegExp\s*\(\s*(?!['"`])/,
    score: { base: 16, tags: ["source"] }
  },
  {
    id: "new_buffer_constructor",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "New Buffer constructor",
    description: "Source text uses the legacy Buffer constructor.",
    locationType: "source",
    pattern: /\bnew\s+Buffer\s*\(/,
    score: { base: 12, tags: ["source"] }
  },
  {
    id: "weak_crypto_hash",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Weak crypto hash",
    description: "Source text references weak hash algorithms.",
    locationType: "source",
    pattern: /\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/,
    score: { base: 16, tags: ["source"] }
  },
  {
    id: "pseudo_random_bytes",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Pseudo-random bytes",
    description: "Source text references crypto.pseudoRandomBytes().",
    locationType: "source",
    pattern: /\bpseudoRandomBytes\s*\(/,
    score: { base: 16, tags: ["source"] }
  },
  {
    id: "template_escape_disabled",
    pack: "source-code",
    severity: "medium",
    confidence: "medium",
    title: "Template escaping disabled",
    description: "Source text appears to disable template escaping.",
    locationType: "source",
    pattern: /\bescapeMarkup\s*=\s*false\b/,
    score: { base: 22, tags: ["source"] }
  },
  {
    id: "sensitive_file_read",
    pack: "source-code",
    severity: "high",
    confidence: "medium",
    title: "Sensitive file read candidate",
    description: "Source text references filesystem reads of sensitive paths or environment files.",
    locationType: "source",
    pattern: /\b(?:readFileSync|readFile)\s*\([^)]*(?:\/etc\/passwd|\.env|id_rsa|credentials)/,
    score: { base: 48, tags: ["source"] }
  },
  {
    id: "private_key_material",
    pack: "source-code",
    severity: "critical",
    confidence: "high",
    title: "Private key material",
    description: "Source text contains a private key header.",
    locationType: "source",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    score: { base: 95, tags: ["source"] }
  }
];
