import type { PatternRule, RuleDefinition } from "../types.js";

export const scriptRiskRules: PatternRule[] = [
  {
    id: "dynamic_code_execution",
    pack: "script-risk",
    severity: "low",
    confidence: "medium",
    title: "Dynamic code execution",
    description: "JavaScript calls eval().",
    locationType: "javascript",
    pattern: /\beval\s*\(/,
    counter: "dynamic_code_execution",
    // eval() is ubiquitous in legitimate minified bundles; weak signal alone.
    score: { base: 12, tags: ["script"], maxGroup: "dynamic-code" }
  },
  {
    id: "function_constructor_with_string",
    pack: "script-risk",
    severity: "low",
    confidence: "medium",
    title: "Function constructor with string",
    description: "JavaScript constructs code from a string.",
    locationType: "javascript",
    pattern: /\bnew\s+Function\s*\(/,
    // new Function() is ubiquitous in legitimate minified bundles (framework
    // template compilers, lodash, etc.) — weak signal alone, like eval().
    score: { base: 15, tags: ["script"], maxGroup: "dynamic-code" }
  },
  {
    id: "string_timer_execution",
    pack: "script-risk",
    severity: "medium",
    confidence: "high",
    title: "String-based timer execution",
    description: "JavaScript passes a string to a timer execution API.",
    locationType: "javascript",
    pattern: /\bset(?:Timeout|Interval)\s*\(\s*['"`]/,
    counter: "dynamic_code_execution",
    score: { base: 24, tags: ["script"], maxGroup: "dynamic-code" }
  },
  {
    id: "document_write_script",
    pack: "script-risk",
    severity: "low",
    confidence: "high",
    title: "document.write usage",
    description: "JavaScript writes dynamic HTML into the document.",
    locationType: "javascript",
    pattern: /\bdocument\.write\s*\(/,
    score: { base: 8, tags: ["script"] }
  },
  {
    id: "innerhtml_script_injection",
    pack: "script-risk",
    severity: "low",
    confidence: "high",
    title: "HTML injection sink",
    description: "JavaScript assigns to an HTML injection sink.",
    locationType: "javascript",
    pattern: /\.(?:innerHTML|outerHTML)\s*=/,
    score: { base: 10, tags: ["script"] }
  },
  {
    id: "insert_adjacent_html",
    pack: "script-risk",
    severity: "low",
    confidence: "high",
    title: "insertAdjacentHTML usage",
    description: "JavaScript inserts HTML through insertAdjacentHTML().",
    locationType: "javascript",
    pattern: /\.insertAdjacentHTML\s*\(/,
    score: { base: 8, tags: ["script"] }
  },
  {
    id: "dynamic_script_src",
    pack: "script-risk",
    severity: "medium",
    confidence: "high",
    title: "Dynamic script creation",
    description: "JavaScript creates a script element dynamically.",
    locationType: "javascript",
    pattern: /\bcreateElement\s*\(\s*['"]script['"]\s*\)/,
    score: { base: 18, tags: ["script"] }
  },
  {
    id: "script_src_assignment",
    pack: "script-risk",
    severity: "medium",
    confidence: "high",
    title: "Dynamic script src assignment",
    description: "JavaScript assigns to a script source dynamically.",
    locationType: "javascript",
    pattern: /\.src\s*=|setAttribute\s*\(\s*['"]src['"]/,
    score: { base: 18, tags: ["script"] }
  },
  {
    id: "append_child_script",
    pack: "script-risk",
    severity: "low",
    confidence: "medium",
    title: "Dynamic script append",
    description: "JavaScript appends a dynamically created script element.",
    locationType: "javascript",
    pattern: /\.appendChild\s*\(\s*(?:script|s|el|node)\s*\)/,
    score: { base: 6, tags: ["script"] }
  },
  {
    id: "external_request_api_seen",
    pack: "script-risk",
    severity: "low",
    confidence: "medium",
    title: "External request API",
    description: "JavaScript references an outbound request API.",
    locationType: "javascript",
    pattern: /\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)\b/,
    score: { base: 6, tags: ["script"] }
  },
  {
    id: "js_location_external",
    pack: "redirects",
    severity: "medium",
    confidence: "high",
    title: "JavaScript redirect logic",
    description: "JavaScript references browser redirect APIs.",
    locationType: "javascript",
    pattern: /\b(?:location\.href|location\.assign|location\.replace|window\.open)\b/,
    score: { base: 20, tags: ["redirect", "script"] }
  },
  {
    id: "decoder_seen",
    pack: "obfuscation",
    severity: "low",
    confidence: "medium",
    title: "Decoder API seen",
    description: "JavaScript references a common string decoder API.",
    locationType: "javascript",
    pattern: /\b(?:atob|btoa|unescape|String\.fromCharCode)\b/,
    counter: "decoder_seen",
    score: { base: 6, tags: ["decoded", "script"] }
  },
  {
    id: "charcodeat_decoder_loop",
    pack: "obfuscation",
    severity: "medium",
    confidence: "medium",
    title: "charCodeAt decoder loop",
    description: "JavaScript uses charCodeAt in loop-like code, a common lightweight decoder pattern.",
    locationType: "javascript",
    pattern: /(?:for|while)\s*\([^)]*\)[\s\S]{0,300}\.charCodeAt\s*\(/,
    score: { base: 22, tags: ["decoded", "obfuscation", "script"] }
  },
  {
    id: "browser_storage_or_clipboard_seen",
    pack: "exfiltration",
    severity: "medium",
    confidence: "medium",
    title: "Storage or clipboard access",
    description: "JavaScript references browser storage, cookies, or clipboard APIs.",
    locationType: "javascript",
    pattern: /\b(?:localStorage|sessionStorage|document\.cookie|navigator\.clipboard)\b/,
    score: { base: 14, tags: ["exfiltration", "script"] }
  },
  {
    id: "wallet_interaction_with_obfuscation",
    pack: "wallet",
    severity: "medium",
    confidence: "medium",
    title: "Wallet API reference",
    description: "JavaScript references wallet or approval APIs.",
    locationType: "javascript",
    pattern: /\b(?:window\.ethereum|WalletConnect|ethereum\.request)\b|\.(?:approve|permit)\s*\(|\bmethod\s*:\s*['"]eth_/i,
    score: { base: 20, tags: ["script", "wallet"] }
  }
];

export const scriptCompositeRules: Record<
  "credential_exfil_candidate" | "decoded_dynamic_execution" | "form_action_changed_by_javascript" | "wallet_api_plus_external_beacon" | "payment_input_event_hooks",
  RuleDefinition
> = {
  credential_exfil_candidate: {
    id: "credential_exfil_candidate",
    pack: "exfiltration",
    severity: "high",
    confidence: "medium",
    title: "Credential or storage exfiltration candidate",
    description: "JavaScript combines credential/storage signals with outbound request APIs.",
    locationType: "javascript",
    score: { base: 72, tags: ["credential", "exfiltration", "script"] }
  },
  decoded_dynamic_execution: {
    id: "decoded_dynamic_execution",
    pack: "obfuscation",
    severity: "high",
    confidence: "high",
    title: "Decoded dynamic execution",
    description: "JavaScript combines decoder APIs with dynamic execution.",
    locationType: "javascript",
    score: { base: 76, tags: ["decoded", "obfuscation", "script"] }
  },
  form_action_changed_by_javascript: {
    id: "form_action_changed_by_javascript",
    pack: "phishing",
    severity: "low",
    confidence: "medium",
    title: "Form action changed by JavaScript",
    description: "JavaScript appears to change a form action target.",
    locationType: "javascript",
    // Legitimate SPAs/SSO flows rewrite form actions; weak on its own, and the
    // "credential"/"phishing" tags were escalating the score multiplier.
    score: { base: 12, tags: ["script"] }
  },
  wallet_api_plus_external_beacon: {
    id: "wallet_api_plus_external_beacon",
    pack: "wallet",
    severity: "high",
    confidence: "medium",
    title: "Wallet API plus external request",
    description: "JavaScript combines wallet APIs with outbound request APIs.",
    locationType: "javascript",
    score: { base: 72, tags: ["exfiltration", "script", "wallet"] }
  },
  payment_input_event_hooks: {
    id: "payment_input_event_hooks",
    pack: "payment",
    severity: "low",
    confidence: "medium",
    title: "Payment input event hooks",
    description: "JavaScript attaches input/change listeners near payment-card fields.",
    locationType: "javascript",
    // Every legitimate checkout/login listens to its own input fields — weak
    // signal alone. The real skimmer pattern is this PLUS off-site exfil of the
    // captured values, which the exfil/credential-form rules score on their own.
    score: { base: 15, tags: ["payment", "script"] }
  }
};
