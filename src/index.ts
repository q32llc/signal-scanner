import { binaryRules, binaryStringRules, cssRules, decodedArtifactRules, htmlRules, htmlTechnologyRules, scriptCompositeRules, scriptRiskRules, sourceCodeRules, urlRules } from "./rules/packs";
import type { RuleDefinition, RuleScoreModel, ScoreTag } from "./rules/types";

export type ContentKind = "html" | "javascript" | "css" | "json" | "svg" | "text" | "unknown" | "archive" | "executable";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type Disposition = "allow" | "warn" | "review" | "block";

export interface FetchRecord {
  url: string;
  finalUrl: string;
  status: number;
  contentType: string;
  contentLength: number | null;
  redirectChain: string[];
  tls?: {
    protocol?: string;
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validTo?: string;
  };
}

export interface ScannerSource {
  url?: string;
  finalUrl?: string;
  filename?: string;
  contentType?: string | null;
  originUrl?: string;
  tls?: TlsMetadata;
}

export interface TlsMetadata {
  authorized?: boolean;
  authorizationError?: string | null;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  fingerprint256?: string;
  serialNumber?: string;
}

export interface ArtifactRecord {
  source: string;
  artifactType: string;
  parentOffset: number;
  depth: number;
  sha256?: string;
  text: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  confidence: Confidence;
  score: number;
  scoreModel: RuleScoreModel;
  title: string;
  description: string;
  locationType: "url" | "html" | "javascript" | "css" | "source" | "binary" | "decoded_artifact" | "aggregate";
  locationValue: string;
  ruleId: string;
  metadata: Record<string, unknown>;
}

export interface ExtractedUrl {
  raw: string;
  normalized: string;
  registrableDomain: string | null;
  relation: "same-origin" | "same-site" | "subdomain" | "off-site" | "unknown";
  scheme: string;
  destinationType: "http" | "https" | "ip" | "private" | "localhost" | "url-shortener" | "other";
  flags: string[];
}

export interface ScannerReport {
  contentKind: ContentKind;
  findings: Finding[];
  urls: ExtractedUrl[];
  artifacts: ArtifactRecord[];
  score: number;
  disposition: Disposition;
  counters: Record<string, number>;
}

export interface Scanner {
  feed(chunk: Uint8Array): Finding[];
  finish(): ScannerReport;
}

interface ScannerOptions {
  source?: ScannerSource;
  maxWindowChars?: number;
  maxDecodedBytes?: number;
  maxDecodeDepth?: number;
}

interface ScannerState {
  source: ScannerSource;
  contentKind: ContentKind;
  textWindow: string;
  scanCarry: string;
  absoluteOffset: number;
  line: number;
  column: number;
  findings: Finding[];
  findingKeys: Set<string>;
  urls: Map<string, ExtractedUrl>;
  artifacts: ArtifactRecord[];
  counters: Record<string, number>;
  forms: FormState[];
  externalScripts: ExtractedUrl[];
  inScript: boolean;
  currentScript: string;
  binaryHeaderScanned: boolean;
}

interface FormState {
  action: string | null;
  method: string | null;
  hasPassword: boolean;
  hasPayment: boolean;
  hiddenTarget: boolean;
}

const DEFAULT_WINDOW_CHARS = 64 * 1024;
const DEFAULT_CARRY_CHARS = 4096;
const DEFAULT_MAX_DECODED_BYTES = 128 * 1024;
const DEFAULT_MAX_DECODE_DEPTH = 2;

export function createScanner(options: ScannerOptions = {}): Scanner {
  const state: ScannerState = {
    source: options.source ?? {},
    contentKind: detectContentKind({
      contentType: options.source?.contentType ?? null,
      filename: options.source?.filename ?? options.source?.url,
      firstBytes: new Uint8Array()
    }),
    textWindow: "",
    scanCarry: "",
    absoluteOffset: 0,
    line: 1,
    column: 1,
    findings: [],
    findingKeys: new Set(),
    urls: new Map(),
    artifacts: [],
    counters: {},
    forms: [],
    externalScripts: [],
    inScript: false,
    currentScript: "",
    binaryHeaderScanned: false
  };
  const maxWindowChars = options.maxWindowChars ?? DEFAULT_WINDOW_CHARS;
  const maxDecodedBytes = options.maxDecodedBytes ?? DEFAULT_MAX_DECODED_BYTES;
  const maxDecodeDepth = options.maxDecodeDepth ?? DEFAULT_MAX_DECODE_DEPTH;
  if (state.source.url) addUrl(state, state.source.url);
  if (state.source.finalUrl && state.source.finalUrl !== state.source.url) addUrl(state, state.source.finalUrl);
  scanRedirectContext(state);
  scanTlsContext(state);

  return {
    feed(chunk: Uint8Array): Finding[] {
      if (!chunk.byteLength) return [];
      if (state.absoluteOffset === 0) {
        state.contentKind = detectContentKind({
          contentType: state.source.contentType ?? null,
          filename: state.source.filename ?? state.source.url,
          firstBytes: chunk
        });
        scanBinaryHeader(state, chunk);
      }
      const before = state.findings.length;
      const text = decodeText(chunk);
      const scanTextInput = state.scanCarry + text;
      state.textWindow = trimWindow(state.textWindow + text, maxWindowChars);
      scanText(state, scanTextInput, state.absoluteOffset - byteLength(state.scanCarry), 0, maxDecodedBytes, maxDecodeDepth);
      updatePosition(state, text);
      state.scanCarry = trimWindow(scanTextInput, DEFAULT_CARRY_CHARS);
      state.absoluteOffset += chunk.byteLength;
      state.counters.bytes_seen = state.absoluteOffset;
      return state.findings.slice(before);
    },
    finish(): ScannerReport {
      finalizeAggregateRules(state);
      const score = scoreFindings(state.findings);
      return {
        contentKind: state.contentKind,
        findings: dedupeFindings(state.findings),
        urls: [...state.urls.values()],
        artifacts: state.artifacts,
        score,
        disposition: dispositionForScore(score),
        counters: { ...state.counters }
      };
    }
  };
}

export function detectContentKind(input: {
  contentType?: string | null;
  filename?: string | null;
  firstBytes?: Uint8Array;
}): ContentKind {
  const first = input.firstBytes ?? new Uint8Array();
  if (hasElfMagic(first)) return "executable";

  const contentType = (input.contentType ?? "").toLowerCase().split(";")[0].trim();
  if (contentType.includes("html")) return "html";
  if (contentType.includes("javascript") || contentType.includes("ecmascript")) return "javascript";
  if (contentType === "text/css") return "css";
  if (contentType.includes("json")) return "json";
  if (contentType.includes("svg")) return "svg";
  if (contentType.startsWith("text/")) return "text";
  if (contentType.includes("zip") || contentType.includes("tar") || contentType.includes("gzip") || contentType.includes("x-7z") || contentType.includes("rar")) return "archive";

  const filename = (input.filename ?? "").toLowerCase().split("?")[0];
  if (/\.(html?|xhtml)$/.test(filename)) return "html";
  if (/\.(mjs|cjs|js|jsx|ts|tsx)$/.test(filename)) return "javascript";
  if (/\.css$/.test(filename)) return "css";
  if (/\.json$/.test(filename)) return "json";
  if (/\.svg$/.test(filename)) return "svg";
  if (/\.(zip|jar|war|tar|tgz|gz|7z|rar)$/.test(filename)) return "archive";

  if (first.length >= 4 && first[0] === 0x50 && first[1] === 0x4b) return "archive";
  if (first.length >= 2 && first[0] === 0x1f && first[1] === 0x8b) return "archive";
  if (first.length >= 6 && first[0] === 0x37 && first[1] === 0x7a && first[2] === 0xbc && first[3] === 0xaf && first[4] === 0x27 && first[5] === 0x1c) return "archive";
  const text = decodeText(first.slice(0, 512)).trimStart();
  if (/^<!doctype html/i.test(text) || /^<html[\s>]/i.test(text)) return "html";
  if (/^<svg[\s>]/i.test(text)) return "svg";
  if (/^\s*(?:import|export|const|let|var|function)\b/.test(text)) return "javascript";
  if (/^\s*(?:@import|[.#]?[a-z0-9_-]+\s*\{[^}]+:)/i.test(text)) return "css";
  if (/^[\[{]/.test(text)) return "json";
  return text ? "text" : "unknown";
}

export function normalizeUrl(raw: string, base?: string): ExtractedUrl | null {
  try {
    const url = new URL(raw, base);
    url.hash = "";
    const normalized = url.toString();
    const host = url.hostname.toLowerCase();
    const registrableDomain = registrableDomainFor(host);
    const baseHost = base ? new URL(base).hostname.toLowerCase() : "";
    const baseDomain = baseHost ? registrableDomainFor(baseHost) : null;
    const flags: string[] = [];
    if (host.startsWith("xn--") || host.includes(".xn--")) flags.push("punycode");
    if (isIpLiteral(host)) flags.push("ip_literal");
    if (isPrivateHost(host)) flags.push("private_or_localhost");
    if (isUrlShortener(host)) flags.push("url_shortener");
    if (/(?:login|signin|account|verify|wallet|checkout|payment|download|payload)/i.test(url.pathname)) flags.push("suspicious_path_terms");
    if (isSuspiciousTld(host)) flags.push("suspicious_tld");
    if (/(?:\/|^)(?:payload|installer|setup|invoice|verify|wallet|checkout|payment)(?:[\/_.-]|$)|\.(?:exe|scr|msi|dmg|pkg|apk|zip)$/i.test(url.pathname)) {
      flags.push("download_like_path");
    }
    if (isMalwareDownloadLikePath(url.pathname)) flags.push("malware_download_like_path");
    if (isSharedHostingSubdomain(host, registrableDomain)) flags.push("shared_hosting_subdomain");
    if (isGeneratedHostLabel(host, registrableDomain)) flags.push("generated_host_label");
    return {
      raw,
      normalized,
      registrableDomain,
      relation: relationFor(host, registrableDomain, baseHost, baseDomain),
      scheme: url.protocol.replace(":", ""),
      destinationType: destinationTypeFor(url, host),
      flags
    };
  } catch {
    return null;
  }
}

function scanText(
  state: ScannerState,
  text: string,
  offset: number,
  depth: number,
  maxDecodedBytes: number,
  maxDecodeDepth: number
): void {
  collectUrls(state, text);
  scanPageIntentSignals(state, text);
  if (state.contentKind === "html" || /<html|<script|<form|<iframe/i.test(text)) scanHtml(state, text);
  if (state.contentKind === "javascript" || state.inScript || /<script\b/i.test(text)) {
    scanJavaScript(state, text);
  }
  if (state.contentKind === "css" || /(?:display\s*:\s*none|opacity\s*:\s*0|@import|url\()/i.test(text)) scanCss(state, text);
  if (state.contentKind === "executable" || likelyBinaryStrings(text)) scanBinaryStrings(state, text);
  if (shouldScanSourceText(state)) scanSourceText(state, text);
  if (depth < maxDecodeDepth) decodeAndRescan(state, text, offset, depth, maxDecodedBytes, maxDecodeDepth);
}

function scanHtml(state: ScannerState, text: string): void {
  for (const tag of text.matchAll(/<\s*([a-z0-9:-]+)\b([^>]*)>/gi)) {
    const name = tag[1].toLowerCase();
    const attrs = parseAttrs(tag[2]);
    if (name === "script") {
      const src = attrs.get("src");
      if (src) {
        increment(state, "html.script_src");
        addUrl(state, src);
        const normalized = normalizeUrl(src, pageUrl(state));
        // Ad/analytics/tag-manager scripts are expected on ordinary ad-funded
        // sites (news, blogs) and are never a phishing exfil channel, so they
        // don't count toward "suspicious external scripts".
        if (normalized?.relation === "off-site" && !isAdOrAnalyticsHost(normalized.normalized)) state.externalScripts.push(normalized);
        if (pageUrl(state)?.startsWith("https://") && normalized?.scheme === "http") addRuleFinding(state, htmlRules.mixed_content_script, normalized.normalized, {});
        scanTechnologyFingerprint(state, src, normalized?.normalized ?? src);
      } else {
        increment(state, "inline_script");
      }
      state.inScript = true;
    }
    if (name === "form") {
      increment(state, "html.form");
      state.forms.push({
        action: attrs.get("action") ?? null,
        method: attrs.get("method")?.toLowerCase() ?? "get",
        hasPassword: false,
        hasPayment: false,
        hiddenTarget: /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i.test(attrs.get("style") ?? "")
      });
    }
    if (name === "input" && state.forms.length) {
      increment(state, "html.input");
      const type = (attrs.get("type") ?? "").toLowerCase();
      const field = `${attrs.get("name") ?? ""} ${attrs.get("autocomplete") ?? ""}`.toLowerCase();
      const form = state.forms[state.forms.length - 1];
      if (type === "password" || field.includes("password")) form.hasPassword = true;
      if (/(?:cc-|card|cvv|cvc|expiry|payment)/.test(`${type} ${field}`)) form.hasPayment = true;
    }
    if (["a", "link", "img", "iframe"].includes(name)) {
      increment(state, `html.${name}`);
      const src = attrs.get("href") ?? attrs.get("src");
      if (src) addUrl(state, src);
      if (name === "iframe" && src && hiddenAttrs(attrs)) {
        const normalized = normalizeUrl(src, pageUrl(state));
        if (normalized?.relation === "off-site" && hasRiskyUrlFlags(normalized)) addRuleFinding(state, htmlRules.hidden_iframe_off_origin, normalized.normalized, {});
      }
    }
    if (name === "base") {
      const href = attrs.get("href");
      if (href) {
        increment(state, "html.base_href");
        addUrl(state, href);
      }
    }
    if (name === "link" && /canonical/i.test(attrs.get("rel") ?? "")) {
      increment(state, "html.canonical");
    }
    if (name === "meta" && /generator/i.test(attrs.get("name") ?? "") && /wordpress/i.test(attrs.get("content") ?? "")) {
      addRuleFinding(state, htmlTechnologyRules.wordpress_surface_reference, pageUrl(state) ?? "html", { generator: attrs.get("content") ?? "" });
    }
    if (name === "meta" && /refresh/i.test(attrs.get("http-equiv") ?? "")) {
      increment(state, "html.meta_refresh");
      const content = attrs.get("content") ?? "";
      const target = content.match(/url\s*=\s*([^;]+)/i)?.[1]?.trim();
      if (target) {
        const normalized = normalizeUrl(target, pageUrl(state));
        if (normalized?.relation === "off-site") addRuleFinding(state, htmlRules.meta_refresh_external, normalized.normalized, {});
      }
    }
  }

  for (const script of text.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) scanJavaScript(state, script[1]);
  if (/wp-content|wp-includes|<meta[^>]+generator[^>]+wordpress/i.test(text)) {
    addRuleFinding(state, htmlTechnologyRules.wordpress_surface_reference, pageUrl(state) ?? "html", {});
  }
  scanTechnologyFingerprint(state, text, pageUrl(state) ?? "html");
  if (/<\/script\s*>/i.test(text)) state.inScript = false;
  if (/(?:login|sign in|password|account|verify|checkout|payment)/i.test(text)) increment(state, "brand_login_or_payment_language");
}

function scanPageIntentSignals(state: ScannerState, text: string): void {
  const normalized = text.replace(/\\\//g, "/");
  if (hasCryptoWalletLoginLanguage(normalized)) increment(state, "content.crypto_wallet_login_language");
  if (hasCryptoTradingLandingLanguage(normalized)) increment(state, "content.crypto_trading_landing_language");
  if (hasLoginUiImageReference(normalized)) increment(state, "content.login_ui_image_reference");
  if (hasSeoTrademarkStuffing(normalized)) increment(state, "content.seo_trademark_stuffing");
}

function scanJavaScript(state: ScannerState, text: string): void {
  for (const rule of scriptRiskRules) {
    if (rule.pattern.test(text)) {
      increment(state, rule.counter ?? rule.id);
      if (!isPrimitiveJavaScriptSignal(rule.id)) addRuleFinding(state, rule, pageUrl(state) ?? "inline-script", {});
    }
  }
  const hasExternalRequestApi = /\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)\b/.test(text);
  if (hasExternalRequestApi && hasNearbyOffSiteUrlWith(text, pageUrl(state), /(?:password|FormData|localStorage|sessionStorage|document\.cookie|navigator\.clipboard)/i)) {
    addRuleFinding(state, scriptCompositeRules.credential_exfil_candidate, pageUrl(state) ?? "script", {});
  }
  if (hasNearbyRegexPair(text, /(?:eval|Function)\s*\(/g, /\b(?:atob|String\.fromCharCode|unescape)\b/g, 320)) {
    addRuleFinding(state, scriptCompositeRules.decoded_dynamic_execution, pageUrl(state) ?? "script", {});
  }
  if (/\.action\s*=|setAttribute\s*\(\s*['"]action['"]/.test(text)) {
    addRuleFinding(state, scriptCompositeRules.form_action_changed_by_javascript, pageUrl(state) ?? "script", {});
  }
  if (hasWalletSignal(text) && hasExternalRequestApi && hasNearbyOffSiteUrlWith(text, pageUrl(state), /\b(?:window\.ethereum|WalletConnect|ethereum\.request|sendBeacon|fetch|XMLHttpRequest|WebSocket)\b|\.(?:approve|permit)\s*\(|\bmethod\s*:\s*['"]eth_/i)) {
    addRuleFinding(state, scriptCompositeRules.wallet_api_plus_external_beacon, pageUrl(state) ?? "script", {});
  }
  if (/(?:cc-number|cardnumber|card|cvv|cvc|expiry|payment)/i.test(text) && /addEventListener\s*\(\s*['"](?:input|change|keyup|keydown)['"]/.test(text)) {
    addRuleFinding(state, scriptCompositeRules.payment_input_event_hooks, pageUrl(state) ?? "script", {});
  }
}

function scanCss(state: ScannerState, text: string): void {
  if (/@import|url\(/i.test(text)) {
    for (const rawUrl of extractCssUrls(text)) {
      addUrl(state, rawUrl);
      const normalized = normalizeUrl(rawUrl, pageUrl(state));
      if (normalized?.relation === "off-site" && hasRiskyUrlFlags(normalized)) {
        addRuleFinding(state, cssRules.css_imports_suspicious_domain, normalized.normalized, {});
      }
    }
  }
  if (/(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|position\s*:\s*absolute[^}]+left\s*:\s*-\d+)/i.test(text)) {
    increment(state, "hidden_css");
    addRuleFinding(state, cssRules.hidden_link_cluster, pageUrl(state) ?? "css", {});
  }
  if (
    state.forms.some((form) => form.hasPassword || form.hasPayment) &&
    /\b(?:form|input|password|card|cc-|checkout|payment)\b/i.test(text) &&
    /(?:position\s*:\s*(?:fixed|absolute)[^}]+(?:opacity\s*:\s*0|z-index\s*:\s*9\d{2,}|pointer-events\s*:\s*auto)|(?:opacity\s*:\s*0[^}]+position\s*:\s*(?:fixed|absolute)))/i.test(text)
  ) {
    increment(state, "invisible_form_overlay");
  }
  if (/unicode-bidi\s*:\s*bidi-override/i.test(text)) {
    addRuleFinding(state, cssRules.unicode_bidi_trick, pageUrl(state) ?? "css", {});
  }
}

function scanSourceText(state: ScannerState, text: string): void {
  for (const rule of sourceCodeRules) {
    if (rule.pattern.test(text)) {
      addRuleFinding(state, rule, state.source.filename ?? state.source.url ?? "source", {});
    }
  }
}

function shouldScanSourceText(state: ScannerState): boolean {
  if (state.source.filename) return true;
  return state.contentKind === "javascript" || state.contentKind === "json" || state.contentKind === "text";
}

function isPrimitiveJavaScriptSignal(ruleId: string): boolean {
  return [
    "document_write_script",
    "innerhtml_script_injection",
    "insert_adjacent_html",
    "dynamic_script_src",
    "script_src_assignment",
    "append_child_script",
    "external_request_api_seen",
    "js_location_external",
    "decoder_seen",
    "charcodeat_decoder_loop",
    "browser_storage_or_clipboard_seen"
  ].includes(ruleId);
}

function scanBinaryHeader(state: ScannerState, chunk: Uint8Array): void {
  if (state.binaryHeaderScanned) return;
  state.binaryHeaderScanned = true;
  if (!hasElfMagic(chunk)) return;
  addRuleFinding(state, binaryRules.elf_executable_magic, state.source.url ?? state.source.filename ?? "stream", {});
  if (declaredNonExecutableBinary(state.source.contentType)) {
    addRuleFinding(state, binaryRules.content_type_magic_mismatch, state.source.url ?? state.source.filename ?? "stream", {
      content_type: state.source.contentType ?? ""
    });
  }
  if (elfHasWritableExecutableStack(chunk)) {
    addRuleFinding(state, binaryRules.elf_writable_executable_stack, state.source.url ?? state.source.filename ?? "stream", {});
  }
}

function scanBinaryStrings(state: ScannerState, text: string): void {
  for (const rule of binaryStringRules) {
    if (rule.pattern.test(text)) {
      increment(state, rule.counter ?? rule.id);
      addRuleFinding(state, rule, state.source.url ?? state.source.filename ?? "binary", {});
    }
  }
}

function decodeAndRescan(state: ScannerState, text: string, offset: number, depth: number, maxDecodedBytes: number, maxDecodeDepth: number): void {
  const candidates: Array<[string, string, number]> = [];
  for (const match of text.matchAll(/[A-Za-z0-9+/]{32,}={0,2}/g)) {
    const index = match.index ?? 0;
    const context = text.slice(Math.max(0, index - 80), Math.min(text.length, index + match[0].length + 80));
    if (/\batob\s*\(|fromBase64|Buffer\.from\s*\([^)]*base64/i.test(context)) candidates.push(["base64_decoded_string", match[0], index]);
  }
  for (const match of text.matchAll(/(?:\\x[0-9a-fA-F]{2}){8,}/g)) candidates.push(["javascript_hex_escapes", match[0], match.index ?? 0]);
  for (const match of text.matchAll(/(?:\\u[0-9a-fA-F]{4}){6,}/g)) candidates.push(["javascript_unicode_escapes", match[0], match.index ?? 0]);
  for (const match of text.matchAll(/String\.fromCharCode\s*\(([\d,\s]+)\)/g)) candidates.push(["fromcharcode_decoded_string", match[1], match.index ?? 0]);

  for (const [artifactType, value, index] of candidates.slice(0, 8)) {
    const decoded = decodeCandidate(artifactType, value, maxDecodedBytes);
    if (!decoded || decoded.length < 8) continue;
    state.artifacts.push({
      source: state.source.filename ?? state.source.url ?? "stream",
      artifactType,
      parentOffset: offset + index,
      depth: depth + 1,
      text: decoded.slice(0, 4096)
    });
    increment(state, artifactType);
    const rule = decodedArtifactRules[artifactType === "base64_decoded_string" ? "large_base64_blob" : artifactType as keyof typeof decodedArtifactRules];
    addRuleFinding(state, rule, state.source.filename ?? state.source.url ?? "stream", { depth: depth + 1 });
    if (depth + 1 < maxDecodeDepth) scanText(state, decoded, offset + index, depth + 1, maxDecodedBytes, maxDecodeDepth);
  }
}

function finalizeAggregateRules(state: ScannerState): void {
  for (const form of state.forms) {
    const action = form.action ? normalizeUrl(form.action, pageUrl(state)) : null;
    if (form.hasPassword && pageUrl(state)?.startsWith("http://")) {
      addRuleFinding(state, htmlRules.password_form_without_https, pageUrl(state) ?? "form", {});
    }
    if (form.hasPassword && action?.relation === "off-site") {
      addRuleFinding(state, htmlRules.credential_form_posts_off_origin, action.normalized, {});
    }
    if (form.hasPayment && [...state.urls.values()].some((url) => url.relation === "off-site")) {
      addRuleFinding(state, htmlRules.card_fields_plus_external_script, pageUrl(state) ?? "payment-form", {});
    }
    if (form.hasPassword && hasSuspiciousTargetContext(state)) {
      addRuleFinding(state, htmlRules.credential_form_on_suspicious_host, pageUrl(state) ?? "form", {});
    }
  }
  const externalScripts = [...state.findings].filter((finding) => finding.ruleId === "external_script_from_unrelated_domain").length;
  const hasSensitivePageContext = state.forms.some((form) => form.hasPassword || form.hasPayment);
  if (hasSensitivePageContext) {
    for (const script of state.externalScripts) {
      addRuleFinding(state, htmlRules.external_script_from_unrelated_domain, script.normalized, { relation: script.relation });
    }
  }
  const riskyExternalScripts = hasSensitivePageContext ? state.externalScripts.length : externalScripts;
  if (riskyExternalScripts >= 5 && hasSensitivePageContext) {
    addRuleFinding(state, htmlRules.excessive_external_scripts_on_login_page, pageUrl(state) ?? "site", { external_scripts: riskyExternalScripts });
  }
  if ([...state.urls.values()].some((url) => url.flags.includes("punycode")) && incremented(state, "brand_login_or_payment_language")) {
    addRuleFinding(state, htmlRules.login_page_with_punycode_links, pageUrl(state) ?? "site", {});
  }
  if (incremented(state, "content.login_ui_image_reference")) {
    addRuleFinding(state, htmlRules.credential_ui_rendered_as_image, pageUrl(state) ?? "site", {});
  }
  // Crypto trigger-word signals only count on an already-suspicious host. They
  // were built for shared-hosted crypto phishing; on reputable hosts (e.g. a
  // LinkedIn login page that merely contains "wallet"/"swap" in bundled JS) they
  // are pure noise.
  if (hasSuspiciousTargetContext(state)) {
    if (incremented(state, "content.crypto_wallet_login_language")) {
      addRuleFinding(state, htmlRules.crypto_wallet_login_language, pageUrl(state) ?? "site", {});
    }
    if (incremented(state, "content.crypto_trading_landing_language")) {
      addRuleFinding(state, htmlRules.crypto_trading_landing_language, pageUrl(state) ?? "site", {});
    }
  }
  if (incremented(state, "content.seo_trademark_stuffing")) {
    addRuleFinding(state, htmlRules.seo_trademark_stuffing, pageUrl(state) ?? "site", {});
  }
}

export function scoreFindings(findings: Finding[]): number {
  let score = 0;
  const groups = new Map<string, Finding[]>();
  const tags = new Set<ScoreTag>();
  for (const finding of findings) {
    const group = groups.get(finding.ruleId);
    if (group) group.push(finding);
    else groups.set(finding.ruleId, [finding]);
    for (const tag of finding.scoreModel.tags) tags.add(tag);
  }
  for (const group of groups.values()) {
    const model = group[0].scoreModel;
    const repeats = Math.min(group.length - 1, model.maxRepeats ?? 0);
    score += model.base + repeats * model.base * (model.repeatMultiplier ?? 0);
  }
  score *= scoreMultiplier(tags);
  return Math.max(0, Math.min(100, Math.round(score)));
}

function scoreMultiplier(tags: Set<ScoreTag>): number {
  let multiplier = 1;
  if (tags.has("credential") && (tags.has("hosting") || tags.has("redirect") || tags.has("url"))) multiplier *= 1.2;
  if ((tags.has("payment") || tags.has("wallet")) && (tags.has("exfiltration") || tags.has("redirect"))) multiplier *= 1.15;
  if (tags.has("decoded") && (tags.has("script") || tags.has("exfiltration"))) multiplier *= 1.15;
  if (tags.has("binary") && tags.has("url")) multiplier *= 1.1;
  return multiplier;
}

export function dispositionForScore(score: number): Disposition {
  if (score >= 75) return "block";
  if (score >= 50) return "review";
  if (score >= 25) return "warn";
  return "allow";
}

function collectUrls(state: ScannerState, text: string): void {
  for (const match of text.matchAll(/\bhttps?:\/\/[^\s"'<>`\\)]+/gi)) addUrl(state, match[0].replace(/[.,;:]+$/, ""));
}

function urlsInText(text: string, base?: string): ExtractedUrl[] {
  const urls: ExtractedUrl[] = [];
  for (const match of text.matchAll(/\bhttps?:\/\/[^\s"'<>`\\)]+/gi)) {
    const normalized = normalizeUrl(match[0].replace(/[.,;:]+$/, ""), base);
    if (normalized) urls.push(normalized);
  }
  return urls;
}

function hasNearbyOffSiteUrlWith(text: string, base: string | undefined, signal: RegExp): boolean {
  for (const match of text.matchAll(/\bhttps?:\/\/[^\s"'<>`\\)]+/gi)) {
    const normalized = normalizeUrl(match[0].replace(/[.,;:]+$/, ""), base);
    if (!normalized || (normalized.relation !== "off-site" && !(normalized.relation === "unknown" && !!normalized.registrableDomain))) continue;
    const index = match.index ?? 0;
    const context = text.slice(Math.max(0, index - 160), Math.min(text.length, index + match[0].length + 160));
    if (/\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)\b/.test(context) && signal.test(context)) return true;
  }
  return false;
}

function hasWalletSignal(text: string): boolean {
  return /\b(?:window\.ethereum|WalletConnect|ethereum\.request)\b/i.test(text) || /\.(?:approve|permit)\s*\(/i.test(text) || /\bmethod\s*:\s*['"]eth_/i.test(text);
}

function hasNearbyRegexPair(text: string, left: RegExp, right: RegExp, distance: number): boolean {
  const leftPositions = [...text.matchAll(left)].map((match) => match.index ?? 0);
  const rightPositions = [...text.matchAll(right)].map((match) => match.index ?? 0);
  return leftPositions.some((leftIndex) => rightPositions.some((rightIndex) => Math.abs(leftIndex - rightIndex) <= distance));
}

function hasRiskyUrlFlags(url: ExtractedUrl): boolean {
  return url.flags.some((flag) => ["punycode", "ip_literal", "private_or_localhost", "url_shortener", "suspicious_tld", "suspicious_path_terms", "malware_download_like_path"].includes(flag));
}

function hasCryptoWalletLoginLanguage(text: string): boolean {
  // Require a strong, crypto-specific term (not bare "crypto"/"ledger", which
  // collide with normal sites) paired with credential/wallet-connect intent.
  return /\b(?:metamask|walletconnect|usdt|tether|trust\s+wallet|seed\s+phrase|connect\s+wallet|coinbase|binance|web3)\b/i.test(text) &&
    /\b(?:login|log\s*in|sign\s*in|connect|password|securely|access|restore|import)\b/i.test(text);
}

function hasCryptoTradingLandingLanguage(text: string): boolean {
  // Crypto-native vocabulary. Generic finance words (token, exchange, trade,
  // market, liquidity) are excluded — they appear on ordinary sites and in
  // minified JS (CSRF/OAuth "token"). The emitted finding is additionally gated
  // on a suspicious host (see finalizeAggregateRules) so reputable sites that
  // merely mention crypto don't trip it.
  const matches = text.match(/\b(?:crypto|defi|dexs?|solana|swap|blockchain|wallet|web3|metamask|walletconnect|usdt|tether|coinbase|binance|jupiter|airdrop|staking|seed\s+phrase)\b/gi) ?? [];
  return new Set(matches.map((match) => match.toLowerCase())).size >= 2;
}

function hasSeoTrademarkStuffing(text: string): boolean {
  const values = [
    ...[...text.matchAll(/<title[^>]*>([^<]{0,240})<\/title>/gis)].map((match) => match[1]),
    ...[...text.matchAll(/"(?:title|children)"\s*:\s*"([^"]{0,240})"/gis)].map((match) => match[1]),
    ...[...text.matchAll(/"(?:og:title|twitter:title)"\s*,\s*"content"\s*:\s*"([^"]{0,240})"/gis)].map((match) => match[1])
  ];
  return values.some((value) => (value.match(/[®™]/g) ?? []).length >= 2);
}

function hasLoginUiImageReference(text: string): boolean {
  return /(?:imageData|alt|name|src|media|filename|fileName|url)["':\s{,[\]\\]*(?:[^"'<>]{0,160})?(?:screencapture|screenshot|screen[-_ ]?capture)/i.test(text) ||
    /(?:screencapture|screenshot|screen[-_ ]?capture)[^"'<>]{0,160}\b(?:login|log[-_ ]?in|signin|sign[-_ ]?in|password|account)\b/i.test(text) ||
    /\b(?:login|log[-_ ]?in|signin|sign[-_ ]?in|password|account)\b[^"'<>]{0,160}(?:screencapture|screenshot|screen[-_ ]?capture)/i.test(text);
}

function hasSuspiciousTargetContext(state: ScannerState): boolean {
  if (incremented(state, "redirect.final_url_offsite")) return true;
  // Genuine HOST suspicion only. A login-intent path ("/login", "/account") is
  // benign — every legitimate login page has one — so suspicious_path_terms is
  // deliberately excluded here.
  return [...state.urls.values()].some((url) =>
    isSourceOrFinalUrl(state, url.normalized) &&
    url.flags.some((flag) => ["shared_hosting_subdomain", "generated_host_label", "suspicious_tld", "punycode", "ip_literal"].includes(flag))
  );
}

function scanRedirectContext(state: ScannerState): void {
  if (!state.source.url || !state.source.finalUrl || state.source.url === state.source.finalUrl) return;
  const source = normalizeUrl(state.source.url);
  const final = normalizeUrl(state.source.finalUrl, state.source.url);
  if (source?.registrableDomain && final?.registrableDomain && source.registrableDomain !== final.registrableDomain) {
    increment(state, "redirect.final_url_offsite");
    addRuleFinding(state, urlRules.final_url_offsite_redirect, final.normalized, { source_url: source.normalized });
  }
}

function scanTlsContext(state: ScannerState): void {
  const tls = state.source.tls;
  if (!tls) return;
  const issuer = tls.issuer ?? "";
  const subject = tls.subject ?? "";
  if (tls.authorized === false) increment(state, "tls.unauthorized_certificate");
  if (/(?:let'?s encrypt|zerossl|buypass|ssl\.com)/i.test(issuer)) increment(state, "tls.free_dv_certificate");
  const organization = subject.match(/(?:^|,\s*)O\s*=\s*([^,]+)/i)?.[1]?.trim();
  if (organization && !/^(?:cloudflare|google trust services|amazon|fastly|akamai|wix|netlify|vercel)\b/i.test(organization)) {
    increment(state, "tls.organization_validated_certificate");
  }
  if (issuer) increment(state, `tls.issuer.${issuer.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 80)}`);
}

function extractCssUrls(text: string): string[] {
  const urls: string[] = [];
  for (const match of text.matchAll(/@import\s+(?:url\(\s*)?["']?([^"')\s;]+)|url\(\s*["']?([^"')]+)["']?\s*\)/gi)) {
    const raw = (match[1] ?? match[2] ?? "").trim().replace(/[.,;:]+$/, "");
    if (/^https?:\/\//i.test(raw)) urls.push(raw);
  }
  return urls;
}

function addUrl(state: ScannerState, raw: string): void {
  const normalized = normalizeUrl(raw, pageUrl(state));
  if (!normalized) return;
  state.urls.set(normalized.normalized, normalized);
  for (const flag of normalized.flags) increment(state, `url.${flag}`);
  if (normalized.flags.includes("punycode") && /login|signin|account|verify/i.test(normalized.normalized)) {
    addRuleFinding(state, urlRules.punycode_login_url, normalized.normalized, {});
  }
  if (normalized.destinationType === "url-shortener") {
    addRuleFinding(state, urlRules.redirect_to_url_shortener, normalized.normalized, {});
  }
  if (normalized.flags.includes("private_or_localhost") && isSourceOrFinalUrl(state, normalized.normalized)) {
    addRuleFinding(state, urlRules.private_ip_url, normalized.normalized, {});
  }
  if (normalized.flags.includes("ip_literal") && !normalized.flags.includes("private_or_localhost")) {
    addRuleFinding(state, urlRules.ip_literal_url, normalized.normalized, {});
  }
  if (normalized.flags.includes("suspicious_tld")) {
    addRuleFinding(state, urlRules.suspicious_tld_url, normalized.normalized, {});
  }
  if (normalized.flags.includes("download_like_path") && normalized.relation === "off-site") {
    addRuleFinding(state, urlRules.download_like_external_url, normalized.normalized, {});
  }
  if (normalized.flags.includes("malware_download_like_path") && isSourceOrFinalUrl(state, normalized.normalized)) {
    addRuleFinding(state, urlRules.malware_download_like_url, normalized.normalized, {});
  }
  if (normalized.flags.includes("shared_hosting_subdomain") && isSourceOrFinalUrl(state, normalized.normalized)) {
    addRuleFinding(state, urlRules.shared_hosting_subdomain_url, normalized.normalized, {});
  }
  const brand = unrelatedBrandInUrl(normalized);
  if (brand && isSourceOrFinalUrl(state, normalized.normalized)) {
    addRuleFinding(state, urlRules.brand_impersonation_url, normalized.normalized, { brand });
  }
  if (isSourceOrFinalUrl(state, normalized.normalized) && isCredentialPathOnSuspiciousHost(normalized)) {
    addRuleFinding(state, urlRules.credential_path_on_suspicious_host, normalized.normalized, {});
  }
  if (isSourceOrFinalUrl(state, normalized.normalized) && isGeneratedSuspiciousLandingUrl(normalized)) {
    addRuleFinding(state, urlRules.generated_landing_url, normalized.normalized, {});
  }
}

function isSourceOrFinalUrl(state: ScannerState, normalizedUrl: string): boolean {
  const source = state.source.url ? normalizeUrl(state.source.url)?.normalized : null;
  const final = state.source.finalUrl ? normalizeUrl(state.source.finalUrl)?.normalized : null;
  return normalizedUrl === source || normalizedUrl === final;
}

function addRuleFinding(state: ScannerState, rule: RuleDefinition, locationValue: string, metadata: Record<string, unknown>): void {
  addFinding(state, rule.id, rule.severity, rule.confidence, rule.score, rule.title, rule.description, rule.locationType, locationValue, { ...metadata, rule_pack: rule.pack });
}

function addFinding(
  state: ScannerState,
  ruleId: string,
  severity: Severity,
  confidence: Confidence,
  scoreModel: RuleScoreModel,
  title: string,
  description: string,
  locationType: Finding["locationType"],
  locationValue: string,
  metadata: Record<string, unknown>
): void {
  const key = `${ruleId}:${locationType}:${locationValue}`;
  if (state.findingKeys.has(key)) return;
  state.findingKeys.add(key);
  state.findings.push({
    id: `${ruleId}:${state.findings.length}`,
    ruleId,
    severity,
    confidence,
    score: scoreModel.base,
    scoreModel,
    title,
    description,
    locationType,
    locationValue,
    metadata: { line: state.line, column: state.column, ...metadata }
  });
}

function parseAttrs(input: string): Map<string, string> {
  const attrs = new Map<string, string>();
  for (const match of input.matchAll(/([a-z0-9:_-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/gi)) {
    attrs.set(match[1].toLowerCase(), match[2] ?? match[3] ?? match[4] ?? "");
  }
  return attrs;
}

function hiddenAttrs(attrs: Map<string, string>): boolean {
  const width = Number(attrs.get("width") ?? "1");
  const height = Number(attrs.get("height") ?? "1");
  return width <= 1 || height <= 1 || /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i.test(attrs.get("style") ?? "");
}

function decodeCandidate(kind: string, value: string, maxBytes: number): string | null {
  try {
    if (kind === "base64_decoded_string") {
      const bytes = base64Decode(value);
      if (!bytes || bytes.byteLength > maxBytes) return null;
      const decoded = decodeText(bytes);
      return isMostlyPrintable(decoded) ? decoded : null;
    }
    if (kind === "javascript_hex_escapes") return value.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16))).slice(0, maxBytes);
    if (kind === "javascript_unicode_escapes") return value.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16))).slice(0, maxBytes);
    if (kind === "fromcharcode_decoded_string") return value.split(",").map((part) => String.fromCharCode(Number(part.trim()))).join("").slice(0, maxBytes);
  } catch {
    return null;
  }
  return null;
}

function base64Decode(value: string): Uint8Array | null {
  if (typeof atob === "function") {
    const binary = atob(value);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }
  const bufferCtor = (globalThis as unknown as { Buffer?: { from(value: string, encoding: string): Uint8Array } }).Buffer;
  return bufferCtor?.from(value, "base64") ?? null;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.ruleId}:${finding.locationValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function relationFor(host: string, domain: string | null, baseHost: string, baseDomain: string | null): ExtractedUrl["relation"] {
  if (!baseHost || !baseDomain || !domain) return "unknown";
  if (host === baseHost) return "same-origin";
  if (domain === baseDomain) return host.endsWith(`.${baseHost}`) ? "subdomain" : "same-site";
  return "off-site";
}

function destinationTypeFor(url: URL, host: string): ExtractedUrl["destinationType"] {
  if (isPrivateHost(host)) return host === "localhost" ? "localhost" : "private";
  if (isIpLiteral(host)) return "ip";
  if (isUrlShortener(host)) return "url-shortener";
  if (url.protocol === "http:") return "http";
  if (url.protocol === "https:") return "https";
  return "other";
}

export function registrableDomainFor(host: string): string | null {
  if (!host || isIpLiteral(host) || host === "localhost") return null;
  const parts = host.toLowerCase().split(".").filter(Boolean);
  if (parts.length < 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  const lastThree = parts.slice(-3).join(".");
  if (/^(?:co|com|net|org|gov|ac)\.[a-z]{2}$/.test(lastTwo) && parts.length >= 3) return lastThree;
  return lastTwo;
}

function isIpLiteral(host: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
}

function isPrivateHost(host: string): boolean {
  return host === "localhost" || /^127\.|^10\.|^192\.168\.|^172\.(?:1[6-9]|2\d|3[01])\./.test(host);
}

function isUrlShortener(host: string): boolean {
  return /^(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly)$/.test(host);
}

function isSharedHostingSubdomain(host: string, registrableDomain: string | null): boolean {
  if (!registrableDomain || host === registrableDomain) return false;
  return [
    "wixstudio.com",
    "wixsite.com",
    "webflow.io",
    "netlify.app",
    "vercel.app",
    "github.io",
    "pages.dev",
    "workers.dev",
    "firebaseapp.com",
    "web.app",
    "herokuapp.com",
    "render.com",
    "glitch.me",
    "replit.app",
    "replit.dev",
    "wordpress.com",
    "blogspot.com",
    "weebly.com",
    "myshopify.com",
    "godaddysites.com",
    "zapier.app",
    "fwh.is",
    "infinityfreeapp.com",
    "000webhostapp.com",
    "fly.dev",
    "onrender.com",
    "surge.sh",
    "site.je"
  ].includes(registrableDomain);
}

function isGeneratedHostLabel(host: string, registrableDomain: string | null): boolean {
  const label = host.split(".")[0] ?? "";
  if (!label || label === registrableDomain) return false;
  return /(?:client|account|secure|manager|payment|support|verify|login|area)[-_]?\d{5,}/i.test(label) ||
    /^[a-z]+(?:-[a-z]+){2,}-\d{4,}$/.test(label) ||
    /^[a-z0-9]{16,}$/.test(label);
}

// Well-known ad, analytics, and tag-manager networks. Scripts from these are
// ubiquitous on legitimate ad-funded sites and are never phishing exfil
// endpoints, so they should not raise the external-script signals that target
// credential-harvest kits.
const AD_ANALYTICS_DOMAINS = new Set([
  "doubleclick.net",
  "googlesyndication.com",
  "googletagmanager.com",
  "googletagservices.com",
  "google-analytics.com",
  "googleadservices.com",
  "adservice.google.com",
  "gstatic.com",
  "scorecardresearch.com",
  "quantserve.com",
  "quantcount.com",
  "criteo.com",
  "criteo.net",
  "taboola.com",
  "outbrain.com",
  "adnxs.com",
  "rubiconproject.com",
  "pubmatic.com",
  "casalemedia.com",
  "amazon-adsystem.com",
  "adsrvr.org",
  "moatads.com",
  "indexww.com",
  "openx.net",
  "3lift.com",
  "sharethrough.com",
  "permutive.com",
  "permutive.app",
  "cloudflareinsights.com",
  "newrelic.com",
  "nr-data.net",
  "segment.com",
  "segment.io",
  "optimizely.com",
  "hotjar.com",
  "chartbeat.com",
  "parsely.com",
  "branch.io",
  "onetrust.com",
  "cookielaw.org",
  "fbcdn.net",
  "facebook.net"
]);

export function isAdOrAnalyticsHost(normalizedUrl: string): boolean {
  try {
    const host = new URL(normalizedUrl).hostname.toLowerCase();
    return AD_ANALYTICS_DOMAINS.has(registrableDomainFor(host) ?? host);
  } catch {
    return false;
  }
}

function isSuspiciousTld(host: string): boolean {
  const tld = host.split(".").pop() ?? "";
  return /^(?:zip|mov|top|xyz|click|country|gq|tk|ml|cf|ga|work|quest|cam|cfd|icu|buzz)$/.test(tld);
}

function isMalwareDownloadLikePath(pathname: string): boolean {
  return /(?:\/|^)(?:bin|bins|payload|update|loader|bot|mozi|mirai|gafgyt|boatnet|dvr)(?:[./_-]|$)|\.(?:sh|bash|elf|bin|mips|mpsl|arm\d?|x86|x86_64|i686|ppc|sparc)(?:$|[?#])|(?:\/|^)(?:mips|arm\d?|x86|x86_64|i686|ppc|sparc)(?:$|[./_-])/i.test(pathname);
}

// Brand keywords + the brand's legitimate registrable domains. Matched against
// HOST LABELS only (never the path/query — so google.com/search?q=paypal is
// safe), as an exact label or, for >=6-char keywords, a label prefix to catch
// concatenated lookalikes like "scotiawealthmanagement.com.evil.tld".
const PHISH_BRANDS: Array<{ brand: string; keywords: string[]; allowed: RegExp }> = [
  { brand: "google", keywords: ["google", "gmail"], allowed: /(?:^|\.)(?:google|gmail)\.(?:com|[a-z]{2})$/i },
  { brand: "microsoft", keywords: ["microsoft", "office365", "outlook", "onedrive"], allowed: /(?:^|\.)(?:microsoft|microsoftonline|live|office|outlook|sharepoint)\.com$/i },
  { brand: "apple", keywords: ["icloud", "appleid"], allowed: /(?:^|\.)(?:apple|icloud)\.com$/i },
  { brand: "paypal", keywords: ["paypal", "paypa1"], allowed: /(?:^|\.)paypal\.(?:com|[a-z]{2})$/i },
  { brand: "amazon", keywords: ["amazon"], allowed: /(?:^|\.)(?:amazon\.[a-z.]{2,6}|amazonaws\.com|aws\.amazon\.com)$/i },
  { brand: "netflix", keywords: ["netflix"], allowed: /(?:^|\.)netflix\.com$/i },
  { brand: "facebook", keywords: ["facebook"], allowed: /(?:^|\.)(?:facebook|meta)\.com$/i },
  { brand: "instagram", keywords: ["instagram"], allowed: /(?:^|\.)instagram\.com$/i },
  { brand: "whatsapp", keywords: ["whatsapp"], allowed: /(?:^|\.)whatsapp\.com$/i },
  { brand: "linkedin", keywords: ["linkedin"], allowed: /(?:^|\.)linkedin\.com$/i },
  { brand: "dropbox", keywords: ["dropbox"], allowed: /(?:^|\.)dropbox\.com$/i },
  { brand: "docusign", keywords: ["docusign"], allowed: /(?:^|\.)docusign\.(?:com|net)$/i },
  { brand: "wetransfer", keywords: ["wetransfer"], allowed: /(?:^|\.)wetransfer\.com$/i },
  { brand: "dhl", keywords: ["dhl"], allowed: /(?:^|\.)dhl\.(?:com|[a-z]{2})$/i },
  { brand: "fedex", keywords: ["fedex"], allowed: /(?:^|\.)fedex\.com$/i },
  { brand: "usps", keywords: ["usps"], allowed: /(?:^|\.)usps\.com$/i },
  { brand: "roblox", keywords: ["roblox"], allowed: /(?:^|\.)roblox\.com$/i },
  { brand: "steam", keywords: ["steamcommunity", "steampowered"], allowed: /(?:^|\.)steam(?:community|powered)\.com$/i },
  { brand: "scotiabank", keywords: ["scotiabank", "scotiawealth", "scotiaonline"], allowed: /(?:^|\.)scotiabank\.com$/i },
  { brand: "wellsfargo", keywords: ["wellsfargo"], allowed: /(?:^|\.)wellsfargo\.com$/i },
  { brand: "chase", keywords: ["chase"], allowed: /(?:^|\.)chase\.com$/i },
  { brand: "bankofamerica", keywords: ["bankofamerica"], allowed: /(?:^|\.)bankofamerica\.com$/i },
  { brand: "citi", keywords: ["citibank", "citigroup"], allowed: /(?:^|\.)citi\.com$/i },
  { brand: "coinbase", keywords: ["coinbase"], allowed: /(?:^|\.)coinbase\.com$/i },
  { brand: "binance", keywords: ["binance"], allowed: /(?:^|\.)binance\.(?:com|us)$/i },
  { brand: "kraken", keywords: ["kraken"], allowed: /(?:^|\.)kraken\.com$/i },
  { brand: "metamask", keywords: ["metamask"], allowed: /(?:^|\.)metamask\.io$/i },
  { brand: "ledger", keywords: ["ledger"], allowed: /(?:^|\.)ledger\.com$/i },
  { brand: "tangem", keywords: ["tangem"], allowed: /(?:^|\.)tangem\.com$/i },
  { brand: "etoro", keywords: ["etoro"], allowed: /(?:^|\.)etoro\.com$/i },
  { brand: "ionos", keywords: ["ionos"], allowed: /(?:^|\.)ionos\.(?:com|de|co\.uk)$/i },
  { brand: "allegro", keywords: ["allegro"], allowed: /(?:^|\.)allegro\.(?:pl|com)$/i }
];

// Normalize leetspeak / homoglyph substitutions so g00gle, paypa1, micr0s0ft,
// 0utlook, faceb00k collapse onto their brand spelling. "1" is ambiguous (i or
// l), so callers check both variants. Non-alphanumerics are dropped last.
function deleet(label: string, one: "i" | "l"): string {
  return label
    .replace(/0/g, "o")
    .replace(/1/g, one)
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b")
    .replace(/9/g, "g")
    .replace(/\$/g, "s")
    .replace(/@/g, "a")
    .replace(/!/g, "i")
    .replace(/[^a-z]/g, "");
}

function unrelatedBrandInUrl(url: ExtractedUrl): string | null {
  let host: string;
  try {
    host = new URL(url.normalized).hostname.toLowerCase();
  } catch {
    return null;
  }
  const labels = host.split(/[.\-_]/).filter(Boolean);
  // Raw labels plus leet/homoglyph-normalized variants (both "1" readings).
  const variants = [...new Set(labels.flatMap((label) => [label, deleet(label, "i"), deleet(label, "l")]))].filter(Boolean);
  for (const { brand, keywords, allowed } of PHISH_BRANDS) {
    if (allowed.test(host)) continue;
    const hit = keywords.some((kw) => variants.some((label) => label === kw || (kw.length >= 6 && label.startsWith(kw))));
    if (hit) return brand;
  }
  return null;
}

const SUSPICIOUS_HOST_FLAGS = ["shared_hosting_subdomain", "generated_host_label", "suspicious_tld", "punycode", "ip_literal", "url_shortener"];

// Login/account/verify path served from a host that legitimate brands never use
// for credentials. Render-free — fires on the URL alone, before any form loads.
function isCredentialPathOnSuspiciousHost(url: ExtractedUrl): boolean {
  return url.flags.includes("suspicious_path_terms") && url.flags.some((flag) => SUSPICIOUS_HOST_FLAGS.includes(flag));
}

function isGeneratedSuspiciousLandingUrl(url: ExtractedUrl): boolean {
  const parsed = new URL(url.normalized);
  const host = parsed.hostname.toLowerCase();
  const firstLabel = host.split(".")[0] ?? "";
  const path = parsed.pathname.toLowerCase();
  const generatedLabel = /^[a-z]{6,10}$/.test(firstLabel) || /^[a-z0-9]{8,18}$/.test(firstLabel);
  const uuidPath = /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\/|$)/i.test(path);
  const fakeUpdateHost = /\.(?:casino|sbs|xyz|top|click|app|co)$/.test(host) || /(?:bet|casino|poker|winx|winsport|perfectgame|parspoker|venusbet)/i.test(host);
  return generatedLabel && uuidPath && fakeUpdateHost;
}

function hasElfMagic(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
}

function declaredNonExecutableBinary(contentType?: string | null): boolean {
  const value = (contentType ?? "").toLowerCase().split(";")[0].trim();
  return !!value && !/(?:elf|executable|x-executable|x-pie-executable|octet-stream)/.test(value);
}

function likelyBinaryStrings(text: string): boolean {
  return /(?:\/bin\/sh|\/dev\/shm|\/proc\/net\/route|iptables|busybox|cfgtool|sendcmd|\[cnc\]|1:q9:find_node|Mozi\.)/i.test(text);
}

function elfHasWritableExecutableStack(bytes: Uint8Array): boolean {
  if (!hasElfMagic(bytes) || bytes.length < 52) return false;
  const dataView = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const littleEndian = bytes[5] !== 2;
  const elfClass = bytes[4];
  const programHeaderOffset = elfClass === 2
    ? Number(dataView.getBigUint64(32, littleEndian))
    : dataView.getUint32(28, littleEndian);
  const programHeaderEntrySize = dataView.getUint16(elfClass === 2 ? 54 : 42, littleEndian);
  const programHeaderCount = dataView.getUint16(elfClass === 2 ? 56 : 44, littleEndian);
  if (!programHeaderOffset || !programHeaderEntrySize || !programHeaderCount) return false;
  const PT_GNU_STACK = 0x6474e551;
  const PF_X = 0x1;
  const PF_W = 0x2;
  for (let index = 0; index < programHeaderCount; index += 1) {
    const offset = programHeaderOffset + index * programHeaderEntrySize;
    if (offset + 8 > bytes.length) return false;
    const type = dataView.getUint32(offset, littleEndian);
    const flags = elfClass === 2
      ? dataView.getUint32(offset + 4, littleEndian)
      : dataView.getUint32(offset + 24, littleEndian);
    if (type === PT_GNU_STACK && (flags & PF_X) && (flags & PF_W)) return true;
  }
  return false;
}

function scanTechnologyFingerprint(state: ScannerState, text: string, locationValue: string): void {
  if (/\bjquery[-.]1\.\d+(?:\.\d+)?(?:\.min)?\.js\b|jQuery v1\./i.test(text)) {
    addRuleFinding(state, htmlTechnologyRules.legacy_jquery_reference, locationValue, {});
  }
  if (/\bangular(?:\.min)?\.js\b|angularjs|AngularJS v1\.|angular\.version/i.test(text)) {
    addRuleFinding(state, htmlTechnologyRules.legacy_angularjs_reference, locationValue, {});
  }
  if (/\bbootstrap(?:\.min)?\.js\b|bootstrap[-.]3\.\d+(?:\.\d+)?(?:\.min)?\.js\b|Bootstrap v3\./i.test(text)) {
    addRuleFinding(state, htmlTechnologyRules.legacy_bootstrap_reference, locationValue, {});
  }
  if (/\blodash[-.]4\.17\.(?:[0-9]|1[0-9]|20)(?:\.min)?\.js\b|lodash v4\.17\.(?:[0-9]|1[0-9]|20)/i.test(text)) {
    addRuleFinding(state, htmlTechnologyRules.legacy_lodash_reference, locationValue, {});
  }
  if (/(?:sites\/default\/files|drupal-settings-json|Drupal\.settings|\/core\/misc\/drupal\.js)/i.test(text)) {
    addRuleFinding(state, htmlTechnologyRules.drupal_surface_reference, locationValue, {});
  }
  if (/\b(?:phpMyAdmin|pma_navigation|\/phpmyadmin\/|\/pma\/)\b/i.test(text)) {
    addRuleFinding(state, htmlTechnologyRules.phpmyadmin_surface_reference, locationValue, {});
  }
}

function pageUrl(state: ScannerState): string | undefined {
  return state.source.finalUrl ?? state.source.url ?? state.source.originUrl;
}

function decodeText(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function trimWindow(value: string, max: number): string {
  return value.length <= max ? value : value.slice(value.length - max);
}

function updatePosition(state: ScannerState, text: string): void {
  for (const char of text) {
    if (char === "\n") {
      state.line += 1;
      state.column = 1;
    } else {
      state.column += 1;
    }
  }
  state.counters.lines_seen = state.line;
  state.counters.bytes_seen = state.absoluteOffset;
}

function byteLength(text: string): number {
  return new TextEncoder().encode(text).byteLength;
}

function isMostlyPrintable(text: string): boolean {
  if (!text) return false;
  const sample = text.slice(0, 4096);
  const printable = [...sample].filter((char) => char === "\n" || char === "\r" || char === "\t" || (char >= " " && char !== "\uFFFD")).length;
  return printable / sample.length >= 0.85;
}

function increment(state: ScannerState, key: string): void {
  state.counters[key] = (state.counters[key] ?? 0) + 1;
}

function incremented(state: ScannerState, key: string): boolean {
  return (state.counters[key] ?? 0) > 0;
}
