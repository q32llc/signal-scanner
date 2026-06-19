import type { RuleDefinition } from "../types.js";

export const urlRules: Record<
  | "punycode_login_url"
  | "redirect_to_url_shortener"
  | "final_url_offsite_redirect"
  | "private_ip_url"
  | "ip_literal_url"
  | "suspicious_tld_url"
  | "download_like_external_url"
  | "malware_download_like_url"
  | "shared_hosting_subdomain_url"
  | "brand_impersonation_url"
  | "credential_path_on_suspicious_host"
  | "generated_landing_url",
  RuleDefinition
> = {
  punycode_login_url: {
    id: "punycode_login_url",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Punycode login URL",
    description: "A login-like URL uses punycode.",
    locationType: "url",
    score: { base: 70, tags: ["phishing", "url"] }
  },
  redirect_to_url_shortener: {
    id: "redirect_to_url_shortener",
    pack: "redirects",
    severity: "medium",
    confidence: "medium",
    title: "URL shortener destination",
    description: "The scanned URL is, or redirects through, a known URL shortener (a common cloaking step).",
    locationType: "url",
    score: { base: 20, tags: ["redirect", "url"] }
  },
  final_url_offsite_redirect: {
    id: "final_url_offsite_redirect",
    pack: "redirects",
    severity: "medium",
    confidence: "high",
    title: "Final URL redirects off-site",
    description: "The fetched URL resolves to a different registrable domain than the submitted URL.",
    locationType: "url",
    score: { base: 25, tags: ["redirect", "url"] }
  },
  private_ip_url: {
    id: "private_ip_url",
    pack: "url-risk",
    severity: "medium",
    confidence: "high",
    title: "Private or local network URL",
    description: "Content references a localhost or private-network URL.",
    locationType: "url",
    score: { base: 25, tags: ["url"] }
  },
  ip_literal_url: {
    id: "ip_literal_url",
    pack: "url-risk",
    severity: "medium",
    confidence: "medium",
    title: "IP literal URL",
    description: "Content references a URL by IP address instead of a hostname.",
    locationType: "url",
    score: { base: 22, tags: ["url"] }
  },
  suspicious_tld_url: {
    id: "suspicious_tld_url",
    pack: "url-risk",
    severity: "low",
    confidence: "medium",
    title: "Suspicious TLD URL",
    description: "Content references a URL with a TLD commonly seen in abuse investigations.",
    locationType: "url",
    score: { base: 8, tags: ["url"] }
  },
  download_like_external_url: {
    id: "download_like_external_url",
    pack: "url-risk",
    severity: "medium",
    confidence: "medium",
    title: "Download-like external URL",
    description: "Content references an off-site URL with download or payload path terms.",
    locationType: "url",
    score: { base: 18, tags: ["url"], repeatMultiplier: 0.25, maxRepeats: 3 }
  },
  malware_download_like_url: {
    id: "malware_download_like_url",
    pack: "url-risk",
    severity: "high",
    confidence: "medium",
    title: "Malware-download-like URL path",
    description: "URL path resembles common malware download naming for scripts, botnet payloads, or architecture-specific binaries.",
    locationType: "url",
    score: { base: 55, tags: ["binary", "url"] }
  },
  shared_hosting_subdomain_url: {
    id: "shared_hosting_subdomain_url",
    pack: "url-risk",
    severity: "low",
    confidence: "medium",
    title: "Shared-hosting subdomain",
    description: "The target URL is hosted on a shared/free-hosting subdomain rather than an independently controlled registrable domain.",
    locationType: "url",
    score: { base: 6, tags: ["hosting", "url"] }
  },
  brand_impersonation_url: {
    id: "brand_impersonation_url",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Brand name in host of an unrelated domain",
    description: "A well-known brand appears in the hostname while the registrable domain does not belong to that brand — a hallmark of credential-phishing lookalike hosts.",
    locationType: "url",
    score: { base: 68, tags: ["phishing", "url"] }
  },
  credential_path_on_suspicious_host: {
    id: "credential_path_on_suspicious_host",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Login/account path on a suspicious host",
    description: "A login, sign-in, account, or verification path is served from a free-hosting subdomain, generated host label, suspicious TLD, punycode, IP literal, or URL shortener — where legitimate brands do not host credentials.",
    locationType: "url",
    score: { base: 66, tags: ["credential", "phishing", "url"] }
  },
  generated_landing_url: {
    id: "generated_landing_url",
    pack: "url-risk",
    severity: "high",
    confidence: "medium",
    title: "Generated suspicious landing URL",
    description: "URL has generated-looking host/path structure commonly seen in injected landing pages and fake-update campaigns.",
    locationType: "url",
    score: { base: 78, tags: ["phishing", "url"] }
  }
};
