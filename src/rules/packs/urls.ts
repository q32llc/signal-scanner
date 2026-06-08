import type { RuleDefinition } from "../types";

export const urlRules: Record<
  | "punycode_login_url"
  | "redirect_to_url_shortener"
  | "private_ip_url"
  | "ip_literal_url"
  | "suspicious_tld_url"
  | "download_like_external_url"
  | "malware_download_like_url"
  | "brand_impersonation_url"
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
    locationType: "url"
  },
  redirect_to_url_shortener: {
    id: "redirect_to_url_shortener",
    pack: "redirects",
    severity: "medium",
    confidence: "medium",
    title: "URL shortener destination",
    description: "Content references a known URL shortener.",
    locationType: "url"
  },
  private_ip_url: {
    id: "private_ip_url",
    pack: "url-risk",
    severity: "medium",
    confidence: "high",
    title: "Private or local network URL",
    description: "Content references a localhost or private-network URL.",
    locationType: "url"
  },
  ip_literal_url: {
    id: "ip_literal_url",
    pack: "url-risk",
    severity: "medium",
    confidence: "medium",
    title: "IP literal URL",
    description: "Content references a URL by IP address instead of a hostname.",
    locationType: "url"
  },
  suspicious_tld_url: {
    id: "suspicious_tld_url",
    pack: "url-risk",
    severity: "low",
    confidence: "medium",
    title: "Suspicious TLD URL",
    description: "Content references a URL with a TLD commonly seen in abuse investigations.",
    locationType: "url"
  },
  download_like_external_url: {
    id: "download_like_external_url",
    pack: "url-risk",
    severity: "medium",
    confidence: "medium",
    title: "Download-like external URL",
    description: "Content references an off-site URL with download or payload path terms.",
    locationType: "url"
  },
  malware_download_like_url: {
    id: "malware_download_like_url",
    pack: "url-risk",
    severity: "high",
    confidence: "medium",
    title: "Malware-download-like URL path",
    description: "URL path resembles common malware download naming for scripts, botnet payloads, or architecture-specific binaries.",
    locationType: "url"
  },
  brand_impersonation_url: {
    id: "brand_impersonation_url",
    pack: "phishing",
    severity: "high",
    confidence: "medium",
    title: "Brand term on unrelated domain",
    description: "URL contains a known brand term while the registrable domain does not belong to that brand.",
    locationType: "url"
  },
  generated_landing_url: {
    id: "generated_landing_url",
    pack: "url-risk",
    severity: "high",
    confidence: "medium",
    title: "Generated suspicious landing URL",
    description: "URL has generated-looking host/path structure commonly seen in injected landing pages and fake-update campaigns.",
    locationType: "url"
  }
};
