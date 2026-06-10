import type { RuleDefinition } from "../types";

export const htmlRules: Record<
  | "external_script_from_unrelated_domain"
  | "mixed_content_script"
  | "hidden_iframe_off_origin"
  | "meta_refresh_external"
  | "password_form_without_https"
  | "credential_form_posts_off_origin"
  | "card_fields_plus_external_script"
  | "excessive_external_scripts_on_login_page"
  | "login_page_with_punycode_links"
  | "credential_ui_rendered_as_image"
  | "crypto_wallet_login_language"
  | "crypto_trading_landing_language"
  | "seo_trademark_stuffing"
  | "credential_form_on_suspicious_host"
  | "brand_impersonation_content",
  RuleDefinition
> = {
  external_script_from_unrelated_domain: {
    id: "external_script_from_unrelated_domain",
    pack: "script-risk",
    severity: "medium",
    confidence: "medium",
    title: "External script from unrelated domain",
    description: "HTML loads a script from an off-site domain.",
    locationType: "url",
    score: { base: 8, tags: ["script", "url"], repeatMultiplier: 0.1, maxRepeats: 3 }
  },
  mixed_content_script: {
    id: "mixed_content_script",
    pack: "script-risk",
    severity: "medium",
    confidence: "high",
    title: "Mixed-content script",
    description: "HTTPS page loads a script over HTTP.",
    locationType: "url",
    // A real injection vector, but a hygiene issue on its own (browsers block it)
    // — shouldn't convict a site as malicious without corroborating signal.
    score: { base: 30, tags: ["script", "url"] }
  },
  hidden_iframe_off_origin: {
    id: "hidden_iframe_off_origin",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Hidden off-origin iframe",
    description: "HTML contains a hidden iframe pointed at an off-origin URL.",
    locationType: "url",
    score: { base: 70, tags: ["phishing", "url"] }
  },
  meta_refresh_external: {
    id: "meta_refresh_external",
    pack: "redirects",
    severity: "medium",
    confidence: "medium",
    title: "Meta refresh to external URL",
    description: "HTML redirects with a meta refresh to an off-site URL.",
    locationType: "url",
    score: { base: 25, tags: ["redirect", "url"] }
  },
  password_form_without_https: {
    id: "password_form_without_https",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Password form without HTTPS",
    description: "Page contains a password form on an HTTP origin.",
    locationType: "html",
    score: { base: 70, tags: ["credential", "phishing"] }
  },
  credential_form_posts_off_origin: {
    id: "credential_form_posts_off_origin",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Credential form posts off origin",
    description: "A form with a password field submits to an off-origin URL.",
    locationType: "url",
    score: { base: 82, tags: ["credential", "phishing", "url"] }
  },
  card_fields_plus_external_script: {
    id: "card_fields_plus_external_script",
    pack: "payment",
    severity: "high",
    confidence: "medium",
    title: "Payment fields with external resources",
    description: "Page contains payment fields and off-site resources.",
    locationType: "html",
    score: { base: 72, tags: ["payment", "script", "url"] }
  },
  excessive_external_scripts_on_login_page: {
    id: "excessive_external_scripts_on_login_page",
    pack: "phishing",
    severity: "medium",
    confidence: "medium",
    title: "Excessive external scripts on login/payment page",
    description: "Login or payment page loads many off-site scripts.",
    locationType: "aggregate",
    score: { base: 14, tags: ["phishing", "script"] }
  },
  login_page_with_punycode_links: {
    id: "login_page_with_punycode_links",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Login page with punycode links",
    description: "Login-like page references punycode URLs.",
    locationType: "aggregate",
    score: { base: 76, tags: ["phishing", "url"] }
  },
  credential_ui_rendered_as_image: {
    id: "credential_ui_rendered_as_image",
    pack: "phishing",
    severity: "medium",
    confidence: "high",
    title: "Credential UI rendered as image",
    description: "Page model or markup references a screenshot/image that appears to contain a login or credential form.",
    locationType: "html",
    score: { base: 34, tags: ["credential", "phishing"] }
  },
  crypto_wallet_login_language: {
    id: "crypto_wallet_login_language",
    pack: "phishing",
    severity: "medium",
    confidence: "high",
    title: "Crypto wallet login language",
    description: "Page model or markup contains crypto/wallet language in login, account, or access context.",
    locationType: "html",
    score: { base: 22, tags: ["phishing", "wallet"] }
  },
  crypto_trading_landing_language: {
    id: "crypto_trading_landing_language",
    pack: "phishing",
    severity: "low",
    confidence: "medium",
    title: "Crypto or DeFi trading landing language",
    description: "Page model or markup contains multiple crypto, DeFi, exchange, swap, trading, or liquidity terms.",
    locationType: "html",
    score: { base: 6, tags: ["phishing", "wallet"] }
  },
  seo_trademark_stuffing: {
    id: "seo_trademark_stuffing",
    pack: "phishing",
    severity: "high",
    confidence: "medium",
    title: "SEO trademark stuffing",
    description: "Page title or SEO model overuses trademark symbols in a way commonly seen on impersonation landing pages.",
    locationType: "html",
    score: { base: 64, tags: ["phishing", "seo"] }
  },
  credential_form_on_suspicious_host: {
    id: "credential_form_on_suspicious_host",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Credential form on suspicious host",
    description: "Page contains credential fields on a generated, shared-hosting, suspicious-path, or redirected host.",
    locationType: "html",
    score: { base: 72, tags: ["credential", "hosting", "phishing"] }
  },
  brand_impersonation_content: {
    id: "brand_impersonation_content",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Page mimics a brand and captures credentials",
    description: "Page content prominently references a well-known brand and presents a credential field, but is served from a domain that does not belong to that brand — the core credential-phishing pattern, independent of the URL.",
    locationType: "html",
    score: { base: 68, tags: ["credential", "phishing"] }
  }
};

export const htmlTechnologyRules: Record<
  | "legacy_jquery_reference"
  | "legacy_angularjs_reference"
  | "legacy_bootstrap_reference"
  | "legacy_lodash_reference"
  | "wordpress_surface_reference"
  | "drupal_surface_reference"
  | "phpmyadmin_surface_reference",
  RuleDefinition
> = {
  legacy_jquery_reference: {
    id: "legacy_jquery_reference",
    pack: "dependency-fingerprint",
    severity: "low",
    confidence: "medium",
    title: "Legacy jQuery reference",
    description: "A script URL or source text references a legacy jQuery major version.",
    locationType: "url",
    score: { base: 4, tags: ["dependency"] }
  },
  legacy_angularjs_reference: {
    id: "legacy_angularjs_reference",
    pack: "dependency-fingerprint",
    severity: "low",
    confidence: "medium",
    title: "Legacy AngularJS reference",
    description: "A script URL or source text references AngularJS 1.x.",
    locationType: "url",
    score: { base: 6, tags: ["dependency"] }
  },
  legacy_bootstrap_reference: {
    id: "legacy_bootstrap_reference",
    pack: "dependency-fingerprint",
    severity: "low",
    confidence: "medium",
    title: "Legacy Bootstrap reference",
    description: "A script URL or source text references Bootstrap 3.x.",
    locationType: "url",
    score: { base: 4, tags: ["dependency"] }
  },
  legacy_lodash_reference: {
    id: "legacy_lodash_reference",
    pack: "dependency-fingerprint",
    severity: "low",
    confidence: "medium",
    title: "Legacy lodash reference",
    description: "A script URL or source text references lodash versions commonly covered by dependency scanners.",
    locationType: "url",
    score: { base: 4, tags: ["dependency"] }
  },
  wordpress_surface_reference: {
    id: "wordpress_surface_reference",
    pack: "technology-fingerprint",
    severity: "info",
    confidence: "medium",
    title: "WordPress surface reference",
    description: "HTML references common WordPress paths or generator metadata.",
    locationType: "html",
    score: { base: 2, tags: ["technology"] }
  },
  drupal_surface_reference: {
    id: "drupal_surface_reference",
    pack: "technology-fingerprint",
    severity: "info",
    confidence: "medium",
    title: "Drupal surface reference",
    description: "HTML or script text references common Drupal surface fingerprints.",
    locationType: "html",
    score: { base: 2, tags: ["technology"] }
  },
  phpmyadmin_surface_reference: {
    id: "phpmyadmin_surface_reference",
    pack: "technology-fingerprint",
    severity: "info",
    confidence: "medium",
    title: "phpMyAdmin surface reference",
    description: "HTML references common phpMyAdmin surface fingerprints.",
    locationType: "html",
    score: { base: 8, tags: ["technology"] }
  }
};
