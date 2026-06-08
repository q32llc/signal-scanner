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
  | "login_page_with_punycode_links",
  RuleDefinition
> = {
  external_script_from_unrelated_domain: {
    id: "external_script_from_unrelated_domain",
    pack: "script-risk",
    severity: "medium",
    confidence: "medium",
    title: "External script from unrelated domain",
    description: "HTML loads a script from an off-site domain.",
    locationType: "url"
  },
  mixed_content_script: {
    id: "mixed_content_script",
    pack: "script-risk",
    severity: "high",
    confidence: "high",
    title: "Mixed-content script",
    description: "HTTPS page loads a script over HTTP.",
    locationType: "url"
  },
  hidden_iframe_off_origin: {
    id: "hidden_iframe_off_origin",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Hidden off-origin iframe",
    description: "HTML contains a hidden iframe pointed at an off-origin URL.",
    locationType: "url"
  },
  meta_refresh_external: {
    id: "meta_refresh_external",
    pack: "redirects",
    severity: "medium",
    confidence: "medium",
    title: "Meta refresh to external URL",
    description: "HTML redirects with a meta refresh to an off-site URL.",
    locationType: "url"
  },
  password_form_without_https: {
    id: "password_form_without_https",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Password form without HTTPS",
    description: "Page contains a password form on an HTTP origin.",
    locationType: "html"
  },
  credential_form_posts_off_origin: {
    id: "credential_form_posts_off_origin",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Credential form posts off origin",
    description: "A form with a password field submits to an off-origin URL.",
    locationType: "url"
  },
  card_fields_plus_external_script: {
    id: "card_fields_plus_external_script",
    pack: "payment",
    severity: "high",
    confidence: "medium",
    title: "Payment fields with external resources",
    description: "Page contains payment fields and off-site resources.",
    locationType: "html"
  },
  excessive_external_scripts_on_login_page: {
    id: "excessive_external_scripts_on_login_page",
    pack: "phishing",
    severity: "medium",
    confidence: "medium",
    title: "Excessive external scripts on login/payment page",
    description: "Login or payment page loads many off-site scripts.",
    locationType: "aggregate"
  },
  login_page_with_punycode_links: {
    id: "login_page_with_punycode_links",
    pack: "phishing",
    severity: "high",
    confidence: "high",
    title: "Login page with punycode links",
    description: "Login-like page references punycode URLs.",
    locationType: "aggregate"
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
    severity: "medium",
    confidence: "medium",
    title: "Legacy jQuery reference",
    description: "A script URL or source text references a legacy jQuery major version.",
    locationType: "url"
  },
  legacy_angularjs_reference: {
    id: "legacy_angularjs_reference",
    pack: "dependency-fingerprint",
    severity: "medium",
    confidence: "medium",
    title: "Legacy AngularJS reference",
    description: "A script URL or source text references AngularJS 1.x.",
    locationType: "url"
  },
  legacy_bootstrap_reference: {
    id: "legacy_bootstrap_reference",
    pack: "dependency-fingerprint",
    severity: "medium",
    confidence: "medium",
    title: "Legacy Bootstrap reference",
    description: "A script URL or source text references Bootstrap 3.x.",
    locationType: "url"
  },
  legacy_lodash_reference: {
    id: "legacy_lodash_reference",
    pack: "dependency-fingerprint",
    severity: "medium",
    confidence: "medium",
    title: "Legacy lodash reference",
    description: "A script URL or source text references lodash versions commonly covered by dependency scanners.",
    locationType: "url"
  },
  wordpress_surface_reference: {
    id: "wordpress_surface_reference",
    pack: "technology-fingerprint",
    severity: "info",
    confidence: "medium",
    title: "WordPress surface reference",
    description: "HTML references common WordPress paths or generator metadata.",
    locationType: "html"
  },
  drupal_surface_reference: {
    id: "drupal_surface_reference",
    pack: "technology-fingerprint",
    severity: "info",
    confidence: "medium",
    title: "Drupal surface reference",
    description: "HTML or script text references common Drupal surface fingerprints.",
    locationType: "html"
  },
  phpmyadmin_surface_reference: {
    id: "phpmyadmin_surface_reference",
    pack: "technology-fingerprint",
    severity: "info",
    confidence: "medium",
    title: "phpMyAdmin surface reference",
    description: "HTML references common phpMyAdmin surface fingerprints.",
    locationType: "html"
  }
};
