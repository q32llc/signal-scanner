export { binaryRules, binaryStringRules } from "./binary";
export { cssRules } from "./css";
export { decodedArtifactRules } from "./decoders";
export { htmlRules } from "./html";
export { htmlTechnologyRules } from "./html";
export { scriptCompositeRules, scriptRiskRules } from "./script-risk";
export { sourceCodeRules } from "./source-code";
export { urlRules } from "./urls";

import { binaryRules, binaryStringRules } from "./binary";
import { cssRules } from "./css";
import { decodedArtifactRules } from "./decoders";
import { htmlRules, htmlTechnologyRules } from "./html";
import { scriptCompositeRules, scriptRiskRules } from "./script-risk";
import { sourceCodeRules } from "./source-code";
import { urlRules } from "./urls";

export const rulePacks = {
  phishing: [
    htmlRules.credential_form_posts_off_origin,
    htmlRules.password_form_without_https,
    htmlRules.hidden_iframe_off_origin,
    htmlRules.excessive_external_scripts_on_login_page,
    htmlRules.login_page_with_punycode_links,
    urlRules.punycode_login_url,
    urlRules.brand_impersonation_url
  ],
  redirects: [htmlRules.meta_refresh_external, urlRules.redirect_to_url_shortener, ...scriptRiskRules.filter((rule) => rule.pack === "redirects")],
  "url-risk": [
    urlRules.private_ip_url,
    urlRules.ip_literal_url,
    urlRules.suspicious_tld_url,
    urlRules.download_like_external_url,
    urlRules.malware_download_like_url,
    urlRules.brand_impersonation_url,
    urlRules.generated_landing_url
  ],
  "technology-fingerprint": [
    htmlTechnologyRules.wordpress_surface_reference,
    htmlTechnologyRules.drupal_surface_reference,
    htmlTechnologyRules.phpmyadmin_surface_reference
  ],
  "dependency-fingerprint": [
    htmlTechnologyRules.legacy_jquery_reference,
    htmlTechnologyRules.legacy_angularjs_reference,
    htmlTechnologyRules.legacy_bootstrap_reference,
    htmlTechnologyRules.legacy_lodash_reference
  ],
  "script-risk": [
    htmlRules.external_script_from_unrelated_domain,
    htmlRules.mixed_content_script,
    ...scriptRiskRules.filter((rule) => rule.pack === "script-risk")
  ],
  obfuscation: [
    ...Object.values(decodedArtifactRules),
    ...scriptRiskRules.filter((rule) => rule.pack === "obfuscation"),
    scriptCompositeRules.decoded_dynamic_execution,
    cssRules.unicode_bidi_trick
  ],
  exfiltration: [
    ...scriptRiskRules.filter((rule) => rule.pack === "exfiltration"),
    scriptCompositeRules.credential_exfil_candidate
  ],
  wallet: scriptRiskRules.filter((rule) => rule.pack === "wallet"),
  payment: [htmlRules.card_fields_plus_external_script, scriptCompositeRules.payment_input_event_hooks],
  "seo-spam": [cssRules.hidden_link_cluster],
  "source-code": sourceCodeRules,
  "binary-static": [...Object.values(binaryRules), ...binaryStringRules]
} as const;
