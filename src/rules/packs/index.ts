export { binaryRules, binaryStringRules } from "./binary.js";
export { cssRules } from "./css.js";
export { decodedArtifactRules } from "./decoders.js";
export { htmlRules } from "./html.js";
export { htmlTechnologyRules } from "./html.js";
export { scriptCompositeRules, scriptRiskRules } from "./script-risk.js";
export { sourceCodeRules } from "./source-code.js";
export { urlRules } from "./urls.js";

import { binaryRules, binaryStringRules } from "./binary.js";
import { cssRules } from "./css.js";
import { decodedArtifactRules } from "./decoders.js";
import { htmlRules, htmlTechnologyRules } from "./html.js";
import { scriptCompositeRules, scriptRiskRules } from "./script-risk.js";
import { sourceCodeRules } from "./source-code.js";
import { urlRules } from "./urls.js";

export const rulePacks = {
  phishing: [
    htmlRules.credential_form_posts_off_origin,
    htmlRules.password_form_without_https,
    htmlRules.hidden_iframe_off_origin,
    htmlRules.excessive_external_scripts_on_login_page,
    htmlRules.login_page_with_punycode_links,
    htmlRules.credential_ui_rendered_as_image,
    htmlRules.crypto_wallet_login_language,
    htmlRules.crypto_trading_landing_language,
    htmlRules.seo_trademark_stuffing,
    htmlRules.credential_form_on_suspicious_host,
    htmlRules.brand_impersonation_content,
    urlRules.punycode_login_url,
    urlRules.brand_impersonation_url
  ],
  redirects: [htmlRules.meta_refresh_external, urlRules.redirect_to_url_shortener, urlRules.final_url_offsite_redirect, ...scriptRiskRules.filter((rule) => rule.pack === "redirects")],
  "url-risk": [
    urlRules.private_ip_url,
    urlRules.ip_literal_url,
    urlRules.suspicious_tld_url,
    urlRules.download_like_external_url,
    urlRules.malware_download_like_url,
    urlRules.shared_hosting_subdomain_url,
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
