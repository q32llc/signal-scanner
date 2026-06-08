import type { RuleDefinition } from "../types";

export const cssRules: Record<"hidden_link_cluster" | "unicode_bidi_trick" | "css_imports_suspicious_domain" | "invisible_form_overlay", RuleDefinition> = {
  hidden_link_cluster: {
    id: "hidden_link_cluster",
    pack: "seo-spam",
    severity: "low",
    confidence: "medium",
    title: "Hidden CSS content",
    description: "CSS contains hidden or offscreen content patterns.",
    locationType: "css"
  },
  unicode_bidi_trick: {
    id: "unicode_bidi_trick",
    pack: "obfuscation",
    severity: "medium",
    confidence: "high",
    title: "Unicode bidi CSS trick",
    description: "CSS uses bidi override, which can hide or reorder visible text.",
    locationType: "css"
  },
  css_imports_suspicious_domain: {
    id: "css_imports_suspicious_domain",
    pack: "script-risk",
    severity: "medium",
    confidence: "medium",
    title: "CSS imports off-site resource",
    description: "CSS imports or loads an off-site URL.",
    locationType: "url"
  },
  invisible_form_overlay: {
    id: "invisible_form_overlay",
    pack: "phishing",
    severity: "medium",
    confidence: "medium",
    title: "Invisible form overlay style",
    description: "CSS contains fixed/absolute overlay and invisibility patterns that can hide or intercept form input.",
    locationType: "css"
  }
};
