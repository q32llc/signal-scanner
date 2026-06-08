import type { RuleDefinition } from "../types";

export const decodedArtifactRules: Record<"large_base64_blob" | "javascript_hex_escapes" | "javascript_unicode_escapes" | "fromcharcode_decoded_string", RuleDefinition> = {
  large_base64_blob: {
    id: "large_base64_blob",
    pack: "obfuscation",
    severity: "medium",
    confidence: "medium",
    title: "Decoded base64 artifact",
    description: "Scanner decoded a base64 artifact and rescanned it.",
    locationType: "decoded_artifact",
    score: { base: 14, tags: ["decoded", "obfuscation"] }
  },
  javascript_hex_escapes: {
    id: "javascript_hex_escapes",
    pack: "obfuscation",
    severity: "medium",
    confidence: "medium",
    title: "Decoded JavaScript hex escapes",
    description: "Scanner decoded JavaScript hex escapes and rescanned the artifact.",
    locationType: "decoded_artifact",
    score: { base: 18, tags: ["decoded", "obfuscation"] }
  },
  javascript_unicode_escapes: {
    id: "javascript_unicode_escapes",
    pack: "obfuscation",
    severity: "medium",
    confidence: "medium",
    title: "Decoded JavaScript unicode escapes",
    description: "Scanner decoded JavaScript unicode escapes and rescanned the artifact.",
    locationType: "decoded_artifact",
    score: { base: 18, tags: ["decoded", "obfuscation"] }
  },
  fromcharcode_decoded_string: {
    id: "fromcharcode_decoded_string",
    pack: "obfuscation",
    severity: "medium",
    confidence: "medium",
    title: "Decoded String.fromCharCode artifact",
    description: "Scanner decoded a literal String.fromCharCode artifact and rescanned it.",
    locationType: "decoded_artifact",
    score: { base: 22, tags: ["decoded", "obfuscation"] }
  }
};
