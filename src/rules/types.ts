export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingLocationType = "url" | "html" | "javascript" | "css" | "source" | "binary" | "decoded_artifact" | "aggregate";

export interface PatternRule {
  id: string;
  pack: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  locationType: FindingLocationType;
  pattern: RegExp;
  counter?: string;
}

export interface RuleDefinition {
  id: string;
  pack: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  locationType: FindingLocationType;
}
