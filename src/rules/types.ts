export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingLocationType = "url" | "html" | "javascript" | "css" | "source" | "binary" | "decoded_artifact" | "aggregate";
export type ScoreTag =
  | "binary"
  | "credential"
  | "decoded"
  | "dependency"
  | "exfiltration"
  | "hosting"
  | "obfuscation"
  | "payment"
  | "phishing"
  | "redirect"
  | "seo"
  | "script"
  | "source"
  | "technology"
  | "url"
  | "wallet";

export interface RuleScoreModel {
  base: number;
  tags: ScoreTag[];
  repeatMultiplier?: number;
  maxRepeats?: number;
}

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
  score: RuleScoreModel;
}

export interface RuleDefinition {
  id: string;
  pack: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  locationType: FindingLocationType;
  score: RuleScoreModel;
}
