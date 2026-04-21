import type { CryptoPrimitive } from "./crypto";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE" | "INFO" | "UNKNOWN";
export type CryptoFindingType =
  | "crypto_weak_algorithm"
  | "crypto_weak_key"
  | "crypto_quantum_vulnerable";

export type CryptoPolicySource =
  | "nist-sp-800-131a"
  | "bsi-tr-02102"
  | "cnsa-2.0"
  | "nist-pqc"
  | "custom";

export interface CryptoRule {
  rule_id: string;
  name: string;
  description: string;
  finding_type: CryptoFindingType;
  default_severity: Severity;
  match_primitive?: CryptoPrimitive | null;
  match_name_patterns: string[];
  match_min_key_size_bits?: number | null;
  match_curves: string[];
  match_protocol_versions: string[];
  quantum_vulnerable?: boolean | null;
  enabled: boolean;
  source: CryptoPolicySource;
  references: string[];
}

export interface CryptoPolicyDoc {
  _id?: string;
  scope: "system" | "project";
  project_id?: string | null;
  rules: CryptoRule[];
  version: number;
  updated_at?: string;
  updated_by?: string | null;
}

export interface EffectivePolicy {
  system_version: number;
  override_version: number | null;
  rules: CryptoRule[];
}
