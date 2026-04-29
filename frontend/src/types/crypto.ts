export type CryptoAssetType =
  | "algorithm"
  | "certificate"
  | "protocol"
  | "related-crypto-material";

export type CryptoPrimitive =
  | "block-cipher"
  | "stream-cipher"
  | "hash"
  | "mac"
  | "pke"
  | "signature"
  | "kem"
  | "kdf"
  | "drbg"
  | "other";

export interface CryptoAsset {
  _id: string;
  project_id: string;
  scan_id: string;
  bom_ref: string;
  name: string;
  asset_type: CryptoAssetType;
  primitive?: CryptoPrimitive | null;
  variant?: string | null;
  parameter_set_identifier?: string | null;
  mode?: string | null;
  padding?: string | null;
  key_size_bits?: number | null;
  curve?: string | null;
  subject_name?: string | null;
  issuer_name?: string | null;
  not_valid_before?: string | null;
  not_valid_after?: string | null;
  signature_algorithm_ref?: string | null;
  certificate_format?: string | null;
  protocol_type?: string | null;
  version?: string | null;
  cipher_suites: string[];
  occurrence_locations: string[];
  detection_context?: string | null;
  confidence?: number | null;
  related_dependency_purls: string[];
  properties: Record<string, string>;
  created_at: string;
}

export interface CryptoAssetSummary {
  total: number;
  by_type: Partial<Record<CryptoAssetType, number>>;
}

export interface CryptoAssetListResponse {
  items: CryptoAsset[];
  total: number;
  limit: number;
  skip: number;
}
