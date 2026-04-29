export type AnalyticsScope = "project" | "team" | "global" | "user";

export type GroupingDimension =
  | "name" | "primitive" | "asset_type" | "weakness_tag" | "severity";

export type TrendMetric =
  | "total_crypto_findings"
  | "quantum_vulnerable_findings"
  | "weak_algo_findings"
  | "weak_key_findings"
  | "cert_expiring_soon"
  | "cert_expired"
  | "unique_algorithms"
  | "unique_cipher_suites";

export type TrendBucket = "day" | "week" | "month";

export interface HotspotEntry {
  key: string;
  grouping_dimension: GroupingDimension;
  asset_count: number;
  finding_count: number;
  severity_mix: Record<string, number>;
  locations: string[];
  project_ids: string[];
  first_seen: string;
  last_seen: string;
}

export interface HotspotResponse {
  scope: AnalyticsScope;
  scope_id: string | null;
  grouping_dimension: GroupingDimension;
  items: HotspotEntry[];
  total: number;
  generated_at: string;
  cache_hit: boolean;
}

export interface TrendPoint {
  timestamp: string;
  metric: TrendMetric;
  value: number;
}

export interface TrendSeries {
  scope: AnalyticsScope;
  scope_id: string | null;
  metric: TrendMetric;
  bucket: TrendBucket;
  points: TrendPoint[];
  range_start: string;
  range_end: string;
  cache_hit: boolean;
}

export interface ScanDelta {
  from_scan_id: string;
  to_scan_id: string;
  added: HotspotEntry[];
  removed: HotspotEntry[];
  unchanged_count: number;
}
