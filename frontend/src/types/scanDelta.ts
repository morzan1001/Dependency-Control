export type DeltaCategory = "findings" | "components" | "crypto";
export type DeltaChange =
  | "added"
  | "removed"
  | "version_changed"
  | "license_changed";

export interface ScanDeltaTotals {
  added: number;
  removed: number;
  unchanged: number;
  changed: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
}

export interface FindingDeltaItem {
  change: "added" | "removed";
  finding_id: string;
  finding_type: string;
  severity: string;
  title: string;
  component: string | null;
  cve_id: string | null;
  file_path: string | null;
  first_seen: string | null;
}

export interface ComponentDeltaItem {
  change: "added" | "removed" | "version_changed" | "license_changed";
  name: string;
  purl: string | null;
  version: string | null;
  from_version: string | null;
  to_version: string | null;
  license: string | null;
  from_license: string | null;
  to_license: string | null;
}

export interface CryptoDeltaItem {
  change: "added" | "removed";
  name: string;
  variant: string | null;
  primitive: string | null;
  locations: string[];
  asset_count: number;
}

export type DeltaItem = FindingDeltaItem | ComponentDeltaItem | CryptoDeltaItem;

export interface ScanDeltaResponse {
  from_scan_id: string;
  to_scan_id: string;
  project_id: string;
  category: DeltaCategory;
  totals: ScanDeltaTotals;
  page: number;
  page_size: number;
  total_pages: number;
  items: DeltaItem[];
}
