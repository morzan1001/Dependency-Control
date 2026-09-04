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

export interface ScanDeltaReachability {
  coverable_count: number;
  analyzed_count: number;
}

// Which build a side of the comparison actually is. A symbolic side ("release", "head") resolves
// server-side, and a release side follows the rescan chain, so the requested id need not be it.
export interface ScanDeltaSide {
  scan_id: string;
  branch: string | null;
  commit_hash: string | null;
  created_at: string | null;
}

export interface ScanDeltaResponse {
  from_scan_id: string;
  to_scan_id: string;
  from_side?: ScanDeltaSide | null;
  to_side?: ScanDeltaSide | null;
  project_id: string;
  category: DeltaCategory;
  totals: ScanDeltaTotals;
  page: number;
  page_size: number;
  total_pages: number;
  items: DeltaItem[];
  // Null means the scan reports no reachability at all, which is distinct from zero coverage.
  from_reachability?: ScanDeltaReachability | null;
  to_reachability?: ScanDeltaReachability | null;
  // Findings a waiver hides in whole or in part on each side.
  from_waived_excluded: number;
  to_waived_excluded: number;
  // Added and removed items the comparison would not have produced had no waiver applied.
  waiver_only_changes: number;
}
