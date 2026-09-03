export interface ReleaseItem {
  scan_id: string;
  project_id: string;
  environment: string;
  version: string | null;
  released_at: string;
  commit_hash: string | null;
  branch: string | null;
  // null once retention removed the released scan.
  scan_status: string | null;
  // The scan whose analysis represents this release after any rescan; null while nothing in its
  // chain has finished analysing, so a deploy awaiting analysis reads apart from a stale one.
  analysis_scan_id: string | null;
}

export interface ReleaseListResponse {
  items: ReleaseItem[];
  total: number;
  page: number;
  size: number;
}

export interface MarkReleasePayload {
  commit_hash: string;
  version?: string;
  environment?: string;
  released_at?: string;
}

export interface UnmarkReleaseResponse {
  scan_id: string;
  environment: string;
  // Still true while another environment holds the scan.
  is_release: boolean;
  remaining_environments: string[];
}
