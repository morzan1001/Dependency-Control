import type { PaginatedResponse } from './common';

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
  // The scan whose analysis represents the release after any rescan; null until one in its chain finishes.
  analysis_scan_id: string | null;
  // The chain hit the resolver's hop bound, so analysis_scan_id is the freshest within it, not the freshest overall.
  analysis_chain_bounded: boolean;
}

export type ReleaseListResponse = PaginatedResponse<ReleaseItem>;

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
  // What the environment reports as running now: the uncovered record, or null once nothing is released there.
  environment_release: ReleaseItem | null;
}
