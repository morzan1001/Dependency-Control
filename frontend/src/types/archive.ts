import { PaginatedResponse } from './common';

export interface ArchiveListItem {
  id: string;
  scan_id: string;
  branch?: string;
  commit_hash?: string;
  scan_created_at?: string;
  archived_at: string;
  compressed_size_bytes: number;
  findings_count: number;
  critical_findings_count: number;
  high_findings_count: number;
  dependencies_count: number;
  sbom_filenames: string[];
}

export interface AdminArchiveListItem extends ArchiveListItem {
  project_id: string;
  project_name?: string;
}

export type ArchiveListResponse = PaginatedResponse<ArchiveListItem>;
export type AdminArchiveListResponse = PaginatedResponse<AdminArchiveListItem>;

export interface ArchiveRestoreResponse {
  scan_id: string;
  project_id: string;
  message: string;
  collections_restored: string[];
}

export interface ArchiveFilters {
  branch?: string;
  date_from?: string;
  date_to?: string;
}
