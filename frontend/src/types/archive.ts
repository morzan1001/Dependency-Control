import { PaginatedResponse } from './common';

export interface ArchiveListItem {
  id: string;
  scan_id: string;
  branch?: string;
  commit_hash?: string;
  scan_created_at?: string;
  archived_at: string;
  compressed_size_bytes: number;
}

export type ArchiveListResponse = PaginatedResponse<ArchiveListItem>;

export interface ArchiveRestoreResponse {
  scan_id: string;
  project_id: string;
  message: string;
  collections_restored: string[];
}
