import { FindingType } from './scan';

export interface WaiverCreate {
  project_id?: string;
  finding_id?: string;
  vulnerability_id?: string;  // For granular CVE-level waivers within aggregated findings
  package_name?: string;
  package_version?: string;
  finding_type?: FindingType;
  reason: string;
  expiration_date?: string;
}

export interface Waiver {
  id: string;
  project_id?: string;
  finding_id?: string;
  package_name?: string;
  package_version?: string;
  finding_type?: FindingType;
  reason: string;
  expiration_date?: string;
  created_at: string;
  created_by: string;
  is_active: boolean;
}

export interface WaiversPaginatedResponse {
  items: Waiver[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface WaiversQueryParams {
  project_id?: string;
  finding_id?: string;
  package_name?: string;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  skip?: number;
  limit?: number;
}
