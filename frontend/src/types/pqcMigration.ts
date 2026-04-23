export type MigrationItemStatus =
  | "migrate_now" | "migrate_soon" | "plan_migration" | "monitor";

export interface MigrationItem {
  asset_bom_ref: string;
  asset_name: string;
  asset_variant: string | null;
  asset_key_size_bits: number | null;
  project_ids: string[];
  asset_count: number;
  source_family: string;
  source_primitive: string;
  use_case: string;
  recommended_pqc: string;
  recommended_standard: string;
  notes: string;
  priority_score: number;
  status: MigrationItemStatus;
  recommended_deadline: string | null;
}

export interface MigrationPlanSummary {
  total_items: number;
  status_counts: Record<MigrationItemStatus, number>;
  earliest_deadline: string | null;
}

export interface MigrationPlanResponse {
  scope: string;
  scope_id: string | null;
  generated_at: string;
  items: MigrationItem[];
  summary: MigrationPlanSummary;
  mappings_version: number;
}
