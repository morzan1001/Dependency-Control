export type PolicyAuditAction = "create" | "update" | "delete" | "revert" | "seed";

export interface PolicyAuditEntry {
  _id: string;
  policy_scope: "system" | "project";
  project_id: string | null;
  version: number;
  action: PolicyAuditAction;
  actor_user_id: string | null;
  actor_display_name: string | null;
  timestamp: string;
  snapshot: Record<string, unknown>;
  change_summary: string;
  comment: string | null;
  reverted_from_version: number | null;
}

export interface PolicyAuditListResponse { entries: PolicyAuditEntry[]; }
