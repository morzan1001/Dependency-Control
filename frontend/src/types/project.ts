import { PaginatedResponse } from './common';
import type { EnhancedStats } from './scan';
import type { TeamRef, TeamSource } from './team';

export type { EnhancedStats } from './scan';

export interface ProjectMember {
  user_id: string;
  username?: string;
  // The stored direct role, which member editing targets.
  role: string;
  // The role access is checked at: the stronger of the direct role and any owning team's grant.
  effective_role?: string;
  notification_preferences?: Record<string, string[]>;
  inherited_from?: string;
}

export type RetentionAction = 'delete' | 'archive' | 'none';

export interface Project {
  id: string;
  name: string;
  // Every team that owns the project. The detail read answers ids and their provenance; the list
  // read and the analytics rows answer resolved names.
  team_ids?: string[];
  team_sources?: Record<string, TeamSource>;
  teams?: TeamRef[];
  members?: ProjectMember[];
  active_analyzers?: string[];
  retention_days?: number;
  retention_action?: RetentionAction;
  analyzer_settings?: Record<string, Record<string, unknown>>;
  default_branch?: string;
  enforce_notification_settings?: boolean;
  enforced_notification_preferences?: Record<string, string[]>;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  gitlab_instance_id?: string;
  gitlab_project_id?: number;
  gitlab_project_path?: string;
  github_instance_id?: string;
  github_repository_id?: string;
  github_repository_path?: string;
  github_pr_comments_enabled?: boolean;
  stats?: EnhancedStats | null;
  last_scan_at?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ProjectCreate {
  name: string;
  team_id?: string;
  active_analyzers?: string[];
  retention_days?: number;
  retention_action?: RetentionAction;
}

export interface ProjectUpdate {
  name?: string;
  // The whole owner set, not a change to it: whatever is left out stops owning the project.
  team_ids?: string[];
  active_analyzers?: string[];
  retention_days?: number;
  retention_action?: RetentionAction;
  analyzer_settings?: Record<string, Record<string, unknown>>;
  enforce_notification_settings?: boolean;
  default_branch?: string | null;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  gitlab_instance_id?: string | null;
  gitlab_project_id?: number | null;
  gitlab_project_path?: string | null;
  github_pr_comments_enabled?: boolean;
}

export interface ProjectApiKeyResponse {
  project_id: string;
  api_key: string;
  note: string;
}

export interface BranchInfo {
  name: string;
  is_active: boolean;
  last_scan_at: string | null;
  is_default: boolean;
}

export type ProjectsResponse = PaginatedResponse<Project>;

export interface ProjectNotificationSettings {
  notification_preferences: Record<string, string[]>;
  enforce_notification_settings?: boolean;
}
