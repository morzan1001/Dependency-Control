import { PaginatedResponse } from './common';
import type { EnhancedStats } from './scan';

export type { EnhancedStats } from './scan';

export interface ProjectMember {
  user_id: string;
  username?: string;
  role: string;
  notification_preferences?: Record<string, string[]>;
  inherited_from?: string;
}

export interface Project {
  id: string;
  name: string;
  owner_id: string;
  team_id?: string;
  team_name?: string;
  members?: ProjectMember[];
  active_analyzers?: string[];
  retention_days?: number;
  retention_action?: 'delete' | 'archive' | 'none';
  default_branch?: string;
  enforce_notification_settings?: boolean;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  gitlab_instance_id?: string;
  gitlab_project_id?: number;
  gitlab_project_path?: string;
  owner_notification_preferences?: {
    [key: string]: string[];
  };
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
  retention_action?: 'delete' | 'archive' | 'none';
}

export interface ProjectUpdate {
  name?: string;
  team_id?: string | null;
  active_analyzers?: string[];
  retention_days?: number;
  retention_action?: 'delete' | 'archive' | 'none';
  enforce_notification_settings?: boolean;
  default_branch?: string | null;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  gitlab_instance_id?: string | null;
  gitlab_project_id?: number | null;
  gitlab_project_path?: string | null;
  owner_notification_preferences?: Record<string, string[]>;
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
}

export type ProjectsResponse = PaginatedResponse<Project>;

export interface ProjectNotificationSettings {
  notification_preferences: Record<string, string[]>;
  enforce_notification_settings?: boolean;
}
