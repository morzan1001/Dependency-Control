import { PaginatedResponse } from './common';

export interface ProjectMember {
  user_id: string;
  username?: string;
  role: string;
  notification_preferences?: Record<string, string[]>;
  inherited_from?: string;
}

// Stats interfaces (simplified for now, ideally imported from stats.ts or similar)
export interface EnhancedStats {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  unknown?: number;
  risk_score?: number;
  [key: string]: any; // for other properties
}

export interface Project {
  _id: string;
  name: string;
  owner_id: string;
  team_id?: string;
  members?: ProjectMember[];
  active_analyzers?: string[];
  retention_days?: number;
  default_branch?: string;
  enforce_notification_settings?: boolean;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  gitlab_project_id?: number;
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
}

export interface ProjectUpdate {
  name?: string;
  team_id?: string | null;
  active_analyzers?: string[];
  retention_days?: number;
  enforce_notification_settings?: boolean;
  default_branch?: string | null;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  owner_notification_preferences?: Record<string, string[]>;
}

export interface ProjectApiKeyResponse {
  project_id: string;
  api_key: string;
  note: string;
}

export type ProjectsResponse = PaginatedResponse<Project>;

export interface ProjectNotificationSettings {
  notification_preferences: Record<string, string[]>;
  enforce_notification_settings?: boolean;
}
