export interface AdvisoryPackage {
  name: string;
  version?: string;
  type?: string;
}

export type BroadcastTargetType = 'global' | 'teams' | 'advisory';
export type NotificationChannel = 'email' | 'slack' | 'mattermost' | 'teams';
export type BroadcastType = 'general' | 'advisory';

export interface BroadcastRequest {
  type: BroadcastType;
  target_type: BroadcastTargetType;
  target_teams?: string[];
  packages?: AdvisoryPackage[];
  subject: string;
  message: string;
  channels?: NotificationChannel[];
  dry_run?: boolean;
}

export interface BroadcastResult {
  recipient_count: number;
  project_count?: number;
  unique_user_count?: number;
}

export interface BroadcastHistoryItem {
  id: string;
  type: string;
  target_type: string;
  subject: string;
  created_at: string;
  created_by: string;
  recipient_count: number;
  project_count: number;
  unique_user_count?: number;
}
