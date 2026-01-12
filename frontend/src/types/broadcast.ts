export interface AdvisoryPackage {
  name: string;
  version?: string;
  type?: string;
}

export type BroadcastTargetType = 'global' | 'teams' | 'advisory';
export type NotificationChannel = 'email' | 'slack' | 'mattermost' | 'teams';

export interface BroadcastRequest {
  type: 'general' | 'advisory';
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
  recipient_count: number;
  project_count: number;
}
