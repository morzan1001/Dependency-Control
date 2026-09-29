export interface AdvisoryPackage {
  name: string;
  version?: string;
  type?: string;
}

export type BroadcastTargetType = 'global' | 'teams' | 'advisory';
export type NotificationChannel = 'email' | 'slack' | 'mattermost' | 'teams';

export interface BroadcastRequest {
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
  // Matched dependencies whose version could not be compared with the max version.
  uncomparable_versions?: string[];
}

export interface BroadcastHistoryItem {
  id: string;
  type: string;
  target_type: string;
  subject: string;
  created_at: string;
  created_by?: string;
  recipient_count: number;
  project_count: number;
  teams?: string[];
}

export interface PackageSuggestions {
  // Alphabetical, at most the endpoint's suggestion limit.
  names: string[];
  // More packages match than are listed; the query has to narrow to reach them.
  more: boolean;
}
