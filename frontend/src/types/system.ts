export interface SystemSettings {
  instance_name?: string;
  project_limit_per_user: number;
  allow_public_registration: boolean;
  enforce_2fa?: boolean;
  enforce_email_verification?: boolean;
  smtp_host?: string;
  smtp_port?: number;
  smtp_user?: string;
  smtp_password?: string;
  smtp_encryption?: string;
  emails_from_email?: string;
  emails_from_name?: string;
  oidc_enabled?: boolean;
  oidc_provider_name?: string;
  oidc_client_id?: string;
  oidc_client_secret?: string;
  oidc_issuer?: string;
  oidc_authorization_endpoint?: string;
  oidc_token_endpoint?: string;
  oidc_userinfo_endpoint?: string;
  oidc_scopes?: string;
  retention_mode: 'global' | 'project';
  global_retention_days: number;
  global_retention_action: 'delete' | 'archive' | 'none';
  rescan_mode: 'global' | 'project';
  global_rescan_enabled: boolean;
  global_rescan_interval: number;
  slack_bot_token?: string;
  slack_client_id?: string;
  slack_client_secret?: string;
  slack_oauth_scopes?: string;
  slack_refresh_token?: string;
  slack_token_expires_at?: number;
  mattermost_url?: string;
  mattermost_bot_token?: string;
  github_token?: string;
  open_source_malware_api_key?: string;
  default_active_analyzers?: string[];
  chat_enabled?: boolean;
  chat_rate_limit_per_minute?: number;
  chat_rate_limit_per_hour?: number;
}

export interface PublicConfig {
  allow_public_registration: boolean;
  enforce_2fa: boolean;
  enforce_email_verification: boolean;
  oidc_enabled?: boolean;
  oidc_provider_name?: string;
}

export interface NotificationChannels {
  email: boolean;
  slack: boolean;
  mattermost: boolean;
}

export interface AppConfig {
  archive_enabled: boolean;
  project_limit_per_user: number;
  retention_mode: 'global' | 'project';
  global_retention_days: number;
  global_retention_action: 'delete' | 'archive' | 'none';
  rescan_mode: 'global' | 'project';
  global_rescan_enabled: boolean;
  global_rescan_interval: number;
  notifications: NotificationChannels;
  slack_client_id?: string;
  slack_oauth_scopes?: string;
  chat_enabled?: boolean;
}

export interface SettingsTabProps {
  formData: Partial<SystemSettings>;
  handleInputChange: (field: keyof SystemSettings, value: string | number | boolean | string[]) => void;
  handleSave: () => void;
  hasPermission: (permission: string) => boolean;
  isPending: boolean;
}