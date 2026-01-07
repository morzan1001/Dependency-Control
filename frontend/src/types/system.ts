export interface SystemSettings {
  allow_registration: boolean;
  teams_enabled: boolean;
  mfa_required: boolean;
  project_limit_per_user: number;
  retention_days: number;
  retention_mode: 'global' | 'project';
  global_retention_days: number;
  
  // Instance
  instance_name?: string;

  // SMTP
  smtp_host?: string;
  smtp_port?: number;
  smtp_username?: string;
  smtp_user?: string; // Alias or typo in component?
  smtp_password?: string;
  smtp_from_email?: string;
  emails_from_email?: string; // Alias or typo in component?
  smtp_encryption?: string;

  // Security & Auth
  enforce_2fa?: boolean;
  enforce_email_verification?: boolean;
  
  // OIDC
  oidc_enabled?: boolean;
  oidc_provider_name?: string;
  oidc_client_id?: string;
  oidc_client_secret?: string;
  oidc_issuer?: string;
  oidc_authorization_endpoint?: string;
  oidc_token_endpoint?: string;
  oidc_userinfo_endpoint?: string;
  oidc_scopes?: string;

  // Rescan
  rescan_mode?: 'global' | 'project';
  global_rescan_enabled?: boolean;
  global_rescan_interval?: number;

  // Integrations - Slack
  slack_bot_token?: string;
  slack_client_id?: string;
  slack_client_secret?: string;

  // Integrations - Mattermost
  mattermost_url?: string;
  mattermost_bot_token?: string;

  // Integrations - GitLab
  gitlab_integration_enabled?: boolean;
  gitlab_url?: string;
  gitlab_oidc_audience?: string;
  gitlab_auto_create_projects?: boolean;
  gitlab_sync_teams?: boolean;
  gitlab_access_token?: string;

  // Integrations - GitHub
  github_token?: string;

  // Enrichment
  open_source_malware_api_key?: string;
  
  [key: string]: any; // Allow flexibility for now
}

export interface PublicConfig {
  allow_public_registration: boolean;
  enforce_2fa: boolean;
  enforce_email_verification: boolean;
  oidc_enabled?: boolean;
  oidc_provider_name?: string;
}
