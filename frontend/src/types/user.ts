export interface User {
  id: string;
  email: string;
  username: string;
  is_active: boolean;
  is_verified?: boolean;
  pending_email?: string | null;
  auth_provider?: string;
  permissions: string[];
  totp_enabled: boolean;
  slack_username?: string;
  mattermost_username?: string;
  notification_preferences?: Record<string, string[]>;
  status?: 'active' | 'invited';
}

export interface UserCreate {
  username: string;
  email: string;
  password: string;
  permissions?: string[];
  is_active?: boolean;
}

export interface UserUpdate {
  permissions?: string[];
  is_active?: boolean;
}

export interface UserUpdateMe {
  slack_username?: string | null;
  mattermost_username?: string | null;
  notification_preferences?: Record<string, string[]>;
}

export interface SystemInvitation {
  id: string;
  email: string;
  token: string;
  invited_by: string;
  created_at: string;
  expires_at: string;
  is_used: boolean;
}

export interface TwoFASetup {
  secret: string;
  qr_code: string;
}

