import { ObjectId } from './common';

export interface User {
  id: ObjectId;
  email: string;
  username: string;
  is_active: boolean;
  is_verified?: boolean;
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
  password?: string;
  is_active?: boolean;
}

export interface UserUpdateMe {
  email?: string;
  username?: string;
  slack_username?: string;
  mattermost_username?: string;
}

export interface SystemInvitation {
  id: ObjectId;
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

