import { SystemSettings } from '@/types/system';

export const SECRET_SETTINGS_FIELDS = [
  'github_token',
  'smtp_password',
  'open_source_malware_api_key',
  'slack_bot_token',
  'slack_client_secret',
  'slack_refresh_token',
  'oidc_client_secret',
  'gitlab_access_token',
  'mattermost_bot_token',
] as const;

// An empty secret input means "unchanged", not "clear" — the API never echoes
// secrets back, so sending "" would wipe a stored value.
export function stripEmptySecrets(payload: Partial<SystemSettings>): Partial<SystemSettings> {
  const result = { ...payload };
  for (const key of SECRET_SETTINGS_FIELDS) {
    if (result[key] === '') {
      delete result[key];
    }
  }
  return result;
}
