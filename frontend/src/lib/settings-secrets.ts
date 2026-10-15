import { SystemSettings } from '@/types/system';

export const SECRET_SETTINGS_FIELDS = [
  'github_token',
  'smtp_password',
  'open_source_malware_api_key',
  'slack_bot_token',
  'slack_client_secret',
  'slack_refresh_token',
  'oidc_client_secret',
  'mattermost_bot_token',
] as const;

// The API never echoes secrets, so an empty input means unchanged; sending "" would wipe the stored value.
export function stripEmptySecrets(payload: Partial<SystemSettings>): Partial<SystemSettings> {
  const result = { ...payload };
  for (const key of SECRET_SETTINGS_FIELDS) {
    if (result[key] === '') {
      delete result[key];
    }
  }
  return result;
}
