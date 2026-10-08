export type WebhookType = "generic" | "teams" | "slack";

export interface Webhook {
  id: string;
  project_id?: string;
  team_id?: string;
  url: string;
  events: string[];
  is_active: boolean;
  created_at: string;
  last_triggered_at?: string;
  last_failure_at?: string;
  webhook_type?: WebhookType;
  secret_configured: boolean;
}

export interface WebhookCreate {
  url: string;
  events: string[];
  secret?: string;
  webhook_type?: WebhookType;
}

// Only the sent fields change; a null secret removes the stored one.
export interface WebhookUpdate {
  url?: string;
  events?: string[];
  is_active?: boolean;
  secret?: string | null;
  webhook_type?: WebhookType;
}

export interface WebhookTestResult {
  success: boolean;
  status_code: number | null;
  error: string | null;
}
