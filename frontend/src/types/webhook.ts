export interface Webhook {
  id: string;
  project_id?: string;
  url: string;
  events: string[];
  secret?: string;
  is_active: boolean;
  created_at: string;
  last_triggered_at?: string;
}

export interface WebhookCreate {
  url: string;
  events: string[];
  secret?: string;
}
