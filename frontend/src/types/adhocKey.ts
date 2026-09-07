import type { KeyListTruncation } from '@/types/apiKey';

export interface AdhocApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
}

export interface AdhocApiKeyCreateResponse extends AdhocApiKey {
  /** Plaintext token; the server returns it only once. */
  token: string;
}

export interface AdhocApiKeyListResponse {
  keys: AdhocApiKey[];
  truncated: KeyListTruncation | null;
}

export interface AdhocApiKeyCreatePayload {
  name: string;
  expires_in_days: number;
}
