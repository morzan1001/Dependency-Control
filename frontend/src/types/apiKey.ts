/** What a saturated key listing left out; null while the listing is the whole of it. */
export interface KeyListTruncation {
  limit: number;
  returned: number;
  total: number;
}

export type ApiKeySurface = 'mcp' | 'adhoc';

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  surfaces: ApiKeySurface[];
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface ApiKeyCreateResponse extends ApiKey {
  expires_at: string;
  /** Plaintext token; the server returns it only once. */
  token: string;
}

export interface ApiKeyListResponse {
  keys: ApiKey[];
  truncated: KeyListTruncation | null;
}

export interface ApiKeyCreatePayload {
  name: string;
  surfaces: ApiKeySurface[];
  expires_in_days?: number;
}
