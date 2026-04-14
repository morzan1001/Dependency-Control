export interface MCPApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface MCPApiKeyCreateResponse extends MCPApiKey {
  /** Plaintext token — server returns it once. Show it to the user
   *  immediately and discard from memory after they copy it. */
  token: string;
}

export interface MCPApiKeyListResponse {
  keys: MCPApiKey[];
}

export interface MCPApiKeyCreatePayload {
  name: string;
  expires_in_days: number;
}
