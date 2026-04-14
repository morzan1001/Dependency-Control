import { api } from '@/api/client';
import type {
  MCPApiKeyCreatePayload,
  MCPApiKeyCreateResponse,
  MCPApiKeyListResponse,
} from '@/types/mcp';

export const mcpKeysApi = {
  list: async (): Promise<MCPApiKeyListResponse> => {
    const response = await api.get<MCPApiKeyListResponse>('/mcp-keys/');
    return response.data;
  },

  create: async (payload: MCPApiKeyCreatePayload): Promise<MCPApiKeyCreateResponse> => {
    const response = await api.post<MCPApiKeyCreateResponse>('/mcp-keys/', payload);
    return response.data;
  },

  revoke: async (keyId: string): Promise<void> => {
    await api.delete(`/mcp-keys/${keyId}`);
  },
};
