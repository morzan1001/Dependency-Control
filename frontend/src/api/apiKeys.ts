import { api } from '@/api/client';
import type {
  ApiKeyCreatePayload,
  ApiKeyCreateResponse,
  ApiKeyListResponse,
} from '@/types/apiKey';

export const apiKeysApi = {
  list: async (): Promise<ApiKeyListResponse> => {
    const response = await api.get<ApiKeyListResponse>('/api-keys/');
    return response.data;
  },

  create: async (payload: ApiKeyCreatePayload): Promise<ApiKeyCreateResponse> => {
    const response = await api.post<ApiKeyCreateResponse>('/api-keys/', payload);
    return response.data;
  },

  revoke: async (keyId: string): Promise<void> => {
    await api.delete(`/api-keys/${keyId}`);
  },
};
