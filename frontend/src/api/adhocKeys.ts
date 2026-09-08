import { api } from '@/api/client';
import type {
  AdhocApiKeyCreatePayload,
  AdhocApiKeyCreateResponse,
  AdhocApiKeyListResponse,
} from '@/types/adhocKey';

export const adhocKeysApi = {
  list: async (): Promise<AdhocApiKeyListResponse> => {
    const response = await api.get<AdhocApiKeyListResponse>('/analyze-keys/');
    return response.data;
  },

  create: async (payload: AdhocApiKeyCreatePayload): Promise<AdhocApiKeyCreateResponse> => {
    const response = await api.post<AdhocApiKeyCreateResponse>('/analyze-keys/', payload);
    return response.data;
  },

  revoke: async (keyId: string): Promise<void> => {
    await api.delete(`/analyze-keys/${keyId}`);
  },
};
