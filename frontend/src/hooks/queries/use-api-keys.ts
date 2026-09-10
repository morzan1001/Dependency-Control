import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiKeysApi } from '@/api/apiKeys';
import type { ApiKeyCreatePayload } from '@/types/apiKey';

export const apiKeyQueryKeys = {
  all: ['api-keys'] as const,
  list: () => [...apiKeyQueryKeys.all, 'list'] as const,
};

export function useApiKeys(enabled: boolean) {
  return useQuery({
    queryKey: apiKeyQueryKeys.list(),
    queryFn: apiKeysApi.list,
    enabled,
    staleTime: 30_000,
  });
}

export function useCreateApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: ApiKeyCreatePayload) => apiKeysApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: apiKeyQueryKeys.list() });
    },
  });
}

export function useRevokeApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (keyId: string) => apiKeysApi.revoke(keyId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: apiKeyQueryKeys.list() });
    },
  });
}
