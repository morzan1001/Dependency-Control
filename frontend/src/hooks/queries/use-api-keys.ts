import { useMutation, useQuery, useQueryClient, type MutationMeta } from '@tanstack/react-query';

import { apiKeysApi } from '@/api/apiKeys';
import type { ApiKeyCreatePayload } from '@/types/apiKey';

export const apiKeyQueryKeys = {
  all: ['api-keys'] as const,
  list: () => [...apiKeyQueryKeys.all, 'list'] as const,
};

export function useApiKeys() {
  return useQuery({
    queryKey: apiKeyQueryKeys.list(),
    queryFn: apiKeysApi.list,
    staleTime: 30_000,
  });
}

export function useCreateApiKey(meta?: MutationMeta) {
  const qc = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (payload: ApiKeyCreatePayload) => apiKeysApi.create(payload),
    // The result carries the one-time plaintext. Without this, reset() only detaches the observer
    // and the MutationCache keeps the token for the default five minutes.
    gcTime: 0,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: apiKeyQueryKeys.list() });
    },
  });
}

export function useRevokeApiKey(meta?: MutationMeta) {
  const qc = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (keyId: string) => apiKeysApi.revoke(keyId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: apiKeyQueryKeys.list() });
    },
  });
}
