import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { adhocKeysApi } from '@/api/adhocKeys';
import type { AdhocApiKeyCreatePayload } from '@/types/adhocKey';

export const adhocKeyQueryKeys = {
  all: ['adhoc-keys'] as const,
  list: () => [...adhocKeyQueryKeys.all, 'list'] as const,
};

export function useAdhocKeys(enabled: boolean) {
  return useQuery({
    queryKey: adhocKeyQueryKeys.list(),
    queryFn: adhocKeysApi.list,
    enabled,
    staleTime: 30_000,
  });
}

export function useCreateAdhocKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: AdhocApiKeyCreatePayload) => adhocKeysApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: adhocKeyQueryKeys.list() });
    },
  });
}

export function useRevokeAdhocKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (keyId: string) => adhocKeysApi.revoke(keyId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: adhocKeyQueryKeys.list() });
    },
  });
}
