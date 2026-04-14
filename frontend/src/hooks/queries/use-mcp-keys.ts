import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { mcpKeysApi } from '@/api/mcp-keys';
import type { MCPApiKeyCreatePayload } from '@/types/mcp';

export const mcpKeyQueryKeys = {
  all: ['mcp-keys'] as const,
  list: () => [...mcpKeyQueryKeys.all, 'list'] as const,
};

export function useMcpKeys(enabled: boolean) {
  return useQuery({
    queryKey: mcpKeyQueryKeys.list(),
    queryFn: mcpKeysApi.list,
    enabled,
    staleTime: 30_000,
  });
}

export function useCreateMcpKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: MCPApiKeyCreatePayload) => mcpKeysApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: mcpKeyQueryKeys.list() });
    },
  });
}

export function useRevokeMcpKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (keyId: string) => mcpKeysApi.revoke(keyId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: mcpKeyQueryKeys.list() });
    },
  });
}
