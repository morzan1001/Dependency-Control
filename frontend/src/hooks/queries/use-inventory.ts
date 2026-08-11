import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { inventoryApi, ComponentsParams } from '@/api/inventory';
import { ApiError } from '@/api/client';

// 4xx responses won't succeed on retry (bad request/not found on this branch); only transient/server errors should retry.
export const retryUnlessClientError = (failureCount: number, error: unknown) => {
  const status = (error as ApiError).response?.status;
  if (status !== undefined && status >= 400 && status < 500) return false;
  return failureCount < 2;
};

export function useInventoryStats(projectId: string, branch?: string) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'stats'],
    queryFn: () => inventoryApi.getStats(projectId, branch),
    enabled: !!projectId && !!branch,
    retry: retryUnlessClientError,
  });
}

export function useInventoryComponents(projectId: string, branch: string | undefined, params: Omit<ComponentsParams, 'branch'>) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'components', params],
    queryFn: () => inventoryApi.getComponents(projectId, { ...params, branch }),
    enabled: !!projectId && !!branch,
    placeholderData: keepPreviousData,
    retry: retryUnlessClientError,
  });
}

export function useInventoryLicenses(projectId: string, branch?: string) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'licenses'],
    queryFn: () => inventoryApi.getLicenses(projectId, branch),
    enabled: !!projectId && !!branch,
    retry: retryUnlessClientError,
  });
}

export function useInventoryCrypto(projectId: string, branch: string | undefined, params: { page?: number; pageSize?: number }) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'crypto', params],
    queryFn: () => inventoryApi.getCrypto(projectId, { ...params, branch }),
    enabled: !!projectId && !!branch,
    placeholderData: keepPreviousData,
    retry: retryUnlessClientError,
  });
}
