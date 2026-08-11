import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { inventoryApi, ComponentsParams } from '@/api/inventory';

export function useInventoryStats(projectId: string, branch?: string) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'stats'],
    queryFn: () => inventoryApi.getStats(projectId, branch),
    enabled: !!projectId && !!branch,
    retry: false,
  });
}

export function useInventoryComponents(projectId: string, branch: string | undefined, params: Omit<ComponentsParams, 'branch'>) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'components', params],
    queryFn: () => inventoryApi.getComponents(projectId, { ...params, branch }),
    enabled: !!projectId && !!branch,
    placeholderData: keepPreviousData,
    retry: false,
  });
}

export function useInventoryLicenses(projectId: string, branch?: string) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'licenses'],
    queryFn: () => inventoryApi.getLicenses(projectId, branch),
    enabled: !!projectId && !!branch,
    retry: false,
  });
}

export function useInventoryCrypto(projectId: string, branch: string | undefined, params: { page?: number; pageSize?: number }) {
  return useQuery({
    queryKey: ['inventory', projectId, branch, 'crypto', params],
    queryFn: () => inventoryApi.getCrypto(projectId, { ...params, branch }),
    enabled: !!projectId && !!branch,
    placeholderData: keepPreviousData,
    retry: false,
  });
}
