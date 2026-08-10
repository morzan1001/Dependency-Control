import { api } from '@/api/client';
import {
  ComponentsPage, CryptoPage, InventoryStats, InventoryTable, LicensesPayload,
} from '@/types/inventory';

export interface ComponentsParams {
  branch?: string;
  page?: number;
  pageSize?: number;
  search?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export const inventoryApi = {
  getStats: async (projectId: string, branch?: string): Promise<InventoryStats> => {
    const response = await api.get<InventoryStats>(`/projects/${projectId}/inventory/stats`, { params: { branch } });
    return response.data;
  },

  getComponents: async (projectId: string, params: ComponentsParams = {}): Promise<ComponentsPage> => {
    const { branch, page = 1, pageSize = 25, search, sortBy = 'name', sortOrder = 'asc' } = params;
    const response = await api.get<ComponentsPage>(`/projects/${projectId}/inventory/components`, {
      params: { branch, page, page_size: pageSize, search: search || undefined, sort_by: sortBy, sort_order: sortOrder },
    });
    return response.data;
  },

  getLicenses: async (projectId: string, branch?: string): Promise<LicensesPayload> => {
    const response = await api.get<LicensesPayload>(`/projects/${projectId}/inventory/licenses`, { params: { branch } });
    return response.data;
  },

  getCrypto: async (projectId: string, params: { branch?: string; page?: number; pageSize?: number } = {}): Promise<CryptoPage> => {
    const { branch, page = 1, pageSize = 25 } = params;
    const response = await api.get<CryptoPage>(`/projects/${projectId}/inventory/crypto`, {
      params: { branch, page, page_size: pageSize },
    });
    return response.data;
  },

  exportTable: async (projectId: string, table: InventoryTable, branch?: string): Promise<Blob> => {
    const response = await api.get(`/projects/${projectId}/inventory/${table}/export`, {
      params: { branch },
      responseType: 'blob',
    });
    return response.data;
  },
};
