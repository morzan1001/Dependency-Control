import { api } from '@/api/client';
import { Waiver, WaiverCreate, WaiversPaginatedResponse, WaiversQueryParams } from '@/types/waiver';

export const waiverApi = {
    create: async (data: WaiverCreate) => {
        const response = await api.post<Waiver>('/waivers/', data);
        return response.data;
    },

    delete: async (waiverId: string): Promise<void> => {
        await api.delete(`/waivers/${waiverId}`);
    },

    getAll: async (params: WaiversQueryParams): Promise<WaiversPaginatedResponse> => {
        const response = await api.get<WaiversPaginatedResponse>('/waivers/', { params });
        return response.data;
    },

    getByProject: async (projectId: string, params?: Omit<WaiversQueryParams, 'project_id'>): Promise<WaiversPaginatedResponse> => {
        return waiverApi.getAll({ ...params, project_id: projectId });
    }
};
