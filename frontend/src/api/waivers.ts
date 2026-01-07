import { api } from '@/api/client';
import { Waiver, WaiverCreate } from '@/types/waiver';

export const waiverApi = {
    create: async (data: WaiverCreate) => {
        const response = await api.post<Waiver>('/waivers/', data);
        return response.data;
    },

    delete: async (waiverId: string) => {
        await api.delete(`/waivers/${waiverId}`);
    },

    getAll: async (projectId: string) => {
        const response = await api.get<Waiver[]>(`/projects/${projectId}/waivers`);
        return response.data;
    }
};
