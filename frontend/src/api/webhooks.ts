import { api } from '@/api/client';
import { Webhook, WebhookCreate } from '@/types/webhook';

export const webhookApi = {
  getGlobal: async (): Promise<Webhook[]> => {
    const response = await api.get<{ items: Webhook[] }>('/webhooks/global/');
    return response.data.items || [];
  },

  createGlobal: async (data: WebhookCreate): Promise<Webhook> => {
    const response = await api.post<Webhook>('/webhooks/global/', data);
    return response.data;
  },

  getProject: async (projectId: string): Promise<Webhook[]> => {
    const response = await api.get<{ items: Webhook[] }>(`/webhooks/project/${projectId}`);
    return response.data.items || [];
  },

  createProject: async (projectId: string, data: WebhookCreate): Promise<Webhook> => {
    const response = await api.post<Webhook>(`/webhooks/project/${projectId}`, data);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await api.delete(`/webhooks/${id}`);
  }
};
