import { api } from '@/api/client';
import { Webhook, WebhookCreate } from '@/types/webhook';

export const webhookApi = {
  getGlobal: async () => {
    const response = await api.get<Webhook[]>('/webhooks/global/');
    return response.data;
  },

  createGlobal: async (data: WebhookCreate) => {
    const response = await api.post<Webhook>('/webhooks/global/', data);
    return response.data;
  },

  getProject: async (projectId: string) => {
    const response = await api.get<Webhook[]>(`/webhooks/project/${projectId}`);
    return response.data;
  },

  createProject: async (projectId: string, data: WebhookCreate) => {
    const response = await api.post<Webhook>(`/webhooks/project/${projectId}`, data);
    return response.data;
  },

  delete: async (id: string) => {
    await api.delete(`/webhooks/${id}`);
  }
};
