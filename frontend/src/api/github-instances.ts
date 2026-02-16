import { api } from '@/api/client';
import {
  GitHubInstance,
  GitHubInstanceCreate,
  GitHubInstanceUpdate,
  GitHubInstanceList,
  GitHubInstanceTestConnectionResponse,
} from '@/types/github';

export const githubInstancesApi = {
  list: async (params?: { page?: number; size?: number; active_only?: boolean }): Promise<GitHubInstanceList> => {
    const response = await api.get<GitHubInstanceList>('/github-instances/', { params });
    return response.data;
  },

  get: async (instanceId: string): Promise<GitHubInstance> => {
    const response = await api.get<GitHubInstance>(`/github-instances/${instanceId}`);
    return response.data;
  },

  create: async (data: GitHubInstanceCreate): Promise<GitHubInstance> => {
    const response = await api.post<GitHubInstance>('/github-instances/', data);
    return response.data;
  },

  update: async (instanceId: string, data: GitHubInstanceUpdate): Promise<GitHubInstance> => {
    const response = await api.put<GitHubInstance>(`/github-instances/${instanceId}`, data);
    return response.data;
  },

  delete: async (instanceId: string, force = false): Promise<void> => {
    await api.delete(`/github-instances/${instanceId}`, {
      params: { force },
    });
  },

  testConnection: async (instanceId: string): Promise<GitHubInstanceTestConnectionResponse> => {
    const response = await api.post<GitHubInstanceTestConnectionResponse>(
      `/github-instances/${instanceId}/test-connection`
    );
    return response.data;
  },
};
