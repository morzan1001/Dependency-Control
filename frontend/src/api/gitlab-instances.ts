import { api } from '@/api/client';
import {
  GitLabInstance,
  GitLabInstanceCreate,
  GitLabInstanceUpdate,
  GitLabInstanceList,
  GitLabInstanceTestConnectionResponse,
} from '@/types/gitlab';

export const gitlabInstancesApi = {
  list: async (params?: { page?: number; size?: number; active_only?: boolean }): Promise<GitLabInstanceList> => {
    const response = await api.get<GitLabInstanceList>('/gitlab-instances/', { params });
    return response.data;
  },

  get: async (instanceId: string): Promise<GitLabInstance> => {
    const response = await api.get<GitLabInstance>(`/gitlab-instances/${instanceId}`);
    return response.data;
  },

  create: async (data: GitLabInstanceCreate): Promise<GitLabInstance> => {
    const response = await api.post<GitLabInstance>('/gitlab-instances/', data);
    return response.data;
  },

  update: async (instanceId: string, data: GitLabInstanceUpdate): Promise<GitLabInstance> => {
    const response = await api.put<GitLabInstance>(`/gitlab-instances/${instanceId}`, data);
    return response.data;
  },

  delete: async (instanceId: string, force = false): Promise<void> => {
    await api.delete(`/gitlab-instances/${instanceId}`, {
      params: { force },
    });
  },

  testConnection: async (instanceId: string): Promise<GitLabInstanceTestConnectionResponse> => {
    const response = await api.post<GitLabInstanceTestConnectionResponse>(
      `/gitlab-instances/${instanceId}/test-connection`
    );
    return response.data;
  },
};
