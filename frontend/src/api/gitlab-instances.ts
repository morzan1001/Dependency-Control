import { api } from '@/api/client';
import {
  GitLabInstance,
  GitLabInstanceCreate,
  GitLabInstanceUpdate,
  GitLabInstanceList,
  GitLabInstanceTestConnectionResponse,
} from '@/types/gitlab';

export const gitlabInstancesApi = {
  /**
   * List all GitLab instances
   */
  list: async (params?: { page?: number; size?: number; active_only?: boolean }) => {
    const response = await api.get<GitLabInstanceList>('/gitlab-instances', { params });
    return response.data;
  },

  /**
   * Get a specific GitLab instance by ID
   */
  get: async (instanceId: string) => {
    const response = await api.get<GitLabInstance>(`/gitlab-instances/${instanceId}`);
    return response.data;
  },

  /**
   * Create a new GitLab instance
   */
  create: async (data: GitLabInstanceCreate) => {
    const response = await api.post<GitLabInstance>('/gitlab-instances', data);
    return response.data;
  },

  /**
   * Update an existing GitLab instance
   */
  update: async (instanceId: string, data: GitLabInstanceUpdate) => {
    const response = await api.put<GitLabInstance>(`/gitlab-instances/${instanceId}`, data);
    return response.data;
  },

  /**
   * Delete a GitLab instance
   */
  delete: async (instanceId: string, force = false) => {
    await api.delete(`/gitlab-instances/${instanceId}`, {
      params: { force },
    });
  },

  /**
   * Test connection to a GitLab instance
   */
  testConnection: async (instanceId: string) => {
    const response = await api.post<GitLabInstanceTestConnectionResponse>(
      `/gitlab-instances/${instanceId}/test-connection`
    );
    return response.data;
  },
};
