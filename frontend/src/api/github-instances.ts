import { api } from '@/api/client';
import {
  GitHubInstance,
  GitHubInstanceCreate,
  GitHubInstanceUpdate,
  GitHubInstanceList,
  GitHubInstanceTestConnectionResponse,
} from '@/types/github';

export const githubInstancesApi = {
  /**
   * List all GitHub instances
   */
  list: async (params?: { page?: number; size?: number; active_only?: boolean }) => {
    const response = await api.get<GitHubInstanceList>('/github-instances/', { params });
    return response.data;
  },

  /**
   * Get a specific GitHub instance by ID
   */
  get: async (instanceId: string) => {
    const response = await api.get<GitHubInstance>(`/github-instances/${instanceId}`);
    return response.data;
  },

  /**
   * Create a new GitHub instance
   */
  create: async (data: GitHubInstanceCreate) => {
    const response = await api.post<GitHubInstance>('/github-instances/', data);
    return response.data;
  },

  /**
   * Update an existing GitHub instance
   */
  update: async (instanceId: string, data: GitHubInstanceUpdate) => {
    const response = await api.put<GitHubInstance>(`/github-instances/${instanceId}`, data);
    return response.data;
  },

  /**
   * Delete a GitHub instance
   */
  delete: async (instanceId: string, force = false) => {
    await api.delete(`/github-instances/${instanceId}`, {
      params: { force },
    });
  },

  /**
   * Test connection to a GitHub instance (JWKS endpoint reachability)
   */
  testConnection: async (instanceId: string) => {
    const response = await api.post<GitHubInstanceTestConnectionResponse>(
      `/github-instances/${instanceId}/test-connection`
    );
    return response.data;
  },
};
