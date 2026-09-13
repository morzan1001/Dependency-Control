import { api, buildQueryParams, createInstanceApi } from '@/api/client';
import {
  GitLabGroupOption,
  GitLabInstance,
  GitLabInstanceCreate,
  GitLabInstanceUpdate,
  GitLabInstanceList,
  GitLabInstanceTestConnectionResponse,
} from '@/types/gitlab';

export const gitlabInstancesApi = {
  ...createInstanceApi<
    GitLabInstance,
    GitLabInstanceCreate,
    GitLabInstanceUpdate,
    GitLabInstanceList,
    GitLabInstanceTestConnectionResponse
  >('/gitlab-instances'),

  listGroups: async (instanceId: string, search?: string): Promise<GitLabGroupOption[]> => {
    const params = buildQueryParams({ search });
    const response = await api.get<GitLabGroupOption[]>(`/gitlab-instances/${instanceId}/groups`, { params });
    return response.data;
  },
};
