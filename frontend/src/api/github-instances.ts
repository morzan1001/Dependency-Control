import { api, createInstanceApi } from '@/api/client';
import {
  GitHubInstance,
  GitHubInstanceCreate,
  GitHubInstanceUpdate,
  GitHubInstanceList,
  GitHubInstanceTestConnectionResponse,
  GitHubOrgTeam,
} from '@/types/github';

export const githubInstancesApi = {
  ...createInstanceApi<
    GitHubInstance,
    GitHubInstanceCreate,
    GitHubInstanceUpdate,
    GitHubInstanceList,
    GitHubInstanceTestConnectionResponse
  >('/github-instances'),

  listOrgs: async (instanceId: string): Promise<string[]> => {
    const response = await api.get<string[]>(`/github-instances/${instanceId}/orgs`);
    return response.data;
  },

  listOrgTeams: async (instanceId: string, org: string): Promise<GitHubOrgTeam[]> => {
    const response = await api.get<GitHubOrgTeam[]>(
      `/github-instances/${instanceId}/orgs/${encodeURIComponent(org)}/teams`,
    );
    return response.data;
  },
};
