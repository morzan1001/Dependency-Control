import { useQuery } from '@tanstack/react-query';
import { gitlabInstancesApi } from '@/api/gitlab-instances';
import { githubInstancesApi } from '@/api/github-instances';

export const gitlabInstanceKeys = { all: ['gitlab-instances'] as const };
export const githubInstanceKeys = { all: ['github-instances'] as const };

export const useGitLabInstances = (params?: { active_only?: boolean }, enabled = true) =>
  useQuery({
    queryKey: [...gitlabInstanceKeys.all, params] as const,
    queryFn: () => gitlabInstancesApi.list(params),
    enabled,
  });

export const useGitHubInstances = (params?: { active_only?: boolean }, enabled = true) =>
  useQuery({
    queryKey: [...githubInstanceKeys.all, params] as const,
    queryFn: () => githubInstancesApi.list(params),
    enabled,
  });

export const useGitLabGroups = (instanceId: string | null, search: string) =>
  useQuery({
    queryKey: [...gitlabInstanceKeys.all, instanceId, 'groups', search] as const,
    queryFn: () => gitlabInstancesApi.listGroups(instanceId as string, search || undefined),
    enabled: !!instanceId,
  });

export const useGitHubOrgs = (instanceId: string | null) =>
  useQuery({
    queryKey: [...githubInstanceKeys.all, instanceId, 'orgs'] as const,
    queryFn: () => githubInstancesApi.listOrgs(instanceId as string),
    enabled: !!instanceId,
  });

export const useGitHubOrgTeams = (instanceId: string | null, org: string | null) =>
  useQuery({
    queryKey: [...githubInstanceKeys.all, instanceId, 'orgs', org, 'teams'] as const,
    queryFn: () => githubInstancesApi.listOrgTeams(instanceId as string, org as string),
    enabled: !!instanceId && !!org,
  });
