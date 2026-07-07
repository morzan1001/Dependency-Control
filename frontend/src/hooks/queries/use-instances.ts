import { useQuery } from '@tanstack/react-query';
import { gitlabInstancesApi } from '@/api/gitlab-instances';
import { githubInstancesApi } from '@/api/github-instances';
import { GitLabInstanceList } from '@/types/gitlab';
import { GitHubInstanceList } from '@/types/github';

function createInstanceKeys(prefix: string) {
  return {
    all: [prefix] as const,
    list: (params?: { active_only?: boolean }) => [prefix, params] as const,
  };
}

export const gitlabInstanceKeys = createInstanceKeys('gitlab-instances');
export const githubInstanceKeys = createInstanceKeys('github-instances');

interface InstanceApi<TList> {
  list: (params?: { page?: number; size?: number; active_only?: boolean }) => Promise<TList>;
}

function createInstanceHooks<TList>(
  api: InstanceApi<TList>,
  keys: ReturnType<typeof createInstanceKeys>,
) {
  const useInstances = (params?: { active_only?: boolean }) =>
    useQuery({
      queryKey: keys.list(params),
      queryFn: () => api.list(params),
    });

  return { useInstances };
}

const gitlab = createInstanceHooks<GitLabInstanceList>(gitlabInstancesApi, gitlabInstanceKeys);

export const useGitLabInstances = gitlab.useInstances;

const github = createInstanceHooks<GitHubInstanceList>(githubInstancesApi, githubInstanceKeys);

export const useGitHubInstances = github.useInstances;
