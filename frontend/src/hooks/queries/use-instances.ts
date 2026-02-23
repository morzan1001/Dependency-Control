import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gitlabInstancesApi } from '@/api/gitlab-instances';
import { githubInstancesApi } from '@/api/github-instances';
import { GitLabInstance, GitLabInstanceCreate, GitLabInstanceUpdate, GitLabInstanceList, GitLabInstanceTestConnectionResponse } from '@/types/gitlab';
import { GitHubInstance, GitHubInstanceCreate, GitHubInstanceUpdate, GitHubInstanceList, GitHubInstanceTestConnectionResponse } from '@/types/github';

// --- Query Keys ---

function createInstanceKeys(prefix: string) {
  return {
    all: [prefix] as const,
    list: (params?: { active_only?: boolean }) => [prefix, params] as const,
  };
}

export const gitlabInstanceKeys = createInstanceKeys('gitlab-instances');
export const githubInstanceKeys = createInstanceKeys('github-instances');

// --- Hook Factory ---

interface InstanceApi<TInstance, TList, TCreate, TUpdate, TTest> {
  list: (params?: { page?: number; size?: number; active_only?: boolean }) => Promise<TList>;
  get: (id: string) => Promise<TInstance>;
  create: (data: TCreate) => Promise<TInstance>;
  update: (id: string, data: TUpdate) => Promise<TInstance>;
  delete: (id: string, force?: boolean) => Promise<void>;
  testConnection: (id: string) => Promise<TTest>;
}

function createInstanceHooks<TInstance, TList, TCreate, TUpdate, TTest>(
  api: InstanceApi<TInstance, TList, TCreate, TUpdate, TTest>,
  keys: ReturnType<typeof createInstanceKeys>,
) {
  const useInstances = (params?: { active_only?: boolean }) =>
    useQuery({
      queryKey: keys.list(params),
      queryFn: () => api.list(params),
    });

  const useCreate = () => {
    const queryClient = useQueryClient();
    return useMutation({
      mutationFn: (data: TCreate) => api.create(data),
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: keys.all });
      },
    });
  };

  const useUpdate = () => {
    const queryClient = useQueryClient();
    return useMutation({
      mutationFn: ({ id, data }: { id: string; data: TUpdate }) => api.update(id, data),
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: keys.all });
      },
    });
  };

  const useDelete = () => {
    const queryClient = useQueryClient();
    return useMutation({
      mutationFn: ({ id, force }: { id: string; force?: boolean }) => api.delete(id, force),
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: keys.all });
      },
    });
  };

  const useTestConnection = () =>
    useMutation({
      mutationFn: (id: string) => api.testConnection(id),
    });

  return { useInstances, useCreate, useUpdate, useDelete, useTestConnection };
}

// --- GitLab Hooks ---

const gitlab = createInstanceHooks<GitLabInstance, GitLabInstanceList, GitLabInstanceCreate, GitLabInstanceUpdate, GitLabInstanceTestConnectionResponse>(
  gitlabInstancesApi,
  gitlabInstanceKeys,
);

export const useGitLabInstances = gitlab.useInstances;
export const useCreateGitLabInstance = gitlab.useCreate;
export const useUpdateGitLabInstance = gitlab.useUpdate;
export const useDeleteGitLabInstance = gitlab.useDelete;
export const useTestGitLabConnection = gitlab.useTestConnection;

// --- GitHub Hooks ---

const github = createInstanceHooks<GitHubInstance, GitHubInstanceList, GitHubInstanceCreate, GitHubInstanceUpdate, GitHubInstanceTestConnectionResponse>(
  githubInstancesApi,
  githubInstanceKeys,
);

export const useGitHubInstances = github.useInstances;
export const useCreateGitHubInstance = github.useCreate;
export const useUpdateGitHubInstance = github.useUpdate;
export const useDeleteGitHubInstance = github.useDelete;
export const useTestGitHubConnection = github.useTestConnection;
