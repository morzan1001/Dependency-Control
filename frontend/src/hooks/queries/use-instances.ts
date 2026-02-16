import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gitlabInstancesApi } from '@/api/gitlab-instances';
import { githubInstancesApi } from '@/api/github-instances';
import { GitLabInstanceCreate, GitLabInstanceUpdate } from '@/types/gitlab';
import { GitHubInstanceCreate, GitHubInstanceUpdate } from '@/types/github';

export const gitlabInstanceKeys = {
  all: ['gitlab-instances'] as const,
  list: (params?: { active_only?: boolean }) => [...gitlabInstanceKeys.all, params] as const,
};

export const githubInstanceKeys = {
  all: ['github-instances'] as const,
  list: (params?: { active_only?: boolean }) => [...githubInstanceKeys.all, params] as const,
};

export const useGitLabInstances = (params?: { active_only?: boolean }) => {
  return useQuery({
    queryKey: gitlabInstanceKeys.list(params),
    queryFn: () => gitlabInstancesApi.list(params),
  });
};

export const useGitHubInstances = (params?: { active_only?: boolean }) => {
  return useQuery({
    queryKey: githubInstanceKeys.list(params),
    queryFn: () => githubInstancesApi.list(params),
  });
};

export const useCreateGitLabInstance = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: GitLabInstanceCreate) => gitlabInstancesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: gitlabInstanceKeys.all });
    },
  });
};

export const useUpdateGitLabInstance = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: GitLabInstanceUpdate }) => gitlabInstancesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: gitlabInstanceKeys.all });
    },
  });
};

export const useDeleteGitLabInstance = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, force }: { id: string; force?: boolean }) => gitlabInstancesApi.delete(id, force),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: gitlabInstanceKeys.all });
    },
  });
};

export const useTestGitLabConnection = () => {
  return useMutation({
    mutationFn: (id: string) => gitlabInstancesApi.testConnection(id),
  });
};

export const useCreateGitHubInstance = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: GitHubInstanceCreate) => githubInstancesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: githubInstanceKeys.all });
    },
  });
};

export const useUpdateGitHubInstance = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: GitHubInstanceUpdate }) => githubInstancesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: githubInstanceKeys.all });
    },
  });
};

export const useDeleteGitHubInstance = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, force }: { id: string; force?: boolean }) => githubInstancesApi.delete(id, force),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: githubInstanceKeys.all });
    },
  });
};

export const useTestGitHubConnection = () => {
  return useMutation({
    mutationFn: (id: string) => githubInstancesApi.testConnection(id),
  });
};
