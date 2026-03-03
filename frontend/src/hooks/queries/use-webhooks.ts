import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { webhookApi } from '@/api/webhooks';
import { Webhook, WebhookCreate } from '@/types/webhook';

export const webhookKeys = {
  all: ['webhooks'] as const,
  global: () => [...webhookKeys.all, 'global'] as const,
  project: (projectId: string) => [...webhookKeys.all, 'project', projectId] as const,
  team: (teamId: string) => [...webhookKeys.all, 'team', teamId] as const,
};

export const useGlobalWebhooks = () => {
  return useQuery({
    queryKey: webhookKeys.global(),
    queryFn: () => webhookApi.getGlobal(),
  });
};

export const useProjectWebhooks = (projectId: string) => {
  return useQuery({
    queryKey: webhookKeys.project(projectId),
    queryFn: () => webhookApi.getProject(projectId),
    enabled: !!projectId,
  });
};

export const useCreateGlobalWebhook = () => {
  const queryClient = useQueryClient();
  return useMutation<Webhook, Error, WebhookCreate>({
    mutationFn: (data: WebhookCreate) => webhookApi.createGlobal(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: webhookKeys.global() });
    },
  });
};

export const useCreateProjectWebhook = () => {
  const queryClient = useQueryClient();
  return useMutation<Webhook, Error, { projectId: string; data: WebhookCreate }>({
    mutationFn: ({ projectId, data }) => 
      webhookApi.createProject(projectId, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: webhookKeys.project(variables.projectId) });
    },
  });
};

export const useTeamWebhooks = (teamId: string) => {
  return useQuery({
    queryKey: webhookKeys.team(teamId),
    queryFn: () => webhookApi.getTeam(teamId),
    enabled: !!teamId,
  });
};

export const useCreateTeamWebhook = () => {
  const queryClient = useQueryClient();
  return useMutation<Webhook, Error, { teamId: string; data: WebhookCreate }>({
    mutationFn: ({ teamId, data }) =>
      webhookApi.createTeam(teamId, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: webhookKeys.team(variables.teamId) });
    },
  });
};

export const useDeleteWebhook = () => {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id: string) => webhookApi.delete(id),
    onSuccess: () => {
      // Invalidate all webhooks as we don't know if it was global or project from ID
      queryClient.invalidateQueries({ queryKey: webhookKeys.all });
    },
  });
};
