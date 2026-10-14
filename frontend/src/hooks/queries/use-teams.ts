import { useQuery, useMutation, useQueryClient, keepPreviousData, type MutationMeta } from '@tanstack/react-query';
import { teamApi } from '@/api/teams';
import { useDebounce } from '@/hooks/use-debounce';
import { isNameTaken, type Named } from '@/lib/utils';
import { TeamBindingRequest, TeamCreate, TeamMemberCreate } from '@/types/team';

export const teamKeys = {
  all: ['teams'] as const,
  lists: () => [...teamKeys.all, 'list'] as const,
  list: (filters: Record<string, unknown>) => [...teamKeys.lists(), filters] as const,
};

interface UseTeamsOptions {
  enabled?: boolean;
}

export const useTeams = (
  search?: string, 
  sortBy = 'name', 
  sortOrder = 'asc',
  options: UseTeamsOptions = {}
) => {
  const { enabled = true } = options;
  return useQuery({
    queryKey: teamKeys.list({ search, sortBy, sortOrder }),
    queryFn: () => teamApi.getAll(search, sortBy, sortOrder),
    enabled,
    placeholderData: keepPreviousData,
  });
};

export const useTeamNameTaken = (name: string, current?: Named) => {
  const search = useDebounce(name.trim());
  const enabled = search !== '' && search !== current?.name;
  const { data } = useTeams(search, 'name', 'asc', { enabled });
  return isNameTaken(data, name, current);
};

export const useCreateTeam = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (data: TeamCreate) => teamApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useDeleteTeam = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (id: string) => teamApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useAddTeamMember = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: ({ teamId, data }: { teamId: string; data: TeamMemberCreate }) => 
      teamApi.addMember(teamId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useUpdateTeam = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: ({ id, data }: { id: string; data: Partial<TeamCreate> }) => 
      teamApi.update(id, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: teamKeys.lists() }),
  });
};

export const useRemoveTeamMember = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: ({ teamId, userId }: { teamId: string; userId: string }) => 
      teamApi.removeMember(teamId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useSetTeamBinding = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: ({ teamId, data }: { teamId: string; data: TeamBindingRequest }) =>
      teamApi.setBinding(teamId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useClearTeamBinding = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: ({ teamId, instanceId }: { teamId: string; instanceId: string }) =>
      teamApi.clearBinding(teamId, instanceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useUpdateTeamMember = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: ({ teamId, userId, role }: { teamId: string; userId: string; role: string }) => 
      teamApi.updateMember(teamId, userId, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};
