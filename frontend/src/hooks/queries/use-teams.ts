import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { teamApi } from '@/api/teams';
import { TeamCreate, TeamMemberCreate } from '@/types/team';

export const teamKeys = {
  all: ['teams'] as const,
  lists: () => [...teamKeys.all, 'list'] as const,
  list: (filters: Record<string, any>) => [...teamKeys.lists(), filters] as const,
  details: () => [...teamKeys.all, 'detail'] as const,
  detail: (id: string) => [...teamKeys.details(), id] as const,
};

export const useTeams = (search?: string, sortBy = 'name', sortOrder = 'asc') => {
  return useQuery({
    queryKey: teamKeys.list({ search, sortBy, sortOrder }),
    queryFn: () => teamApi.getAll(search, sortBy, sortOrder),
  });
};

export const useTeam = (id: string) => {
  return useQuery({
    queryKey: teamKeys.detail(id),
    queryFn: () => teamApi.getOne(id),
    enabled: !!id,
  });
};

export const useCreateTeam = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: TeamCreate) => teamApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useDeleteTeam = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => teamApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useAddTeamMember = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ teamId, data }: { teamId: string; data: TeamMemberCreate }) => 
      teamApi.addMember(teamId, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.detail(variables.teamId) });
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useUpdateTeam = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<TeamCreate> }) => 
      teamApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useRemoveTeamMember = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ teamId, userId }: { teamId: string; userId: string }) => 
      teamApi.removeMember(teamId, userId),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.detail(variables.teamId) });
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};

export const useUpdateTeamMember = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ teamId, userId, role }: { teamId: string; userId: string; role: string }) => 
      teamApi.updateMember(teamId, userId, role),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.detail(variables.teamId) });
      queryClient.invalidateQueries({ queryKey: teamKeys.lists() });
    },
  });
};
