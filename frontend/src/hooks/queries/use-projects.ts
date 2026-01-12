import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { projectApi } from '@/api/projects';
import { ProjectCreate, ProjectUpdate } from '@/types/project';

// Centralized Query Keys
export const projectKeys = {
  all: ['projects'] as const,
  lists: () => [...projectKeys.all, 'list'] as const,
  list: (filters: Record<string, unknown>) => [...projectKeys.lists(), filters] as const,
  details: () => [...projectKeys.all, 'detail'] as const,
  detail: (id: string) => [...projectKeys.details(), id] as const,
  branches: (id: string) => [...projectKeys.detail(id), 'branches'] as const,
};

export const useProjects = (
  search: string = '',
  page: number = 1,
  limit: number = 20,
  sortBy: string = 'created_at',
  sortOrder: 'asc' | 'desc' = 'desc'
) => {
  return useQuery({
    queryKey: projectKeys.list({ search, page, limit, sortBy, sortOrder }),
    queryFn: () => projectApi.getAll(search, (page - 1) * limit, limit, sortBy, sortOrder),
    placeholderData: keepPreviousData,
  });
};

export const useProject = (id: string) => {
  return useQuery({
    queryKey: projectKeys.detail(id),
    queryFn: () => projectApi.getOne(id),
    enabled: !!id,
  });
};

export const useCreateProject = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: ProjectCreate) => projectApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() });
    },
  });
};

export const useUpdateProject = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: ProjectUpdate }) => projectApi.update(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: projectKeys.detail(variables.id) });
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() });
    },
  });
};

export const useDeleteProject = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => projectApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() });
    },
  });
};

export const useProjectBranches = (id: string) => {
  return useQuery({
    queryKey: projectKeys.branches(id),
    queryFn: () => projectApi.getBranches(id),
    enabled: !!id,
  });
};

export const useRotateProjectApiKey = () => {
    return useMutation({
        mutationFn: (id: string) => projectApi.rotateApiKey(id),
        onSuccess: () => {
             // Maybe invalidate project details? Usually API key is returned and shown once.
        }
    })
}

export const useUpdateProjectNotifications = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, settings }: { id: string, settings: unknown }) => projectApi.updateNotificationSettings(id, settings),
        onSuccess: (_, { id }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(id) });
        }
    })
}

export const useInviteProjectMember = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, email, role }: { id: string, email: string, role: string }) => projectApi.inviteMember(id, email, role),
        onSuccess: (_, { id }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(id) });
        }
    })
}

export const useUpdateProjectMember = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, userId, role }: { id: string, userId: string, role: string }) => projectApi.updateMember(id, userId, role),
        onSuccess: (_, { id }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(id) });
        }
    })
}

export const useRemoveProjectMember = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, userId }: { id: string, userId: string }) => projectApi.removeMember(id, userId),
        onSuccess: (_, { id }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(id) });
        }
    })
}
