import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { projectApi } from '@/api/projects';
import { ProjectCreate, ProjectUpdate, ProjectNotificationSettings } from '@/types/project';
import type { ArchiveFilters } from '@/types/archive';
import type { ApiError } from '@/api/client';
import { DROPDOWN_PAGE_SIZE } from '@/lib/constants';

// Project list filter interface
interface ProjectListFilters {
  search: string;
  page: number;
  limit: number;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
  teamId?: string;
}

// Centralized Query Keys
export const projectKeys = {
  all: ['projects'] as const,
  lists: () => [...projectKeys.all, 'list'] as const,
  list: (filters: ProjectListFilters) => [...projectKeys.lists(), filters] as const,
  dropdown: () => [...projectKeys.all, 'dropdown'] as const,
  details: () => [...projectKeys.all, 'detail'] as const,
  detail: (id: string) => [...projectKeys.details(), id] as const,
  branches: (id: string) => [...projectKeys.detail(id), 'branches'] as const,
  archives: (id: string, page: number, filters?: ArchiveFilters) => [...projectKeys.detail(id), 'archives', page, filters] as const,
  archiveBranches: (id: string) => [...projectKeys.detail(id), 'archive-branches'] as const,
};

export const useProjects = (
  search: string = '',
  page: number = 1,
  limit: number = 20,
  sortBy: string = 'created_at',
  sortOrder: 'asc' | 'desc' = 'desc',
  teamId?: string,
) => {
  return useQuery<Awaited<ReturnType<typeof projectApi.getAll>>, ApiError>({
    queryKey: projectKeys.list({ search, page, limit, sortBy, sortOrder, teamId }),
    queryFn: () => projectApi.getAll(search, (page - 1) * limit, limit, sortBy, sortOrder, teamId),
    placeholderData: keepPreviousData,
    retry: 2,
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

export const useProjectsDropdown = () => {
  return useQuery({
    queryKey: projectKeys.dropdown(),
    queryFn: () => projectApi.getAll(undefined, 0, DROPDOWN_PAGE_SIZE),
    staleTime: 5 * 60 * 1000,
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
        mutationFn: ({ id, settings }: { id: string, settings: ProjectNotificationSettings }) => projectApi.updateNotificationSettings(id, settings),
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

export const useTransferOwnership = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, newOwnerId }: { id: string, newOwnerId: string }) => projectApi.transferOwnership(id, newOwnerId),
        onSuccess: (_, { id }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(id) });
            queryClient.invalidateQueries({ queryKey: projectKeys.lists() });
        }
    })
}

export const useProjectArchives = (projectId: string, page: number = 1, size: number = 20, filters?: ArchiveFilters) => {
    return useQuery({
        queryKey: projectKeys.archives(projectId, page, filters),
        queryFn: () => projectApi.getArchives(projectId, page, size, filters),
        enabled: !!projectId,
        placeholderData: keepPreviousData,
    });
};

export const useArchiveBranches = (projectId: string) => {
    return useQuery({
        queryKey: projectKeys.archiveBranches(projectId),
        queryFn: () => projectApi.getArchiveBranches(projectId),
        enabled: !!projectId,
        staleTime: 5 * 60 * 1000,
    });
};

export const useRestoreArchive = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ projectId, scanId }: { projectId: string; scanId: string }) =>
            projectApi.restoreArchive(projectId, scanId),
        onSuccess: (_, { projectId }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) });
            queryClient.invalidateQueries({ queryKey: [...projectKeys.detail(projectId), 'archives'] });
        },
    });
};

export const usePinScan = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ projectId, scanId }: { projectId: string; scanId: string }) =>
            projectApi.pinScan(projectId, scanId),
        onSuccess: (_, { projectId }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) });
        },
    });
};

export const useUnpinScan = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ projectId, scanId }: { projectId: string; scanId: string }) =>
            projectApi.unpinScan(projectId, scanId),
        onSuccess: (_, { projectId }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) });
        },
    });
};
