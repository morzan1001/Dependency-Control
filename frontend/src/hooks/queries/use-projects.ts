import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { projectApi } from '@/api/projects';
import { ProjectCreate, ProjectNotificationSettings } from '@/types/project';
import type { ArchiveFilters } from '@/types/archive';
import type { ApiError } from '@/api/client';
import { DROPDOWN_PAGE_SIZE } from '@/lib/constants';

interface ProjectListFilters {
  search: string;
  page: number;
  limit: number;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
  teamId?: string;
}

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
    // Page through all projects so dropdowns are not truncated to the first page.
    queryFn: async () => {
      const first = await projectApi.getAll(undefined, 0, DROPDOWN_PAGE_SIZE, 'name', 'asc');
      const items = [...first.items];
      while (items.length < first.total) {
        const next = await projectApi.getAll(undefined, items.length, DROPDOWN_PAGE_SIZE, 'name', 'asc');
        if (next.items.length === 0) break;
        items.push(...next.items);
      }
      return { ...first, items, total: first.total };
    },
    staleTime: 5 * 60 * 1000,
  });
};

export const useUpdateProjectNotifications = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, settings }: { id: string, settings: ProjectNotificationSettings }) => projectApi.updateNotificationSettings(id, settings),
        onSuccess: (_, { id }) => {
            queryClient.invalidateQueries({ queryKey: projectKeys.detail(id) });
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
