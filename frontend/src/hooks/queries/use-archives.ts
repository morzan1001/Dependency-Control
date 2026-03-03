import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { archivesApi } from '@/api/archives';
import type { ArchiveFilters } from '@/types/archive';

export const archiveKeys = {
  all: ['admin-archives'] as const,
  list: (page: number, filters?: ArchiveFilters & { project_id?: string }) =>
    [...archiveKeys.all, 'list', page, filters] as const,
};

export const useAdminArchives = (
  page: number = 1,
  size: number = 20,
  filters?: ArchiveFilters & { project_id?: string },
) => {
  return useQuery({
    queryKey: archiveKeys.list(page, filters),
    queryFn: () => archivesApi.getAll(page, size, filters),
    placeholderData: keepPreviousData,
  });
};
