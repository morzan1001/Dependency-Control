import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { archivesApi } from '@/api/archives';
import type { ArchiveFilters } from '@/types/archive';

export const archiveKeys = {
  all: ['admin-archives'] as const,
  list: (page: number, filters?: ArchiveFilters) => [...archiveKeys.all, 'list', page, filters] as const,
};

export interface ArchiveFilterValue {
  branch: string;
  from: string;
  to: string;
}

export const NO_ARCHIVE_FILTER: ArchiveFilterValue = { branch: '', from: '', to: '' };

export function archiveFilters({ branch, from, to }: ArchiveFilterValue): ArchiveFilters | undefined {
  const filters: ArchiveFilters = {};
  if (branch) filters.branch = branch;
  if (from) filters.date_from = new Date(`${from}T00:00:00`).toISOString();
  if (to) filters.date_to = new Date(`${to}T23:59:59`).toISOString();
  return Object.keys(filters).length > 0 ? filters : undefined;
}

export const useAdminArchives = (page: number = 1, size: number = 20, filters?: ArchiveFilters) => {
  return useQuery({
    queryKey: archiveKeys.list(page, filters),
    queryFn: () => archivesApi.getAll(page, size, filters),
    placeholderData: keepPreviousData,
  });
};
