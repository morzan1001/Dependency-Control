import { api, buildQueryParams } from '@/api/client';
import { AdminArchiveListResponse, ArchiveFilters } from '@/types/archive';

export const archivesApi = {
  getAll: async (
    page: number = 1,
    size: number = 20,
    filters?: ArchiveFilters,
  ): Promise<AdminArchiveListResponse> => {
    const params = buildQueryParams({
      page,
      size,
      branch: filters?.branch,
      date_from: filters?.date_from,
      date_to: filters?.date_to,
    });
    const response = await api.get<AdminArchiveListResponse>('/archives/all', { params });
    return response.data;
  },
};
