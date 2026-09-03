import { api } from '@/api/client';
import { SMALL_PAGE_SIZE } from '@/lib/constants';
import type {
  MarkReleasePayload,
  ReleaseItem,
  ReleaseListResponse,
  UnmarkReleaseResponse,
} from '@/types/release';

export interface ReleaseListParams {
  skip?: number;
  limit?: number;
  environment?: string;
}

export const releaseApi = {
  list: async (projectId: string, params: ReleaseListParams = {}): Promise<ReleaseListResponse> => {
    const { skip = 0, limit = SMALL_PAGE_SIZE, environment } = params;
    const query: Record<string, string | number> = { skip, limit };
    // The endpoint rejects a blank environment against its slug pattern, so an unset one is omitted.
    if (environment) query.environment = environment;
    const response = await api.get<ReleaseListResponse>(`/projects/${projectId}/releases`, { params: query });
    return response.data;
  },

  mark: async (projectId: string, payload: MarkReleasePayload): Promise<ReleaseItem> => {
    const response = await api.post<ReleaseItem>(`/projects/${projectId}/releases`, payload);
    return response.data;
  },

  // The environment is required because withdrawal is per-environment and the endpoint would
  // otherwise silently fall back to its own default while the scan runs elsewhere.
  unmark: async (projectId: string, scanId: string, environment: string): Promise<UnmarkReleaseResponse> => {
    const response = await api.delete<UnmarkReleaseResponse>(
      `/projects/${projectId}/scans/${scanId}/release`,
      { params: { environment } },
    );
    return response.data;
  },
};
