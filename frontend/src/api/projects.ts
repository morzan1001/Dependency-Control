import { api, buildQueryParams } from '@/api/client';
import { Project, ProjectCreate, ProjectUpdate, ProjectApiKeyResponse, ProjectsResponse, ProjectNotificationSettings, ProjectMember, BranchInfo } from '@/types/project';
import { ArchiveListResponse, ArchiveRestoreResponse, ArchiveFilters } from '@/types/archive';

export const projectApi = {
  getAll: async (
    search?: string,
    skip: number = 0,
    limit: number = 20,
    sortBy: string = 'created_at',
    sortOrder: 'asc' | 'desc' = 'desc',
    teamId?: string,
  ): Promise<ProjectsResponse> => {
    const params = buildQueryParams({ search, skip, limit, sort_by: sortBy, sort_order: sortOrder, team_id: teamId });

    const response = await api.get<ProjectsResponse>('/projects/', { params });
    return response.data;
  },

  getOne: async (id: string): Promise<Project> => {
    const response = await api.get<Project>(`/projects/${id}`);
    return response.data;
  },

  create: async (data: ProjectCreate): Promise<ProjectApiKeyResponse> => {
    const response = await api.post<ProjectApiKeyResponse>('/projects/', data);
    return response.data;
  },

  update: async (id: string, data: ProjectUpdate): Promise<Project> => {
    const response = await api.put<Project>(`/projects/${id}`, data);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await api.delete(`/projects/${id}`);
  },

  getBranches: async (id: string): Promise<BranchInfo[]> => {
    const response = await api.get<BranchInfo[]>(`/projects/${id}/branches`);
    return response.data;
  },

  exportCsv: async (projectId: string): Promise<Blob> => {
    const response = await api.get(`/projects/${projectId}/export/csv`, { responseType: 'blob' });
    return response.data;
  },

  exportSbom: async (projectId: string): Promise<Blob> => {
    const response = await api.get(`/projects/${projectId}/export/sbom`, { responseType: 'blob' });
    return response.data;
  },

  rotateApiKey: async (projectId: string): Promise<ProjectApiKeyResponse> => {
    const response = await api.post<ProjectApiKeyResponse>(`/projects/${projectId}/rotate-key`);
    return response.data;
  },

  updateNotificationSettings: async (projectId: string, settings: ProjectNotificationSettings): Promise<Project> => {
    const response = await api.put<Project>(`/projects/${projectId}/notifications`, settings);
    return response.data;
  },

  inviteMember: async (projectId: string, email: string, role: string): Promise<{ message: string }> => {
    const response = await api.post<{ message: string }>(`/projects/${projectId}/invite`, { email, role });
    return response.data;
  },

  updateMember: async (projectId: string, userId: string, role: string): Promise<ProjectMember> => {
    const response = await api.put<ProjectMember>(`/projects/${projectId}/members/${userId}`, { role });
    return response.data;
  },

  removeMember: async (projectId: string, userId: string): Promise<{ message: string }> => {
    const response = await api.delete<{ message: string }>(`/projects/${projectId}/members/${userId}`);
    return response.data;
  },

  transferOwnership: async (projectId: string, newOwnerId: string): Promise<Project> => {
    const response = await api.post<Project>(`/projects/${projectId}/transfer-ownership`, { new_owner_id: newOwnerId });
    return response.data;
  },

  getArchives: async (
    projectId: string,
    page: number = 1,
    size: number = 20,
    filters?: ArchiveFilters,
  ): Promise<ArchiveListResponse> => {
    const params = buildQueryParams({
      page, size,
      branch: filters?.branch,
      date_from: filters?.date_from,
      date_to: filters?.date_to,
    });
    const response = await api.get<ArchiveListResponse>(`/projects/${projectId}/archives`, { params });
    return response.data;
  },

  getArchiveBranches: async (projectId: string): Promise<string[]> => {
    const response = await api.get<string[]>(`/projects/${projectId}/archives/branches`);
    return response.data;
  },

  restoreArchive: async (projectId: string, scanId: string): Promise<ArchiveRestoreResponse> => {
    const response = await api.post<ArchiveRestoreResponse>(`/projects/${projectId}/archives/${scanId}/restore`);
    return response.data;
  },

  downloadArchive: async (projectId: string, scanId: string): Promise<Blob> => {
    const response = await api.get(`/projects/${projectId}/archives/${scanId}/download`, { responseType: 'blob' });
    return response.data;
  },

  pinScan: async (projectId: string, scanId: string): Promise<{ scan_id: string; pinned: boolean }> => {
    const response = await api.post<{ scan_id: string; pinned: boolean }>(`/projects/${projectId}/scans/${scanId}/pin`);
    return response.data;
  },

  unpinScan: async (projectId: string, scanId: string): Promise<{ scan_id: string; pinned: boolean }> => {
    const response = await api.post<{ scan_id: string; pinned: boolean }>(`/projects/${projectId}/scans/${scanId}/unpin`);
    return response.data;
  },
};
