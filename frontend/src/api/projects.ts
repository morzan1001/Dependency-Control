import { api } from '@/api/client';
import { Project, ProjectCreate, ProjectUpdate, ProjectApiKeyResponse, ProjectsResponse, ProjectNotificationSettings, ProjectMember } from '@/types/project';

export const projectApi = {
  getAll: async (
    search?: string, 
    skip: number = 0, 
    limit: number = 20, 
    sortBy: string = 'created_at', 
    sortOrder: 'asc' | 'desc' = 'desc'
  ) => {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    params.append('sort_by', sortBy);
    params.append('sort_order', sortOrder);
    
    const response = await api.get<ProjectsResponse>('/projects/', { params });
    return response.data;
  },

  getOne: async (id: string) => {
    const response = await api.get<Project>(`/projects/${id}`);
    return response.data;
  },

  create: async (data: ProjectCreate) => {
    const response = await api.post<ProjectApiKeyResponse>('/projects/', data);
    return response.data;
  },

  update: async (id: string, data: ProjectUpdate) => {
    const response = await api.put<Project>(`/projects/${id}`, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete<{ message: string }>(`/projects/${id}`);
    return response.data;
  },

  getBranches: async (id: string) => {
    const response = await api.get<string[]>(`/projects/${id}/branches`);
    return response.data;
  },

  exportCsv: async (projectId: string) => {
    const response = await api.get(`/projects/${projectId}/export/csv`, { responseType: 'blob' });
    return response.data;
  },

  exportSbom: async (projectId: string) => {
    const response = await api.get(`/projects/${projectId}/export/sbom`, { responseType: 'blob' });
    return response.data;
  },

  rotateApiKey: async (projectId: string) => {
    const response = await api.post<ProjectApiKeyResponse>(`/projects/${projectId}/rotate-key`);
    return response.data;
  },

  updateNotificationSettings: async (projectId: string, settings: ProjectNotificationSettings) => {
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
  }
};
