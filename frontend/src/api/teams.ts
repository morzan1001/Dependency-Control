import { api } from '@/api/client';
import { Team, TeamCreate, TeamMemberCreate } from '@/types/team';

export const teamApi = {
  getAll: async (search?: string, sortBy = 'name', sortOrder = 'asc'): Promise<Team[]> => {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    params.append('sort_by', sortBy);
    params.append('sort_order', sortOrder);
    const response = await api.get<Team[]>('/teams/', { params });
    return response.data;
  },

  getOne: async (id: string): Promise<Team> => {
    const response = await api.get<Team>(`/teams/${id}`);
    return response.data;
  },

  create: async (data: TeamCreate): Promise<Team> => {
    const response = await api.post<Team>('/teams/', data);
    return response.data;
  },

  update: async (id: string, data: Partial<TeamCreate>): Promise<Team> => {
    const response = await api.put<Team>(`/teams/${id}`, data);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await api.delete(`/teams/${id}`);
  },

  addMember: async (teamId: string, data: TeamMemberCreate): Promise<Team> => {
    const response = await api.post<Team>(`/teams/${teamId}/members`, data);
    return response.data;
  },

  removeMember: async (teamId: string, userId: string): Promise<Team> => {
    const response = await api.delete<Team>(`/teams/${teamId}/members/${userId}`);
    return response.data;
  },

  updateMember: async (teamId: string, userId: string, role: string): Promise<Team> => {
    const response = await api.put<Team>(`/teams/${teamId}/members/${userId}`, { role });
    return response.data;
  }
};
