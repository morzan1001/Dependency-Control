import { api } from '@/api/client';
import { User, UserCreate, UserUpdate, UserUpdateMe, SystemInvitation } from '@/types/user';

export const userApi = {
  getAll: async (skip = 0, limit = 20, search?: string, sortBy = 'username', sortOrder = 'asc'): Promise<User[]> => {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    if (search) params.append('search', search);
    params.append('sort_by', sortBy);
    params.append('sort_order', sortOrder);

    const response = await api.get<User[]>('/users/', { params });
    return response.data;
  },

  getMe: async (): Promise<User> => {
    const response = await api.get<User>('/users/me');
    return response.data;
  },

  create: async (data: UserCreate): Promise<User> => {
    const response = await api.post<User>('/users/', data);
    return response.data;
  },

  update: async (userId: string, data: UserUpdate): Promise<User> => {
    const response = await api.put<User>(`/users/${userId}`, data);
    return response.data;
  },

  updateMe: async (data: UserUpdateMe): Promise<User> => {
    const response = await api.patch<User>('/users/me', data);
    return response.data;
  },

  updatePassword: async (currentPassword: string, newPassword: string): Promise<User> => {
    const response = await api.post<User>('/users/me/password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
    return response.data;
  },

  migrateToLocal: async (newPassword: string): Promise<User> => {
    const response = await api.post<User>('/users/me/migrate', { new_password: newPassword });
    return response.data;
  },

  adminMigrateToLocal: async (userId: string): Promise<User> => {
    const response = await api.post<User>(`/users/${userId}/migrate`);
    return response.data;
  },

  adminResetPassword: async (userId: string): Promise<{ message: string; email_sent: boolean; reset_link?: string }> => {
    const response = await api.post<{ message: string; email_sent: boolean; reset_link?: string }>(`/users/${userId}/reset-password`);
    return response.data;
  },

  adminDisable2FA: async (userId: string): Promise<User> => {
    const response = await api.post<User>(`/users/${userId}/2fa/disable`);
    return response.data;
  },

  getPendingInvitations: async (): Promise<SystemInvitation[]> => {
    const response = await api.get<SystemInvitation[]>('/invitations/system');
    return response.data;
  },

  invite: async (email: string): Promise<{ message: string; link: string }> => {
    const response = await api.post<{ message: string; link: string }>('/invitations/system', { email });
    return response.data;
  },

  validateInvitation: async (token: string): Promise<{ email: string }> => {
    const response = await api.get<{ email: string }>(`/invitations/system/${token}`);
    return response.data;
  },

  delete: async (userId: string): Promise<void> => {
    await api.delete(`/users/${userId}`);
  }
};
