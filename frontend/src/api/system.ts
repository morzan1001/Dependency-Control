import { api } from '@/api/client';
import { SystemSettings, PublicConfig, AppConfig } from '@/types/system';

export const systemApi = {
  getSettings: async () => {
    const response = await api.get<SystemSettings>('/system/settings');
    return response.data;
  },
  
  updateSettings: async (data: Partial<SystemSettings>) => {
    const response = await api.put<SystemSettings>('/system/settings', data);
    return response.data;
  },

  getPublicConfig: async () => {
    const response = await api.get<PublicConfig>('/system/public-config');
    return response.data;
  },

  /**
   * Get lightweight, non-sensitive app configuration for authenticated users.
   * Use this instead of getSettings for components that only need config data.
   */
  getAppConfig: async () => {
    const response = await api.get<AppConfig>('/system/app-config');
    return response.data;
  },

  getNotificationChannels: async () => {
    const response = await api.get<string[]>('/system/notifications/channels');
    return response.data;
  }
};
