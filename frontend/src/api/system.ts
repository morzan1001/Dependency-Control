import { api } from '@/api/client';
import { SystemSettings, PublicConfig, AppConfig } from '@/types/system';

export const systemApi = {
  getSettings: async (): Promise<SystemSettings> => {
    const response = await api.get<SystemSettings>('/system/settings');
    return response.data;
  },

  updateSettings: async (data: Partial<SystemSettings>): Promise<SystemSettings> => {
    const response = await api.put<SystemSettings>('/system/settings', data);
    return response.data;
  },

  getPublicConfig: async (): Promise<PublicConfig> => {
    const response = await api.get<PublicConfig>('/system/public-config');
    return response.data;
  },

  getAppConfig: async (): Promise<AppConfig> => {
    const response = await api.get<AppConfig>('/system/app-config');
    return response.data;
  },

  getNotificationChannels: async (): Promise<string[]> => {
    const response = await api.get<string[]>('/system/notifications/channels');
    return response.data;
  }
};
