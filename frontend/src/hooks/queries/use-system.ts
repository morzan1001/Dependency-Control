import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { systemApi } from '@/api/system';
import { SystemSettings } from '@/types/system';

export const systemKeys = {
  all: ['system'] as const,
  settings: () => [...systemKeys.all, 'settings'] as const,
  appConfig: () => [...systemKeys.all, 'appConfig'] as const,
  publicConfig: () => [...systemKeys.all, 'publicConfig'] as const,
  notificationChannels: () => [...systemKeys.all, 'notificationChannels'] as const,
};

/**
 * Full system settings - only for the admin settings page.
 * Requires 'system:manage' permission.
 */
export const useSystemSettings = () => {
  return useQuery({
    queryKey: systemKeys.settings(),
    queryFn: systemApi.getSettings,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

export const useUpdateSystemSettings = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<SystemSettings>) => systemApi.updateSettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: systemKeys.settings() });
      // Also invalidate app config since some values might have changed
      queryClient.invalidateQueries({ queryKey: systemKeys.appConfig() });
    },
  });
};

interface UseAppConfigOptions {
  /** Set to false to disable the query until needed (e.g., dialog is open) */
  enabled?: boolean;
}

/**
 * Lightweight app configuration for authenticated users.
 * Use this for components that only need config data (limits, retention, etc.).
 * Does NOT expose secrets like API keys or passwords.
 * 
 * @param options.enabled - Set to false to defer loading until needed (default: true)
 */
export const useAppConfig = (options: UseAppConfigOptions = {}) => {
  const { enabled = true } = options;
  return useQuery({
    queryKey: systemKeys.appConfig(),
    queryFn: systemApi.getAppConfig,
    staleTime: 5 * 60 * 1000, // 5 minutes
    enabled,
  });
};

export const usePublicConfig = () => {
  return useQuery({
    queryKey: systemKeys.publicConfig(),
    queryFn: systemApi.getPublicConfig,
    staleTime: 10 * 60 * 1000, // 10 minutes - rarely changes
  });
};

export const useNotificationChannels = () => {
  return useQuery({
    queryKey: systemKeys.notificationChannels(),
    queryFn: systemApi.getNotificationChannels,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};
