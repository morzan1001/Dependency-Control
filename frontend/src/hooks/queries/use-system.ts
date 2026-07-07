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

// Full system settings; requires 'system:manage' permission.
export const useSystemSettings = () => {
  return useQuery({
    queryKey: systemKeys.settings(),
    queryFn: systemApi.getSettings,
    staleTime: 5 * 60 * 1000,
  });
};

export const useUpdateSystemSettings = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<SystemSettings>) => systemApi.updateSettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: systemKeys.settings() });
      // App config derives from these settings, so refresh it too.
      queryClient.invalidateQueries({ queryKey: systemKeys.appConfig() });
    },
  });
};

interface UseAppConfigOptions {
  enabled?: boolean;
}

// Lightweight, non-secret app config for authenticated users.
export const useAppConfig = (options: UseAppConfigOptions = {}) => {
  const { enabled = true } = options;
  return useQuery({
    queryKey: systemKeys.appConfig(),
    queryFn: systemApi.getAppConfig,
    staleTime: 5 * 60 * 1000,
    enabled,
  });
};

export const usePublicConfig = () => {
  return useQuery({
    queryKey: systemKeys.publicConfig(),
    queryFn: systemApi.getPublicConfig,
    staleTime: 10 * 60 * 1000, // rarely changes
  });
};

export const useNotificationChannels = () => {
  return useQuery({
    queryKey: systemKeys.notificationChannels(),
    queryFn: systemApi.getNotificationChannels,
    staleTime: 5 * 60 * 1000,
  });
};
