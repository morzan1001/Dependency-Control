import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { systemApi } from '@/api/system';
import { SystemSettings } from '@/types/system';

export const systemKeys = {
  settings: ['systemSettings'] as const,
};

export const useSystemSettings = () => {
  return useQuery({
    queryKey: systemKeys.settings,
    queryFn: systemApi.getSettings,
  });
};

export const useUpdateSystemSettings = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<SystemSettings>) => systemApi.updateSettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: systemKeys.settings });
    },
  });
};
export const usePublicConfig = () => {
  return useQuery({
    queryKey: ['publicConfig'],
    queryFn: systemApi.getPublicConfig,
  });
};

export const useNotificationChannels = () => {
  return useQuery({
    queryKey: ['notificationChannels'],
    queryFn: systemApi.getNotificationChannels,
  });
};
