import { useMutation, useQuery } from '@tanstack/react-query';
import { broadcastApi } from '@/api/broadcast';
import { BroadcastRequest } from '@/types/broadcast';
import { toast } from 'sonner';
import { getErrorMessage } from '@/lib/utils';

export const broadcastKeys = {
  all: ['broadcast'] as const,
  history: () => [...broadcastKeys.all, 'history'] as const,
  suggestions: (query: string) => [...broadcastKeys.all, 'suggestions', query] as const,
};

export const useBroadcast = () => {
  return useMutation({
    mutationFn: (data: BroadcastRequest) => broadcastApi.send(data),
    onSuccess: (data) => {
      if (data.project_count !== undefined && data.project_count > 0) {
        toast.success(`Broadcast sent successfully`, {
          description: `Notified members of ${data.project_count} projects.`
        });
      } else if (!data.unique_user_count) {
        // If not dry run and normal global msg
         toast.success(`Broadcast sent successfully`, {
          description: `Notified recipients.`
        });
      }
    },
    onError: (error) => {
       toast.error("Failed to send broadcast", {
        description: getErrorMessage(error)
       })
    }
  });
};

export const useBroadcastHistory = () => {
  return useQuery({
    queryKey: broadcastKeys.history(),
    queryFn: () => broadcastApi.getHistory()
  });
};

export const usePackageSuggestions = (q: string) => {
  return useQuery({
    queryKey: broadcastKeys.suggestions(q),
    queryFn: () => broadcastApi.suggestPackages(q),
    enabled: q.length >= 2,
    staleTime: 60 * 1000,
  });
};
