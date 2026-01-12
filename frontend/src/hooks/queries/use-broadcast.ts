import { useMutation, useQuery } from '@tanstack/react-query';
import { broadcastApi } from '@/api/broadcast';
import { BroadcastRequest } from '@/types/broadcast';
import { toast } from 'sonner';

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
       const err = error as { response?: { data?: { detail?: string } } };
       toast.error("Failed to send broadcast", {
        description: err.response?.data?.detail || "An unexpected error occurred."
       })
    }
  });
};

export const useBroadcastHistory = () => {
  return useQuery({
    queryKey: ['broadcast-history'],
    queryFn: () => broadcastApi.getHistory()
  });
};
export const usePackageSuggestions = (q: string) => {
  return useQuery({
    queryKey: ['packageSuggestions', q],
    queryFn: () => broadcastApi.suggestPackages(q),
    enabled: q.length >= 2,
    staleTime: 60 * 1000,
  });
};
