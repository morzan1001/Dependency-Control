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
    onError: (error: any) => {
       toast.error("Failed to send broadcast", {
        description: error.response?.data?.detail || "An unexpected error occurred."
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
