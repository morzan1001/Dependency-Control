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
    // No success toast: the caller toasts real sends; dry runs must not claim a send happened.
    onError: (error, variables) => {
      // Only dry runs report errors here; real sends toast their own errors.
      if (variables.dry_run) {
        toast.error("Failed to calculate impact", {
          description: getErrorMessage(error)
        });
      }
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
