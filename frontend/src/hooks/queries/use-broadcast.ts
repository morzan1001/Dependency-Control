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
    // Success is intentionally not toasted here: dry-run impact previews must
    // not claim a broadcast was sent, and real sends are already toasted by the
    // caller (Broadcasts.tsx). Toasting here would falsely report dry runs and
    // double-toast real sends.
    onError: (error, variables) => {
      // Real sends surface their own error toast in Broadcasts.tsx; only dry-run
      // impact calculations delegate error reporting to this hook.
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
