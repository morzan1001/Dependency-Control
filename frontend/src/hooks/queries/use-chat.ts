import { useMutation, useQuery, useQueryClient, type MutationMeta } from '@tanstack/react-query';
import { chatApi } from '@/api/chat';

export const chatKeys = {
  all: ['chat'] as const,
  conversations: () => [...chatKeys.all, 'conversations'] as const,
  conversation: (id: string) => [...chatKeys.all, 'conversation', id] as const,
};

export function useConversations() {
  return useQuery({
    queryKey: chatKeys.conversations(),
    queryFn: chatApi.listConversations,
    staleTime: 30_000,
  });
}

export function useConversation(id: string | null) {
  return useQuery({
    queryKey: chatKeys.conversation(id || ''),
    queryFn: () => chatApi.getConversation(id!),
    enabled: !!id,
  });
}

export function useCreateConversation(meta?: MutationMeta) {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (title?: string) => chatApi.createConversation(title),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: chatKeys.conversations() });
    },
  });
}

export function useDeleteConversation(meta?: MutationMeta) {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (id: string) => chatApi.deleteConversation(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: chatKeys.conversations() });
    },
  });
}
