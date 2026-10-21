import { useQuery, useMutation, useQueryClient, type MutationMeta } from '@tanstack/react-query';
import { userApi } from '@/api/users';
import type { ApiError } from '@/api/client';
import { UserUpdate, UserUpdateMe } from '@/types/user';
import { getErrorMessage } from '@/lib/utils';

// A save that carries a new name is refused with 400 when the name is taken and 422 when it breaks the rule.
export const refusesUsername = (sent: UserUpdate | UserUpdateMe | undefined, error: unknown) => {
  const status = (error as ApiError).response?.status;
  return sent?.username !== undefined && (status === 400 || status === 422);
};

// Email refusals: 400 taken, already this account's or already a member's; 404 no user verified it; 422 malformed; 501 no mail server to confirm it.
export const refusesEmail = (error: unknown) => {
  const status = (error as ApiError).response?.status;
  return status === 400 || status === 404 || status === 422 || status === 501;
};

export const usernameRefusalMessage = (
  mutation: { isError: boolean; error: unknown },
  sent: UserUpdate | UserUpdateMe | undefined,
) => (mutation.isError && refusesUsername(sent, mutation.error) ? getErrorMessage(mutation.error, { withField: false }) : null);

export const emailRefusalMessage = (mutation: { isError: boolean; error: unknown }) =>
  mutation.isError && refusesEmail(mutation.error) ? getErrorMessage(mutation.error, { withField: false }) : null;

export const userKeys = {
  all: ['users'] as const,
  lists: () => [...userKeys.all, 'list'] as const,
  list: (filters: Record<string, unknown>) => [...userKeys.lists(), filters] as const,
  me: ['me'] as const,
  invitations: ['invitations'] as const,
};

export const useUsers = (
  skip: number = 0, 
  limit: number = 20, 
  search: string = '', 
  sortBy: string = 'username', 
  sortOrder: string = 'asc'
) => {
  return useQuery({
    queryKey: userKeys.list({ skip, limit, search, sortBy, sortOrder }),
    queryFn: () => userApi.getAll(skip, limit, search, sortBy, sortOrder),
  });
};

export const useCurrentUser = () => {
  return useQuery({
    queryKey: userKeys.me,
    queryFn: userApi.getMe,
    staleTime: 5 * 60 * 1000,
  });
};

export const usePendingInvitations = () => {
  return useQuery({
    queryKey: userKeys.invitations,
    queryFn: userApi.getPendingInvitations,
  });
};

export const useUpdateUser = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: ({ id, data }: { id: string; data: UserUpdate }) => userApi.update(id, data),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: userKeys.lists() }),
        queryClient.invalidateQueries({ queryKey: userKeys.me }),
      ]),
  });
};

export const useUpdateMe = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (data: UserUpdateMe) => userApi.updateMe(data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: userKeys.me }),
  });
};

export const useDeleteUser = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (userId: string) => userApi.delete(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
    },
  });
};

export const useRevokeInvitation = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (invitationId: string) => userApi.revokeInvitation(invitationId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.invitations });
    },
  });
};

export const useInviteUser = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (email: string) => userApi.invite(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
      queryClient.invalidateQueries({ queryKey: userKeys.invitations });
    },
  });
};

export const useAdminMigrateUser = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (userId: string) => userApi.adminMigrateToLocal(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
    }
  });
};

export const useAdminResetPassword = (meta?: MutationMeta) => {
  return useMutation({
    meta,
    mutationFn: (userId: string) => userApi.adminResetPassword(userId),
  });
};

export const useAdminDisable2FA = (meta?: MutationMeta) => {
  const queryClient = useQueryClient();
  return useMutation({
    meta,
    mutationFn: (userId: string) => userApi.adminDisable2FA(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
    }
  });
};
