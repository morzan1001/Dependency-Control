import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { userApi } from '@/api/users';
import { UserCreate, UserUpdate, UserUpdateMe } from '@/types/user';

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

export const useCreateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: UserCreate) => userApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
    },
  });
};

export const useUpdateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UserUpdate }) => userApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
    },
  });
};

export const useUpdateMe = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: UserUpdateMe) => userApi.updateMe(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.me });
    },
  });
};

export const useDeleteUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => userApi.delete(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
      queryClient.invalidateQueries({ queryKey: userKeys.invitations });
    },
  });
};

export const useInviteUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (email: string) => userApi.invite(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
      queryClient.invalidateQueries({ queryKey: userKeys.invitations });
    },
  });
};

export const useAdminMigrateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => userApi.adminMigrateToLocal(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
    }
  });
};

export const useAdminResetPassword = () => {
  return useMutation({
    mutationFn: (userId: string) => userApi.adminResetPassword(userId),
  });
};

export const useAdminDisable2FA = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => userApi.adminDisable2FA(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() });
    }
  });
};
