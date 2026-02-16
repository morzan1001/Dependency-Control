import { api } from '@/api/client';
import { Token } from '@/types/auth';
import { User, UserCreate, TwoFASetup } from '@/types/user';

export const authApi = {
  login: async (username: string, password: string, otp?: string): Promise<Token> => {
    const params = new URLSearchParams();
    params.append('username', username);
    params.append('password', password);
    params.append('grant_type', 'password');
    if (otp) {
      params.append('otp', otp);
    }

    const response = await api.post<Token>('/login/access-token', params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  },

  signup: async (data: UserCreate): Promise<User> => {
    const response = await api.post<User>('/signup', data);
    return response.data;
  },

  verifyEmail: async (token: string): Promise<{ message: string }> => {
    const response = await api.get<{ message: string }>(`/verify-email?token=${token}`);
    return response.data;
  },

  resendVerificationEmail: async (email: string): Promise<{ message: string }> => {
    const response = await api.post<{ message: string }>('/resend-verification', { email });
    return response.data;
  },

  resetPassword: async (token: string, newPassword: string): Promise<{ message: string }> => {
    const response = await api.post<{ message: string }>('/reset-password', { token, new_password: newPassword });
    return response.data;
  },

  validateInvitation: async (token: string): Promise<{ email: string }> => {
    const response = await api.get<{ email: string }>(`/invitations/system/${token}`);
    return response.data;
  },

  acceptInvitation: async (token: string, username: string, password: string): Promise<User> => {
    const response = await api.post<User>('/invitations/system/accept', { token, username, password });
    return response.data;
  },

  setup2FA: async (): Promise<TwoFASetup> => {
    const response = await api.post<TwoFASetup>('/users/me/2fa/setup');
    return response.data;
  },

  enable2FA: async (code: string, password: string): Promise<User> => {
    const response = await api.post<User>('/users/me/2fa/enable', { code, password });
    return response.data;
  },

  disable2FA: async (password: string): Promise<User> => {
    const response = await api.post<User>('/users/me/2fa/disable', { password });
    return response.data;
  },

  getMe: async (): Promise<User> => {
    const response = await api.get<User>('/users/me');
    return response.data;
  }
};
