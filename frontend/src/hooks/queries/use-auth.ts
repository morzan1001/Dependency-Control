import { useMutation } from '@tanstack/react-query';
import { authApi } from '@/api/auth';

// The 2FA endpoints refuse a wrong code or password with these details; every other refusal belongs to no field.
export const INVALID_OTP_CODE = 'Invalid OTP code';
export const INVALID_PASSWORD = 'Invalid password';

export const useLogin = () => {
  return useMutation({
    mutationFn: ({ username, password, otp }: { username: string; password: string; otp?: string }) => 
      authApi.login(username, password, otp),
  });
};

export const useSignup = () => {
    return useMutation({
        mutationFn: authApi.signup
    })
}

export const useResetPassword = () => {
    return useMutation({
        mutationFn: ({ token, newPassword }: { token: string; newPassword: string }) => 
            authApi.resetPassword(token, newPassword)
    })
}

export const useValidateInvitation = () => {
    return useMutation({
        mutationFn: authApi.validateInvitation
    })
}

export const useAcceptInvitation = () => {
    return useMutation({
        mutationFn: ({ token, username, password }: { token: string; username: string; password: string }) =>
            authApi.acceptInvitation(token, username, password)
    })
}

export const useSetup2FA = () => {
    return useMutation({
        mutationFn: authApi.setup2FA
    })
}

export const useEnable2FA = () => {
    return useMutation({
        mutationFn: ({ code, password }: { code: string; password: string }) =>
            authApi.enable2FA(code, password)
    })
}
