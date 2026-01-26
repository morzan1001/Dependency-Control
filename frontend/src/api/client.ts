import axios, { AxiosError, AxiosHeaders } from 'axios';
import { logger } from '@/lib/logger';
import { API_TIMEOUT_MS, API_REFRESH_TIMEOUT_MS } from '@/lib/constants';

declare module 'axios' {
  export interface AxiosRequestConfig {
    _retry?: boolean;
  }

  export interface InternalAxiosRequestConfig {
    _retry?: boolean;
  }
}

export interface ApiErrorData {
  detail?: string;
  message?: string;
  code?: string;
}

export type ApiError = AxiosError<ApiErrorData>;

interface RuntimeConfig {
  VITE_API_URL?: string;
}

declare global {
  interface Window {
    __RUNTIME_CONFIG__?: RuntimeConfig;
  }
}

const getBaseUrl = () => {
  if (window.__RUNTIME_CONFIG__?.VITE_API_URL) {
    return window.__RUNTIME_CONFIG__.VITE_API_URL;
  }
  return import.meta.env.VITE_API_URL || '/api/v1';
};

export const api = axios.create({
  baseURL: getBaseUrl(),
  timeout: API_TIMEOUT_MS,
  headers: {
    'Content-Type': 'application/json',
  },
});

const refreshClient = axios.create({
  baseURL: getBaseUrl(),
  timeout: API_REFRESH_TIMEOUT_MS,
  headers: {
    'Content-Type': 'application/json',
  },
});

let logoutCallback: (() => void) | null = null;

export const setLogoutCallback = (callback: () => void) => {
  logoutCallback = callback;
};

let refreshPromise: Promise<string | null> | null = null;
let isRefreshing = false;

const refreshAccessToken = async (): Promise<string | null> => {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    return null;
  }

  if (refreshPromise) {
    return refreshPromise;
  }

  isRefreshing = true;

  refreshPromise = refreshClient
    .post('/login/refresh-token', { refresh_token: refreshToken })
    .then((response) => {
      const data = response.data;
      if (!data || typeof data.access_token !== 'string' || typeof data.refresh_token !== 'string') {
        throw new Error('Invalid token response structure');
      }
      const { access_token, refresh_token } = data as {
        access_token: string;
        refresh_token: string;
      };
      localStorage.setItem('token', access_token);
      localStorage.setItem('refresh_token', refresh_token);
      return access_token;
    })
    .catch((err) => {
      logger.error('Token refresh failed', err instanceof Error ? err.message : 'Unknown error');
      localStorage.removeItem('token');
      localStorage.removeItem('refresh_token');
      return null;
    })
    .finally(() => {
      refreshPromise = null;
      isRefreshing = false;
    });

  return refreshPromise;
};

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  logger.error('Request Error:', error);
  return Promise.reject(error);
});

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && originalRequest) {
      const requestUrl = originalRequest.url || '';
      const isAuthEndpoint =
        requestUrl.includes('/login/access-token') ||
        requestUrl.includes('/login/refresh-token');

      if (!originalRequest._retry && !isAuthEndpoint) {
        originalRequest._retry = true;

        try {
          const newAccessToken = await refreshAccessToken();
          if (newAccessToken) {
            const headers = AxiosHeaders.from(originalRequest.headers);
            headers.set('Authorization', `Bearer ${newAccessToken}`);
            originalRequest.headers = headers;
            return api(originalRequest);
          }
        } catch {
          // Refresh failed
        }
      }

      if (logoutCallback && !isRefreshing) {
        logoutCallback();
      }
    }
    return Promise.reject(error);
  }
);
