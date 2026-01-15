import axios, { AxiosError, AxiosHeaders } from 'axios';
import { logger } from '@/lib/logger';

declare module 'axios' {
  export interface AxiosRequestConfig {
    _retry?: boolean;
  }

  export interface InternalAxiosRequestConfig {
    _retry?: boolean;
  }
}

// Standard API error response shape
export interface ApiErrorData {
  detail?: string;
  message?: string;
  code?: string;
}

// Type-safe API error
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
  headers: {
    'Content-Type': 'application/json',
  },
});

const refreshClient = axios.create({
  baseURL: getBaseUrl(),
  headers: {
    'Content-Type': 'application/json',
  },
});

let logoutCallback: (() => void) | null = null;

export const setLogoutCallback = (callback: () => void) => {
  logoutCallback = callback;
};

let refreshPromise: Promise<string | null> | null = null;

const refreshAccessToken = async () => {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    return null;
  }

  if (!refreshPromise) {
    refreshPromise = refreshClient
      .post('/login/refresh-token', { refresh_token: refreshToken })
      .then((response) => {
        const { access_token, refresh_token } = response.data as {
          access_token: string;
          refresh_token: string;
        };
        localStorage.setItem('token', access_token);
        localStorage.setItem('refresh_token', refresh_token);
        return access_token;
      })
      .catch((err) => {
        logger.error('Token refresh failed', err);
        return null;
      })
      .finally(() => {
        refreshPromise = null;
      });
  }

  return refreshPromise;
};

api.interceptors.request.use((config) => {
  // logger.debug(`Request: ${config.method?.toUpperCase()} ${config.url}`);
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
        const newAccessToken = await refreshAccessToken();
        if (newAccessToken) {
          const headers = AxiosHeaders.from(originalRequest.headers);
          headers.set('Authorization', `Bearer ${newAccessToken}`);
          originalRequest.headers = headers;
          return api(originalRequest);
        }
      }

      if (logoutCallback) {
        logoutCallback();
      }
    }
    return Promise.reject(error);
  }
);
