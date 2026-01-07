import axios, { AxiosError } from 'axios';
import { logger } from '@/lib/logger';

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

let logoutCallback: (() => void) | null = null;

export const setLogoutCallback = (callback: () => void) => {
  logoutCallback = callback;
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
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      if (logoutCallback) {
        logoutCallback();
      }
    }
    return Promise.reject(error);
  }
);
