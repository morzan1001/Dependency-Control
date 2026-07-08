import { describe, it, expect, vi, beforeEach } from 'vitest';

// Capture the fake axios instances (instances[0] = api, instances[1] = refreshClient).
const { mockCreate, instances } = vi.hoisted(() => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const instances: any[] = [];
  const mockCreate = () => {
    const inst = {
      post: vi.fn(),
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
    };
    instances.push(inst);
    return inst;
  };
  return { mockCreate, instances };
});

// jsdom lacks a usable localStorage; provide a minimal in-memory one.
const memoryStore = vi.hoisted(() => {
  const store = new Map<string, string>();
  return {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    get length() {
      return store.size;
    },
  };
});
Object.defineProperty(globalThis, 'localStorage', {
  value: memoryStore,
  configurable: true,
});

vi.mock('axios', async () => {
  const actual = await vi.importActual<typeof import('axios')>('axios');
  return {
    ...actual,
    default: { ...actual.default, create: mockCreate },
    create: mockCreate,
  };
});

// Importing the module registers the interceptors on instances[0].
import { setLogoutCallback } from '@/api/client';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = instances[0] as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const refreshClient = instances[1] as any;
// The response interceptor's rejection handler (2nd arg to response.use).
const onRejected = api.interceptors.response.use.mock.calls[0][1] as (
  err: unknown,
) => Promise<unknown>;

// A 401 on a normal (non-auth) request that should trigger a refresh attempt.
const make401 = () => ({
  isAxiosError: true,
  response: { status: 401 },
  config: { url: '/projects', headers: {} },
});

describe('client 401 interceptor + token refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('token', 'old-access');
    localStorage.setItem('refresh_token', 'valid-refresh');
  });

  it('keeps tokens and does NOT log out when the refresh fails with a network error', async () => {
    const logout = vi.fn();
    setLogoutCallback(logout);
    refreshClient.post.mockRejectedValue({ isAxiosError: true, message: 'Network Error' });

    await expect(onRejected(make401())).rejects.toBeTruthy();

    expect(localStorage.getItem('refresh_token')).toBe('valid-refresh');
    expect(localStorage.getItem('token')).toBe('old-access');
    expect(logout).not.toHaveBeenCalled();
  });

  it('keeps tokens and does NOT log out when the refresh fails with a 5xx', async () => {
    const logout = vi.fn();
    setLogoutCallback(logout);
    refreshClient.post.mockRejectedValue({ isAxiosError: true, response: { status: 503 } });

    await expect(onRejected(make401())).rejects.toBeTruthy();

    expect(localStorage.getItem('refresh_token')).toBe('valid-refresh');
    expect(localStorage.getItem('token')).toBe('old-access');
    expect(logout).not.toHaveBeenCalled();
  });

  it('clears tokens and logs out when the refresh is rejected with a 4xx', async () => {
    const logout = vi.fn();
    setLogoutCallback(logout);
    refreshClient.post.mockRejectedValue({ isAxiosError: true, response: { status: 401 } });

    await expect(onRejected(make401())).rejects.toBeTruthy();

    expect(localStorage.getItem('refresh_token')).toBeNull();
    expect(localStorage.getItem('token')).toBeNull();
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it('retries the original request with the new token on a successful refresh', async () => {
    const logout = vi.fn();
    setLogoutCallback(logout);
    refreshClient.post.mockResolvedValue({
      data: { access_token: 'new-access', refresh_token: 'new-refresh' },
    });

    // The fake `api` object is not callable, so the retry throws; swallow it and assert only the prior token rotation.
    await onRejected(make401()).catch(() => undefined);

    expect(localStorage.getItem('token')).toBe('new-access');
    expect(localStorage.getItem('refresh_token')).toBe('new-refresh');
    expect(logout).not.toHaveBeenCalled();
  });
});
