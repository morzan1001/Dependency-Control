import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ChatSSEEvent } from '@/types/chat';

// Mock the client module to assert chat.ts delegates to the shared refreshAccessToken.
const clientMocks = vi.hoisted(() => ({
  getBaseUrl: vi.fn(() => '/api/v1'),
  refreshAccessToken: vi.fn<() => Promise<string | null>>(),
  api: {
    post: vi.fn(),
    get: vi.fn(),
    delete: vi.fn(),
  },
}));

vi.mock('@/api/client', () => clientMocks);

import { chatApi } from '@/api/chat';

// Minimal in-memory localStorage (jsdom in this harness lacks a usable one).
const memoryStore = (() => {
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
})();
Object.defineProperty(globalThis, 'localStorage', {
  value: memoryStore,
  configurable: true,
});

function sseResponse(events: ChatSSEEvent[]): Response {
  const encoder = new TextEncoder();
  const payload = events.map((e) => `data: ${JSON.stringify(e)}\n`).join('');
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(payload));
      controller.close();
    },
  });
  return new Response(body, { status: 200 });
}

async function drain(gen: AsyncGenerator<ChatSSEEvent>): Promise<ChatSSEEvent[]> {
  const out: ChatSSEEvent[] = [];
  for await (const ev of gen) out.push(ev);
  return out;
}

describe('chatApi.sendMessage token refresh (delegates to shared client helper)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('token', 'old-access');
    localStorage.setItem('refresh_token', 'valid-refresh');
    clientMocks.getBaseUrl.mockReturnValue('/api/v1');
  });

  it('on a 401 it calls the SHARED refreshAccessToken and retries with the new token', async () => {
    const fetchMock = vi.fn();
    fetchMock
      .mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
      .mockResolvedValueOnce(sseResponse([{ type: 'done' } as ChatSSEEvent]));
    vi.stubGlobal('fetch', fetchMock);

    clientMocks.refreshAccessToken.mockResolvedValue('new-access');

    const events = await drain(chatApi.sendMessage('conv-1', 'hi'));

    expect(clientMocks.refreshAccessToken).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(events).toEqual([{ type: 'done' }]);

    vi.unstubAllGlobals();
  });

  it('yields an error event and does not retry when the shared refresh returns null', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: 'Unauthorized' }), { status: 401 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    clientMocks.refreshAccessToken.mockResolvedValue(null);

    const events = await drain(chatApi.sendMessage('conv-1', 'hi'));

    expect(clientMocks.refreshAccessToken).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(events).toEqual([{ type: 'error', message: 'Unauthorized' }]);

    vi.unstubAllGlobals();
  });

  it('does not throw when the shared refresh rejects (transient failure); yields error', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: 'Unauthorized' }), { status: 401 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    clientMocks.refreshAccessToken.mockRejectedValue(new Error('Network Error'));

    const events = await drain(chatApi.sendMessage('conv-1', 'hi'));

    expect(clientMocks.refreshAccessToken).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(events).toEqual([{ type: 'error', message: 'Unauthorized' }]);

    vi.unstubAllGlobals();
  });

  it('builds the messages URL from the shared getBaseUrl', async () => {
    const fetchMock = vi.fn().mockResolvedValue(sseResponse([{ type: 'done' } as ChatSSEEvent]));
    vi.stubGlobal('fetch', fetchMock);
    clientMocks.getBaseUrl.mockReturnValue('https://example.test/api');

    await drain(chatApi.sendMessage('conv-42', 'hello'));

    expect(clientMocks.getBaseUrl).toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://example.test/api/chat/conversations/conv-42/messages',
      expect.objectContaining({ method: 'POST' }),
    );

    vi.unstubAllGlobals();
  });
});
