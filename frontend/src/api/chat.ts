import { api } from '@/api/client';
import type {
  Conversation,
  ConversationDetailResponse,
  ConversationListResponse,
  ChatSSEEvent,
} from '@/types/chat';

const getBaseUrl = () => {
  if (window.__RUNTIME_CONFIG__?.VITE_API_URL) {
    return window.__RUNTIME_CONFIG__.VITE_API_URL;
  }
  return import.meta.env.VITE_API_URL || '/api/v1';
};

/**
 * Attempts to refresh the access token by calling the refresh endpoint.
 * Returns true if a new token was obtained and stored in localStorage, false otherwise.
 */
async function tryRefreshToken(): Promise<boolean> {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) return false;

  try {
    const response = await fetch(`${getBaseUrl()}/login/refresh-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      localStorage.removeItem('token');
      localStorage.removeItem('refresh_token');
      return false;
    }

    const data = await response.json();
    if (
      !data ||
      typeof data.access_token !== 'string' ||
      typeof data.refresh_token !== 'string'
    ) {
      localStorage.removeItem('token');
      localStorage.removeItem('refresh_token');
      return false;
    }

    localStorage.setItem('token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

/**
 * Tries to parse a single SSE data line into a ChatSSEEvent.
 * Returns the event on success, or null if the line is not a data line or is malformed.
 */
function parseSseLine(line: string): ChatSSEEvent | null {
  if (!line.startsWith('data: ')) return null;
  try {
    return JSON.parse(line.slice(6)) as ChatSSEEvent;
  } catch {
    return null;
  }
}

/**
 * Reads the SSE stream from a Response and yields ChatSSEEvents.
 */
async function* readSseStream(
  response: Response,
  signal?: AbortSignal,
): AsyncGenerator<ChatSSEEvent> {
  const reader = response.body?.getReader();
  if (!reader) {
    yield { type: 'error', message: 'No response body' };
    return;
  }

  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    if (signal?.aborted) {
      reader.cancel();
      break;
    }

    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      const event = parseSseLine(line);
      if (event) yield event;
    }
  }
}

/**
 * Resolves the error event to yield for a non-ok response.
 */
async function resolveErrorEvent(response: Response): Promise<ChatSSEEvent> {
  if (response.status === 429) {
    const retryAfter = response.headers.get('Retry-After');
    return { type: 'error', message: `Rate limit exceeded. Try again in ${retryAfter}s.` };
  }
  const body = await response.json().catch(() => ({ detail: 'Unknown error' }));
  return { type: 'error', message: (body as { detail?: string }).detail || 'Request failed' };
}

/**
 * Performs the raw fetch for sendMessage, reading the current token from localStorage.
 */
function performSendMessageFetch(
  conversationId: string,
  content: string,
  images: string[],
  signal?: AbortSignal,
): Promise<Response> {
  const token = localStorage.getItem('token');
  return fetch(`${getBaseUrl()}/chat/conversations/${conversationId}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ content, images }),
    signal,
  });
}

export const chatApi = {
  createConversation: async (title?: string): Promise<Conversation> => {
    const response = await api.post<Conversation>('/chat/conversations', { title });
    return response.data;
  },

  listConversations: async (): Promise<ConversationListResponse> => {
    const response = await api.get<ConversationListResponse>('/chat/conversations');
    return response.data;
  },

  getConversation: async (id: string): Promise<ConversationDetailResponse> => {
    const response = await api.get<ConversationDetailResponse>(`/chat/conversations/${id}`);
    return response.data;
  },

  deleteConversation: async (id: string): Promise<void> => {
    await api.delete(`/chat/conversations/${id}`);
  },

  sendMessage: async function* (
    conversationId: string,
    content: string,
    images: string[] = [],
    signal?: AbortSignal,
  ): AsyncGenerator<ChatSSEEvent> {
    let response = await performSendMessageFetch(conversationId, content, images, signal);

    if (response.status === 401) {
      // Try to refresh token and retry once
      const refreshed = await tryRefreshToken();
      if (refreshed) {
        response = await performSendMessageFetch(conversationId, content, images, signal);
      }
    }

    if (!response.ok) {
      yield await resolveErrorEvent(response);
      return;
    }

    yield* readSseStream(response, signal);
  },
};
