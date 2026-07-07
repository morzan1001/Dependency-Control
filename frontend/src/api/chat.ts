import { api, getBaseUrl, refreshAccessToken } from '@/api/client';
import type {
  Conversation,
  ConversationDetailResponse,
  ConversationListResponse,
  ChatSSEEvent,
} from '@/types/chat';

function parseSseLine(line: string): ChatSSEEvent | null {
  if (!line.startsWith('data: ')) return null;
  try {
    return JSON.parse(line.slice(6)) as ChatSSEEvent;
  } catch {
    return null;
  }
}

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

async function resolveErrorEvent(response: Response): Promise<ChatSSEEvent> {
  if (response.status === 429) {
    const retryAfter = response.headers.get('Retry-After');
    return { type: 'error', message: `Rate limit exceeded. Try again in ${retryAfter}s.` };
  }
  const body = await response.json().catch(() => ({ detail: 'Unknown error' }));
  return { type: 'error', message: (body as { detail?: string }).detail || 'Request failed' };
}

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
      let newToken: string | null = null;
      try {
        newToken = await refreshAccessToken();
      } catch {
        // Transient refresh failure: keep tokens, fall through to error handling.
      }
      if (newToken) {
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
