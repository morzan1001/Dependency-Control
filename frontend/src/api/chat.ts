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
  ): AsyncGenerator<ChatSSEEvent> {
    const token = localStorage.getItem('token');
    const response = await fetch(
      `${getBaseUrl()}/chat/conversations/${conversationId}/messages`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ content, images }),
      },
    );

    if (!response.ok) {
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        yield { type: 'error', message: `Rate limit exceeded. Try again in ${retryAfter}s.` };
        return;
      }
      const body = await response.json().catch(() => ({ detail: 'Unknown error' }));
      yield { type: 'error', message: body.detail || 'Request failed' };
      return;
    }

    const reader = response.body?.getReader();
    if (!reader) {
      yield { type: 'error', message: 'No response body' };
      return;
    }

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const event: ChatSSEEvent = JSON.parse(line.slice(6));
            yield event;
          } catch {
            // Skip malformed events
          }
        }
      }
    }
  },
};
