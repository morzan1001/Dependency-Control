import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ChatSSEEvent, ConversationDetailResponse, Message } from '@/types/chat';

import Chat from '../Chat';

const { chatApi } = vi.hoisted(() => ({
  chatApi: {
    createConversation: vi.fn(),
    listConversations: vi.fn(),
    getConversation: vi.fn(),
    deleteConversation: vi.fn(),
    sendMessage: vi.fn(),
  },
}));
vi.mock('@/api/chat', () => ({ chatApi }));

vi.mock('@/context', () => ({
  useAuth: () => ({ hasPermission: () => true }),
}));

const conversation = {
  id: 'c1',
  user_id: 'u1',
  title: 'Risk talk',
  created_at: '2026-10-08T10:00:00Z',
  updated_at: '2026-10-08T10:00:00Z',
  message_count: 2,
};

const message = (id: string, role: 'user' | 'assistant', content: string): Message => ({
  id,
  conversation_id: 'c1',
  role,
  content,
  tool_calls: [],
  created_at: '2026-10-08T10:00:00Z',
});

const firstTurn = [
  message('m1', 'user', 'first question'),
  message('m2', 'assistant', 'first answer'),
];

const detail = (...messages: Message[]): ConversationDetailResponse => ({ conversation, messages });

function streamOf(...events: ChatSSEEvent[]) {
  return async function* () {
    for (const event of events) yield event;
  };
}

async function openConversationAndAsk(question: string) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <Chat />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByRole('button', { name: /History/ }));
  fireEvent.click(await screen.findByText('Risk talk'));
  await screen.findByText('first answer');

  fireEvent.change(screen.getByPlaceholderText('Ask about your security data…'), {
    target: { value: question },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
}

describe('Chat turn after the stream ends', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    Element.prototype.scrollIntoView = vi.fn();
    chatApi.listConversations.mockResolvedValue({ conversations: [conversation], total: 1 });
  });

  it('keeps a finished follow-up on screen until the refetched conversation holds it', async () => {
    let deliverRefetch!: (value: ConversationDetailResponse) => void;
    chatApi.getConversation
      .mockResolvedValueOnce(detail(...firstTurn))
      .mockReturnValueOnce(new Promise((resolve) => (deliverRefetch = resolve)));
    chatApi.sendMessage.mockImplementationOnce(
      streamOf({ type: 'token', content: 'second answer' }, { type: 'done' }),
    );

    await openConversationAndAsk('second question');
    await waitFor(() => expect(chatApi.getConversation).toHaveBeenCalledTimes(2));
    await act(() => new Promise((resolve) => setTimeout(resolve, 50)));

    expect(screen.getByText('second question')).toBeInTheDocument();
    expect(screen.getByText('second answer')).toBeInTheDocument();

    await act(async () => {
      deliverRefetch(
        detail(
          ...firstTurn,
          message('m3', 'user', 'second question'),
          message('m4', 'assistant', 'second answer'),
        ),
      );
    });

    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /Stop generating/ })).not.toBeInTheDocument(),
    );
    expect(screen.getAllByText('second question')).toHaveLength(1);
    expect(screen.getAllByText('second answer')).toHaveLength(1);
  });

  it('refetches after an error event and shows the stored turn', async () => {
    chatApi.getConversation
      .mockResolvedValueOnce(detail(...firstTurn))
      .mockResolvedValueOnce(
        detail(
          ...firstTurn,
          message('m3', 'user', 'second question'),
          message('m4', 'assistant', 'partial answer\n\n_[stream interrupted]_'),
        ),
      );
    chatApi.sendMessage.mockImplementationOnce(
      streamOf(
        { type: 'token', content: 'partial answer' },
        { type: 'error', message: 'model crashed' },
      ),
    );

    await openConversationAndAsk('second question');

    expect(await screen.findByText('[stream interrupted]')).toBeInTheDocument();
    expect(chatApi.getConversation).toHaveBeenCalledTimes(2);
    expect(screen.getByText('second question')).toBeInTheDocument();
    expect(screen.getByText('model crashed')).toBeInTheDocument();
  });

  it('refetches after Stop and shows the stored turn', async () => {
    chatApi.getConversation
      .mockResolvedValueOnce(detail(...firstTurn))
      .mockResolvedValueOnce(
        detail(
          ...firstTurn,
          message('m3', 'user', 'second question'),
          message('m4', 'assistant', 'partial answer\n\n_[stream interrupted]_'),
        ),
      );
    chatApi.sendMessage.mockImplementationOnce(async function* (
      _id: string,
      _content: string,
      signal: AbortSignal,
    ) {
      yield { type: 'token', content: 'partial answer' };
      await new Promise((_resolve, reject) =>
        signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError'))),
      );
    });

    await openConversationAndAsk('second question');
    fireEvent.click(await screen.findByRole('button', { name: /Stop generating/ }));

    expect(await screen.findByText('[stream interrupted]')).toBeInTheDocument();
    expect(chatApi.getConversation).toHaveBeenCalledTimes(2);
    expect(screen.getByText('second question')).toBeInTheDocument();
  });
});
