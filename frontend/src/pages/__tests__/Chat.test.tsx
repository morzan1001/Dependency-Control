import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { toast } from 'sonner';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { createMutationCache } from '@/lib/mutation-cache';

import Chat from '../Chat';

// jsdom has no scrollIntoView; Chat auto-scrolls to the messages end anchor.
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});

vi.mock('sonner', () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

const { chatApi, history } = vi.hoisted(() => ({
  chatApi: {
    createConversation: vi.fn(),
    listConversations: vi.fn(),
    getConversation: vi.fn(),
    deleteConversation: vi.fn(),
  },
  history: { granted: false },
}));
vi.mock('@/api/chat', () => ({ chatApi }));

vi.mock('@/context', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isLoading: false,
    permissions: [],
    hasPermission: () => history.granted,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

const sendMessage = vi.fn();
vi.mock('@/hooks/useChatStream', () => ({
  useChatStream: () => ({
    sendMessage,
    abort: vi.fn(),
    streamingContent: '',
    streamingToolCalls: [],
    pendingUserMessage: null,
    isStreaming: false,
    activeToolCall: null,
    error: null,
  }),
}));

const RISK_TALK = {
  id: 'conv-1',
  user_id: 'u1',
  title: 'Risk talk',
  created_at: '2026-10-08T10:00:00Z',
  updated_at: '2026-10-08T10:00:00Z',
  message_count: 0,
};

function renderChat() {
  const qc = new QueryClient({ mutationCache: createMutationCache(), defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Chat />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  history.granted = false;
  chatApi.listConversations.mockResolvedValue({ conversations: [RISK_TALK], total: 1 });
  chatApi.getConversation.mockResolvedValue({ conversation: RISK_TALK, messages: [] });
});

describe('Chat error handling', () => {
  it('surfaces a toast (and does not send) when creating a conversation fails on first message', async () => {
    chatApi.createConversation.mockRejectedValueOnce(new Error('backend down'));

    renderChat();

    // Clicking a suggested prompt with no active conversation triggers createConversation, which rejects.
    const prompt = screen.getByText('Critical vulnerabilities');
    fireEvent.click(prompt);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Failed to send message', { description: 'backend down' });
    });
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('New chat clears the active conversation without creating an empty one', async () => {
    chatApi.createConversation.mockResolvedValueOnce(RISK_TALK);

    renderChat();

    fireEvent.click(screen.getByText('Risk overview'));
    await screen.findByRole('heading', { name: 'Risk talk' });

    fireEvent.click(screen.getByRole('button', { name: /New chat/i }));

    await screen.findByRole('heading', { name: 'Chat' });
    expect(chatApi.createConversation).toHaveBeenCalledTimes(1);
  });

  it('sends the message and does not toast when create succeeds', async () => {
    chatApi.createConversation.mockResolvedValueOnce(RISK_TALK);

    renderChat();

    fireEvent.click(screen.getByText('Risk overview'));

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith(
        'Give me a short summary of my overall security posture.',
        'conv-1',
      );
    });
    expect(toast.error).not.toHaveBeenCalled();
  });
});

describe('Chat history deletion', () => {
  beforeEach(() => {
    history.granted = true;
  });

  it('closes a conversation once it is deleted while open', async () => {
    chatApi.deleteConversation.mockResolvedValueOnce(undefined);
    renderChat();
    fireEvent.click(await screen.findByRole('button', { name: /History/ }));
    fireEvent.click(await screen.findByText('Risk talk'));
    await screen.findByRole('heading', { name: 'Risk talk' });

    fireEvent.click(screen.getByRole('button', { name: /History/ }));
    fireEvent.click(await screen.findByRole('button', { name: 'Delete conversation' }));
    await waitFor(() => expect(chatApi.deleteConversation).toHaveBeenCalledWith('conv-1'));
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));

    expect(await screen.findByRole('heading', { name: 'Chat' })).toBeInTheDocument();
  });

  it('names a deletion that failed and why', async () => {
    chatApi.deleteConversation.mockRejectedValueOnce(new Error('Network Error'));
    renderChat();
    fireEvent.click(await screen.findByRole('button', { name: /History/ }));

    fireEvent.click(await screen.findByRole('button', { name: 'Delete conversation' }));

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Failed to delete conversation', { description: 'Network Error' });
    });
  });
});
