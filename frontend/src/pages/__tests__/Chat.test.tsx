import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import Chat from '../Chat';

// jsdom has no scrollIntoView; Chat auto-scrolls to the messages end anchor.
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});

// --- toast (sonner) --------------------------------------------------------
vi.mock('sonner', () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

// --- auth ------------------------------------------------------------------
vi.mock('@/context', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isLoading: false,
    permissions: [],
    hasPermission: () => false,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

// --- chat stream -----------------------------------------------------------
const sendMessage = vi.fn();
vi.mock('@/hooks/useChatStream', () => ({
  useChatStream: () => ({
    sendMessage,
    abort: vi.fn(),
    streamingContent: '',
    streamingToolCalls: [],
    streamingInfo: null,
    pendingUserMessage: null,
    clearPendingUserMessage: vi.fn(),
    isStreaming: false,
    activeToolCall: null,
    error: null,
  }),
}));

// --- chat queries ----------------------------------------------------------
const createMutateAsync = vi.fn();
const deleteMutateAsync = vi.fn();
vi.mock('@/hooks/queries/use-chat', () => ({
  useConversations: () => ({ data: { conversations: [] } }),
  useConversation: () => ({ data: undefined, refetch: vi.fn() }),
  useCreateConversation: () => ({ mutateAsync: createMutateAsync }),
  useDeleteConversation: () => ({ mutateAsync: deleteMutateAsync }),
}));

function renderChat() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Chat />
    </QueryClientProvider>,
  );
}

describe('Chat error handling', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
  });

  it('surfaces a toast (and does not send) when creating a conversation fails on first message', async () => {
    const { toast } = await import('sonner');
    createMutateAsync.mockRejectedValueOnce(new Error('backend down'));

    renderChat();

    // Empty state renders the suggested-prompt buttons; clicking one calls
    // handleSend with no active conversation -> createConversation rejects.
    const prompt = screen.getByText('Critical vulnerabilities');
    fireEvent.click(prompt);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith(
        'Failed to send message',
        expect.objectContaining({ description: 'backend down' }),
      );
    });
    // The rejected create must not have led to a sendMessage call.
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('surfaces a toast when starting a new conversation fails', async () => {
    const { toast } = await import('sonner');
    createMutateAsync.mockRejectedValueOnce(new Error('nope'));

    renderChat();

    fireEvent.click(screen.getByRole('button', { name: /New chat/i }));

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith(
        'Failed to start a new conversation',
        expect.objectContaining({ description: 'nope' }),
      );
    });
  });

  it('sends the message and does not toast when create succeeds', async () => {
    const { toast } = await import('sonner');
    createMutateAsync.mockResolvedValueOnce({ id: 'conv-1' });

    renderChat();

    fireEvent.click(screen.getByText('Risk overview'));

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith(
        'Give me a short summary of my overall security posture.',
        [],
        'conv-1',
      );
    });
    expect(toast.error).not.toHaveBeenCalled();
  });
});
