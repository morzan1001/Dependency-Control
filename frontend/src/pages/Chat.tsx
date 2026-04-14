import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { History, MessageSquare, MessagesSquare, Plus, Sparkles, Square } from 'lucide-react';

import { ChatInput } from '@/components/chat/ChatInput';
import { ChatMessage, StreamingMessage } from '@/components/chat/ChatMessage';
import { ConversationHistoryDialog } from '@/components/chat/ConversationHistoryDialog';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useAuth } from '@/context';
import {
  useConversation,
  useConversations,
  useCreateConversation,
  useDeleteConversation,
} from '@/hooks/queries/use-chat';
import { useChatStream } from '@/hooks/useChatStream';
import type { Message } from '@/types/chat';

const PROMPT_SUGGESTIONS: ReadonlyArray<{
  icon: typeof Sparkles;
  title: string;
  prompt: string;
}> = [
  {
    icon: Sparkles,
    title: 'Critical vulnerabilities',
    prompt: 'Which critical vulnerabilities do I have across my projects right now?',
  },
  {
    icon: Sparkles,
    title: 'Risk overview',
    prompt: 'Give me a short summary of my overall security posture.',
  },
  {
    icon: Sparkles,
    title: 'Remediation priorities',
    prompt: 'What should I fix first, and why?',
  },
  {
    icon: Sparkles,
    title: 'Dependency impact',
    prompt: 'Which projects use log4j, and are any of them reachable?',
  },
];

export default function Chat() {
  const { hasPermission } = useAuth();
  const canReadHistory = hasPermission('chat:history_read');
  const canDeleteHistory = hasPermission('chat:history_delete');

  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const { data: conversationsData } = useConversations();
  const { data: conversationDetail, refetch: refetchConversation } =
    useConversation(activeConversationId);
  const createConversation = useCreateConversation();
  const deleteConversation = useDeleteConversation();

  const onMessageComplete = useCallback(() => {
    refetchConversation();
  }, [refetchConversation]);

  const {
    sendMessage,
    abort,
    streamingContent,
    streamingToolCalls,
    pendingUserMessage,
    clearPendingUserMessage,
    isStreaming,
    activeToolCall,
    error,
  } = useChatStream(activeConversationId, onMessageComplete);

  // Drop the optimistic user message once the persisted version is back
  // from the server (so we don't render it twice). On error, also drop it
  // a moment after the stream ends so the UI doesn't hang on a pending bubble.
  useEffect(() => {
    if (isStreaming || !pendingUserMessage) return;
    const lastMsg = conversationDetail?.messages?.[conversationDetail.messages.length - 1];
    if (lastMsg?.role === 'user' && lastMsg.content === pendingUserMessage.content) {
      clearPendingUserMessage();
      return;
    }
    if (lastMsg?.role === 'assistant') {
      clearPendingUserMessage();
      return;
    }
    // Fallback — clear after a short grace period if nothing matched.
    const t = setTimeout(clearPendingUserMessage, 1500);
    return () => clearTimeout(t);
  }, [isStreaming, pendingUserMessage, conversationDetail?.messages, clearPendingUserMessage]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [conversationDetail?.messages, streamingContent, streamingToolCalls.length]);

  const handleNewConversation = async () => {
    const conv = await createConversation.mutateAsync(undefined);
    setActiveConversationId(conv.id);
  };

  const handleDeleteConversation = async (id: string) => {
    await deleteConversation.mutateAsync(id);
    if (activeConversationId === id) {
      setActiveConversationId(null);
    }
  };

  const handleSend = (content: string) => {
    if (!activeConversationId) {
      createConversation.mutateAsync(undefined).then((conv) => {
        setActiveConversationId(conv.id);
        sendMessage(content, [], conv.id);
      });
      return;
    }
    sendMessage(content);
  };

  const messages: Message[] = useMemo(
    () => conversationDetail?.messages ?? [],
    [conversationDetail],
  );
  const showEmptyState = messages.length === 0 && !isStreaming;
  const conversationTitle = conversationDetail?.conversation.title ?? 'New chat';

  return (
    <TooltipProvider delayDuration={200}>
    <div className="flex h-[calc(100vh-4rem)] flex-col">
      {/* Page header */}
      <header className="flex items-center justify-between gap-4 border-b bg-background px-6 py-4">
        <div className="flex items-center gap-3 overflow-hidden">
          <MessagesSquare className="h-5 w-5 shrink-0 text-primary" />
          <div className="overflow-hidden">
            <h1 className="truncate text-lg font-semibold leading-none tracking-tight">
              {activeConversationId ? conversationTitle : 'Chat'}
            </h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Ask the AI assistant about your SBOM data, vulnerabilities and dependencies.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" onClick={handleNewConversation}>
                <Plus className="mr-2 h-4 w-4" />
                New chat
              </Button>
            </TooltipTrigger>
            <TooltipContent>Start a new conversation</TooltipContent>
          </Tooltip>
          {canReadHistory && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setHistoryOpen(true)}
                >
                  <History className="mr-2 h-4 w-4" />
                  History
                  {conversationsData && conversationsData.conversations.length > 0 && (
                    <span className="ml-2 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                      {conversationsData.conversations.length}
                    </span>
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>Browse past conversations</TooltipContent>
            </Tooltip>
          )}
        </div>
      </header>

      {/* Messages area */}
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-3xl space-y-4 px-4 py-6">
          {showEmptyState && !pendingUserMessage ? (
            <EmptyState onPrompt={handleSend} />
          ) : (
            <>
              {messages.map((msg) => (
                <ChatMessage key={msg.id} message={msg} />
              ))}
              {pendingUserMessage && (
                <ChatMessage
                  message={{
                    id: 'pending-user',
                    conversation_id: activeConversationId ?? '',
                    role: 'user',
                    content: pendingUserMessage.content,
                    images: pendingUserMessage.images,
                    tool_calls: [],
                    token_count: 0,
                    created_at: new Date().toISOString(),
                  }}
                />
              )}
              {isStreaming && (
                <StreamingMessage
                  content={streamingContent}
                  toolCalls={streamingToolCalls}
                  activeToolCall={activeToolCall}
                />
              )}
            </>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertTitle>Something went wrong</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Stop button floats above input while streaming */}
      {isStreaming && (
        <div className="mx-auto flex max-w-3xl justify-center pb-2">
          <Button onClick={abort} variant="outline" size="sm">
            <Square className="mr-2 h-3 w-3 fill-current" />
            Stop generating
          </Button>
        </div>
      )}

      <ChatInput onSend={handleSend} disabled={isStreaming} />

      {canReadHistory && (
        <ConversationHistoryDialog
          open={historyOpen}
          onOpenChange={setHistoryOpen}
          conversations={conversationsData?.conversations ?? []}
          activeId={activeConversationId}
          onSelect={setActiveConversationId}
          onCreate={handleNewConversation}
          onDelete={handleDeleteConversation}
          canDelete={canDeleteHistory}
        />
      )}
    </div>
    </TooltipProvider>
  );
}

function EmptyState({ onPrompt }: Readonly<{ onPrompt: (content: string) => void }>) {
  return (
    <div className="flex flex-col items-center gap-6 py-12 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
        <MessageSquare className="h-6 w-6 text-primary" />
      </div>
      <div>
        <h2 className="text-xl font-semibold tracking-tight">
          How can I help with your supply chain today?
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Ask anything about your projects, scans, findings or dependencies.
        </p>
      </div>
      <div className="grid w-full gap-2 sm:grid-cols-2">
        {PROMPT_SUGGESTIONS.map(({ icon: Icon, title, prompt }) => (
          <button
            key={title}
            type="button"
            onClick={() => onPrompt(prompt)}
            className="group flex items-start gap-3 rounded-lg border bg-card p-3 text-left transition-colors hover:border-primary/40 hover:bg-muted/50"
          >
            <Icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-colors group-hover:text-primary" />
            <div className="overflow-hidden">
              <div className="truncate text-sm font-medium">{title}</div>
              <div className="line-clamp-2 text-xs text-muted-foreground">{prompt}</div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
