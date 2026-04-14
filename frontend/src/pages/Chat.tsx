import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/context'; // adjust if different
import { ChatSidebar } from '@/components/chat/ChatSidebar';
import { ChatMessage, StreamingMessage } from '@/components/chat/ChatMessage';
import { ChatInput } from '@/components/chat/ChatInput';
import {
  useConversations,
  useConversation,
  useCreateConversation,
  useDeleteConversation,
} from '@/hooks/queries/use-chat';
import { useChatStream } from '@/hooks/useChatStream';
import type { Message } from '@/types/chat';

export default function Chat() {
  const { hasPermission } = useAuth();
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const showHistory = hasPermission('chat:history_read');
  const { data: conversationsData } = useConversations();
  const { data: conversationDetail, refetch: refetchConversation } = useConversation(activeConversationId);
  const createConversation = useCreateConversation();
  const deleteConversation = useDeleteConversation();

  const onMessageComplete = useCallback(() => {
    refetchConversation();
  }, [refetchConversation]);

  const {
    sendMessage,
    streamingContent,
    streamingToolCalls,
    isStreaming,
    activeToolCall,
    error,
  } = useChatStream(activeConversationId, onMessageComplete);

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [conversationDetail?.messages, streamingContent]);

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
      // Auto-create conversation on first message
      createConversation.mutateAsync(undefined).then((conv) => {
        setActiveConversationId(conv.id);
        setTimeout(() => sendMessage(content), 50);
      });
      return;
    }
    sendMessage(content);
  };

  const messages: Message[] = conversationDetail?.messages || [];

  return (
    <div className="flex h-[calc(100vh-4rem)] overflow-hidden">
      {showHistory && (
        <ChatSidebar
          conversations={conversationsData?.conversations || []}
          activeId={activeConversationId}
          onSelect={setActiveConversationId}
          onCreate={handleNewConversation}
          onDelete={handleDeleteConversation}
        />
      )}
      <div className="flex flex-1 flex-col">
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 && !isStreaming && (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              <p>Start a conversation by typing a message below.</p>
            </div>
          )}
          {messages.map((msg) => (
            <ChatMessage key={msg.id} message={msg} />
          ))}
          {isStreaming && (
            <StreamingMessage
              content={streamingContent}
              toolCalls={streamingToolCalls}
              activeToolCall={activeToolCall}
            />
          )}
          {error && (
            <div className="rounded-md border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>
        <ChatInput onSend={handleSend} disabled={isStreaming} />
      </div>
    </div>
  );
}
