import { useCallback, useRef, useState } from 'react';
import { chatApi } from '@/api/chat';
import type { ToolCall } from '@/types/chat';

interface StreamState {
  isStreaming: boolean;
  error: string | null;
  activeToolCall: string | null;
}

export function useChatStream(
  conversationId: string | null,
  onMessageComplete: () => void,
) {
  const [streamState, setStreamState] = useState<StreamState>({
    isStreaming: false,
    error: null,
    activeToolCall: null,
  });
  const [streamingContent, setStreamingContent] = useState('');
  const [streamingToolCalls, setStreamingToolCalls] = useState<ToolCall[]>([]);
  const abortRef = useRef(false);

  const sendMessage = useCallback(
    async (content: string, images: string[] = []) => {
      if (!conversationId || streamState.isStreaming) return;

      abortRef.current = false;
      setStreamState({ isStreaming: true, error: null, activeToolCall: null });
      setStreamingContent('');
      setStreamingToolCalls([]);

      try {
        for await (const event of chatApi.sendMessage(conversationId, content, images)) {
          if (abortRef.current) break;

          switch (event.type) {
            case 'token':
              setStreamingContent((prev) => prev + event.content);
              break;
            case 'tool_call_start':
              setStreamState((prev) => ({ ...prev, activeToolCall: event.tool_name }));
              break;
            case 'tool_call_end':
              setStreamingToolCalls((prev) => [
                ...prev,
                {
                  tool_name: event.tool_name,
                  arguments: {},
                  result: event.result,
                  duration_ms: 0,
                },
              ]);
              setStreamState((prev) => ({ ...prev, activeToolCall: null }));
              break;
            case 'done':
              onMessageComplete();
              break;
            case 'error':
              setStreamState((prev) => ({ ...prev, error: event.message }));
              break;
          }
        }
      } catch (err) {
        setStreamState((prev) => ({
          ...prev,
          error: err instanceof Error ? err.message : 'Stream failed',
        }));
      } finally {
        setStreamState((prev) => ({ ...prev, isStreaming: false, activeToolCall: null }));
      }
    },
    [conversationId, streamState.isStreaming, onMessageComplete],
  );

  const abort = useCallback(() => {
    abortRef.current = true;
  }, []);

  return {
    sendMessage,
    abort,
    streamingContent,
    streamingToolCalls,
    ...streamState,
  };
}
