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
  const abortControllerRef = useRef<AbortController | null>(null);
  const isStreamingRef = useRef(false);

  const sendMessage = useCallback(
    async (content: string, images: string[] = [], conversationIdOverride?: string) => {
      const effectiveId = conversationIdOverride ?? conversationId;
      if (!effectiveId || isStreamingRef.current) return;

      isStreamingRef.current = true;
      abortControllerRef.current = new AbortController();
      setStreamState({ isStreaming: true, error: null, activeToolCall: null });
      setStreamingContent('');
      setStreamingToolCalls([]);

      try {
        for await (const event of chatApi.sendMessage(
          effectiveId,
          content,
          images,
          abortControllerRef.current.signal,
        )) {
          if (abortControllerRef.current?.signal.aborted) break;

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
                  arguments: event.arguments,
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
        // Ignore AbortError — user intentionally cancelled
        if (!(err instanceof DOMException && err.name === 'AbortError')) {
          setStreamState((prev) => ({
            ...prev,
            error: err instanceof Error ? err.message : 'Stream failed',
          }));
        }
      } finally {
        isStreamingRef.current = false;
        setStreamState((prev) => ({ ...prev, isStreaming: false, activeToolCall: null }));
      }
    },
    [conversationId, onMessageComplete],
  );

  const abort = useCallback(() => {
    abortControllerRef.current?.abort();
  }, []);

  return {
    sendMessage,
    abort,
    streamingContent,
    streamingToolCalls,
    ...streamState,
  };
}
