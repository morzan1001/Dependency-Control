import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Bot, User } from 'lucide-react';

import { Card } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { Message, ToolCall } from '@/types/chat';

import { ToolCallBlock, ToolCallLoading } from './ToolCallBlock';

function AvatarChip({ role }: Readonly<{ role: 'user' | 'assistant' }>) {
  const Icon = role === 'user' ? User : Bot;
  return (
    <div
      className={cn(
        'flex h-8 w-8 shrink-0 items-center justify-center rounded-full border',
        role === 'user'
          ? 'border-primary/40 bg-primary/10 text-primary'
          : 'border-border bg-muted text-foreground',
      )}
    >
      <Icon className="h-4 w-4" />
    </div>
  );
}

function MessageBody({
  content,
  className,
}: Readonly<{
  content: string;
  className?: string;
}>) {
  return (
    <div
      className={cn(
        'prose prose-sm max-w-none dark:prose-invert',
        'prose-pre:my-2 prose-pre:rounded-md prose-pre:bg-muted prose-pre:text-foreground',
        'prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5 prose-code:font-mono prose-code:text-xs prose-code:before:content-none prose-code:after:content-none',
        'prose-p:my-1 prose-ul:my-1 prose-ol:my-1',
        // Table styling — react-markdown + remark-gfm renders <table> from
        // GFM tables; default prose styles are too tight, so override here.
        'prose-table:my-3 prose-table:w-full prose-table:border-collapse prose-table:overflow-hidden prose-table:rounded-md prose-table:border',
        'prose-thead:bg-muted/60',
        'prose-th:px-3 prose-th:py-2 prose-th:text-left prose-th:font-semibold prose-th:border-b',
        'prose-td:px-3 prose-td:py-1.5 prose-td:align-top prose-td:border-b prose-td:last:border-b-0',
        'prose-tr:border-0',
        className,
      )}
    >
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
    </div>
  );
}

function TypingDots() {
  return (
    <div className="flex items-center gap-1 py-1">
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-muted-foreground/60" />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-muted-foreground/60 [animation-delay:0.15s]" />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-muted-foreground/60 [animation-delay:0.3s]" />
    </div>
  );
}

interface ChatMessageProps {
  readonly message: Message;
}

export function ChatMessage({ message }: ChatMessageProps) {
  const isUser = message.role === 'user';

  if (isUser) {
    return (
      <div className="flex justify-end gap-3">
        <div className="max-w-[78%] rounded-2xl rounded-tr-sm bg-primary px-4 py-2.5 text-primary-foreground">
          {message.images?.map((img) => (
            <img
              key={img.slice(0, 32)}
              src={`data:image/png;base64,${img}`}
              alt="Attached"
              className="my-2 max-w-sm rounded"
            />
          ))}
          <MessageBody content={message.content} className="prose-invert" />
        </div>
        <AvatarChip role="user" />
      </div>
    );
  }

  return (
    <div className="flex gap-3">
      <AvatarChip role="assistant" />
      <Card className="max-w-[85%] flex-1 border-muted/60 bg-card px-4 py-3 shadow-none">
        {message.images?.map((img) => (
          <img
            key={img.slice(0, 32)}
            src={`data:image/png;base64,${img}`}
            alt="Attached"
            className="my-2 max-w-sm rounded"
          />
        ))}
        {message.tool_calls?.map((tc, i) => (
          <ToolCallBlock key={`${message.id}-tc-${i}-${tc.tool_name}`} toolCall={tc} />
        ))}
        {message.content && <MessageBody content={message.content} />}
      </Card>
    </div>
  );
}

interface StreamingMessageProps {
  readonly content: string;
  readonly toolCalls: ToolCall[];
  readonly activeToolCall: string | null;
}

export function StreamingMessage({
  content,
  toolCalls,
  activeToolCall,
}: StreamingMessageProps) {
  // Show typing dots whenever the assistant has nothing visible right now:
  //   - before any token / tool has come back (cold start)
  //   - between rounds: a tool call just ended but the next content/tool is
  //     still being decided by the model. Without this, the UI looks frozen.
  const isThinking = !content && !activeToolCall;
  return (
    <div className="flex gap-3">
      <AvatarChip role="assistant" />
      <Card className="max-w-[85%] flex-1 border-muted/60 bg-card px-4 py-3 shadow-none">
        {toolCalls.map((tc, i) => (
          <ToolCallBlock key={`stream-tc-${i}-${tc.tool_name}`} toolCall={tc} />
        ))}
        {activeToolCall && <ToolCallLoading toolName={activeToolCall} />}
        {content && <MessageBody content={content} />}
        {isThinking && <TypingDots />}
      </Card>
    </div>
  );
}
