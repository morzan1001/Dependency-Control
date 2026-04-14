import ReactMarkdown from 'react-markdown';
import { Bot, User } from 'lucide-react';
import type { Message, ToolCall } from '@/types/chat';
import { ToolCallBlock, ToolCallLoading } from './ToolCallBlock';

interface ChatMessageProps {
  message: Message;
}

export function ChatMessage({ message }: ChatMessageProps) {
  const isUser = message.role === 'user';

  return (
    <div className={`flex gap-3 ${isUser ? 'justify-end' : ''}`}>
      {!isUser && (
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/10">
          <Bot className="h-4 w-4 text-primary" />
        </div>
      )}
      <div className={`max-w-[80%] ${isUser ? 'bg-primary text-primary-foreground' : 'bg-muted'} rounded-lg px-4 py-3`}>
        {message.tool_calls?.map((tc, i) => (
          <ToolCallBlock key={i} toolCall={tc} />
        ))}
        {message.images?.map((img, i) => (
          <img key={i} src={`data:image/png;base64,${img}`} alt="Attached" className="my-2 max-w-sm rounded" />
        ))}
        <div className="prose prose-sm dark:prose-invert max-w-none">
          <ReactMarkdown>{message.content}</ReactMarkdown>
        </div>
      </div>
      {isUser && (
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary">
          <User className="h-4 w-4 text-primary-foreground" />
        </div>
      )}
    </div>
  );
}

interface StreamingMessageProps {
  content: string;
  toolCalls: ToolCall[];
  activeToolCall: string | null;
}

export function StreamingMessage({ content, toolCalls, activeToolCall }: StreamingMessageProps) {
  return (
    <div className="flex gap-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/10">
        <Bot className="h-4 w-4 text-primary" />
      </div>
      <div className="max-w-[80%] rounded-lg bg-muted px-4 py-3">
        {toolCalls.map((tc, i) => (
          <ToolCallBlock key={i} toolCall={tc} />
        ))}
        {activeToolCall && <ToolCallLoading toolName={activeToolCall} />}
        {content && (
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <ReactMarkdown>{content}</ReactMarkdown>
          </div>
        )}
        {!content && !activeToolCall && toolCalls.length === 0 && (
          <div className="flex gap-1">
            <span className="h-2 w-2 animate-bounce rounded-full bg-muted-foreground/50" />
            <span className="h-2 w-2 animate-bounce rounded-full bg-muted-foreground/50 [animation-delay:0.2s]" />
            <span className="h-2 w-2 animate-bounce rounded-full bg-muted-foreground/50 [animation-delay:0.4s]" />
          </div>
        )}
      </div>
    </div>
  );
}
