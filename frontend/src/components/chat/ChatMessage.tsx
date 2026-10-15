import { memo, useMemo, type ComponentProps } from 'react';
import ReactMarkdown, { type Components } from 'react-markdown';
import remarkBreaks from 'remark-breaks';
import remarkGfm from 'remark-gfm';
import { Bot, User } from 'lucide-react';
import { Link as RouterLink } from 'react-router-dom';

import { Card } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import type { Message, ToolCall } from '@/types/chat';

import {
  collectEntitiesFromToolCalls,
  linkifyAssistantMarkdown,
} from './chat-entities';
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

function AssistantLink(props: Readonly<ComponentProps<'a'>>) {
  const { href, children, ...rest } = props;
  // Single-slash paths stay in the SPA; `//host` is protocol-relative and therefore external.
  if (typeof href === 'string' && href.startsWith('/') && !href.startsWith('//')) {
    return (
      <RouterLink to={href} className="text-primary hover:underline">
        {children}
      </RouterLink>
    );
  }
  return (
    <a
      {...rest}
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className="text-primary hover:underline"
    >
      {children}
    </a>
  );
}

// Module-level, so a streaming answer's table is not remounted, losing its sideways scroll, on every chunk.
const MARKDOWN_COMPONENTS: Components = {
  a: AssistantLink,
  // A rendered <img> would fetch a model-chosen URL without a click.
  img: ({ src, alt }) => <AssistantLink href={src}>{alt || src}</AssistantLink>,
  pre: ({ children }) => <pre className="overflow-x-auto">{children}</pre>,
  table: ({ children }) => <Table>{children}</Table>,
  thead: ({ children }) => <TableHeader>{children}</TableHeader>,
  tbody: ({ children }) => <TableBody>{children}</TableBody>,
  tr: ({ children }) => <TableRow>{children}</TableRow>,
  th: ({ children, style }) => <TableHead style={style}>{children}</TableHead>,
  td: ({ children, style }) => <TableCell style={style}>{children}</TableCell>,
};

function MessageBody({
  content,
  className,
  toolCalls,
}: Readonly<{
  content: string;
  className?: string;
  toolCalls?: ReadonlyArray<ToolCall>;
}>) {
  // Only link entities seen in a tool result, so invented names stay plain text.
  const linkified = useMemo(() => {
    if (!toolCalls || toolCalls.length === 0) return content;
    const entities = collectEntitiesFromToolCalls(toolCalls);
    return linkifyAssistantMarkdown(content, entities);
  }, [content, toolCalls]);

  return (
    <div
      className={cn(
        'prose prose-sm max-w-none break-words dark:prose-invert',
        'prose-pre:my-2 prose-pre:rounded-md prose-pre:bg-muted prose-pre:text-foreground',
        'prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5 prose-code:font-mono prose-code:text-xs prose-code:before:content-none prose-code:after:content-none',
        'prose-p:my-1 prose-ul:my-1 prose-ol:my-1',
        'prose-a:text-primary prose-a:no-underline hover:prose-a:underline',
        className,
      )}
    >
      <ReactMarkdown remarkPlugins={[remarkGfm, remarkBreaks]} components={MARKDOWN_COMPONENTS}>
        {linkified}
      </ReactMarkdown>
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

function ChatMessageImpl({ message }: ChatMessageProps) {
  const isUser = message.role === 'user';

  if (isUser) {
    return (
      <div className="flex justify-end gap-3">
        <div className="min-w-0 max-w-[78%] rounded-2xl rounded-tr-sm bg-primary px-4 py-2.5 text-primary-foreground">
          <MessageBody content={message.content} className="prose-invert" />
        </div>
        <AvatarChip role="user" />
      </div>
    );
  }

  return (
    <div className="flex gap-3">
      <AvatarChip role="assistant" />
      <Card className="min-w-0 max-w-[85%] flex-1 border-muted/60 bg-card px-4 py-3 shadow-none">
        {message.tool_calls?.map((tc, i) => (
          <ToolCallBlock key={`${message.id}-tc-${i}-${tc.tool_name}`} toolCall={tc} />
        ))}
        {message.content && (
          <MessageBody content={message.content} toolCalls={message.tool_calls} />
        )}
      </Card>
    </div>
  );
}

// Memoized so a completed message doesn't re-parse markdown on every streaming re-render.
export const ChatMessage = memo(ChatMessageImpl);

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
  const isThinking = !content && !activeToolCall;
  return (
    <div className="flex gap-3">
      <AvatarChip role="assistant" />
      <Card className="min-w-0 max-w-[85%] flex-1 border-muted/60 bg-card px-4 py-3 shadow-none">
        {toolCalls.map((tc, i) => (
          <ToolCallBlock key={`stream-tc-${i}-${tc.tool_name}`} toolCall={tc} />
        ))}
        {activeToolCall && <ToolCallLoading toolName={activeToolCall} />}
        {content && <MessageBody content={content} toolCalls={toolCalls} />}
        {isThinking && <TypingDots />}
      </Card>
    </div>
  );
}
