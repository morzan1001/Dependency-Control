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

const LINK_CLASS = 'text-primary underline underline-offset-4';

function AssistantLink(props: Readonly<ComponentProps<'a'>>) {
  const { href, children, ...rest } = props;
  // Single-slash paths stay in the SPA; `//host` is protocol-relative and therefore external.
  if (typeof href === 'string' && href.startsWith('/') && !href.startsWith('//')) {
    return (
      <RouterLink to={href} className={LINK_CLASS}>
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
      className={LINK_CLASS}
    >
      {children}
    </a>
  );
}

// Module-level, so a streaming answer's table is not remounted, losing its sideways scroll, on every chunk.
const ASSISTANT_MARKDOWN: Components = {
  a: AssistantLink,
  // A rendered <img> would fetch a model-chosen URL without a click.
  img: ({ src, alt }) => <AssistantLink href={src}>{alt || src}</AssistantLink>,
  p: ({ children }) => <p className="my-1">{children}</p>,
  ul: ({ children }) => <ul className="my-1 list-disc pl-5">{children}</ul>,
  ol: ({ children }) => <ol className="my-1 list-decimal pl-5">{children}</ol>,
  blockquote: ({ children }) => <blockquote className="my-2 border-l-4 pl-4 italic">{children}</blockquote>,
  // Matches a tool call's panel; its <code> child drops the inline chip.
  pre: ({ children }) => (
    <pre className="my-2 overflow-x-auto rounded-md border bg-muted/20 px-3 py-2 text-xs [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-inherit">
      {children}
    </pre>
  ),
  code: ({ children }) => <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">{children}</code>,
  table: ({ children }) => <Table>{children}</Table>,
  thead: ({ children }) => <TableHeader>{children}</TableHeader>,
  tbody: ({ children }) => <TableBody>{children}</TableBody>,
  tr: ({ children }) => <TableRow>{children}</TableRow>,
  th: ({ children, style }) => <TableHead style={style}>{children}</TableHead>,
  td: ({ children, style }) => <TableCell style={style}>{children}</TableCell>,
};

// The muted header and row hover of the app table fail on the bubble's primary fill.
const USER_MARKDOWN: Components = {
  ...ASSISTANT_MARKDOWN,
  tr: ({ children }) => <TableRow className="hover:bg-transparent">{children}</TableRow>,
  th: ({ children, style }) => <TableHead style={style} className="text-inherit">{children}</TableHead>,
};

function MessageBody({
  content,
  components,
  className,
  toolCalls,
}: Readonly<{
  content: string;
  components: Components;
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
    <div className={cn('break-words text-sm', className)}>
      <ReactMarkdown remarkPlugins={[remarkGfm, remarkBreaks]} components={components}>
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
          <MessageBody content={message.content} components={USER_MARKDOWN} className="[&_a]:text-inherit [&_a]:underline" />
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
          <MessageBody content={message.content} components={ASSISTANT_MARKDOWN} toolCalls={message.tool_calls} />
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
        {content && <MessageBody content={content} components={ASSISTANT_MARKDOWN} toolCalls={toolCalls} />}
        {isThinking && <TypingDots />}
      </Card>
    </div>
  );
}
