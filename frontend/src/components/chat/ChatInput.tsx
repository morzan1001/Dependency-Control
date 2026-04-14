import { Send } from 'lucide-react';
import { useEffect, useRef, useState, type KeyboardEvent } from 'react';

import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';

interface ChatInputProps {
  readonly onSend: (content: string) => void;
  readonly disabled?: boolean;
  readonly placeholder?: string;
}

const MIN_HEIGHT = 48;
const MAX_HEIGHT = 200;

export function ChatInput({ onSend, disabled, placeholder }: ChatInputProps) {
  const [input, setInput] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const resize = () => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(Math.max(el.scrollHeight, MIN_HEIGHT), MAX_HEIGHT)}px`;
  };

  useEffect(() => {
    resize();
  }, [input]);

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setInput('');
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const canSend = !disabled && input.trim().length > 0;

  return (
    <div className="border-t bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex max-w-3xl items-end gap-2 px-4 py-3">
        <Textarea
          ref={textareaRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder ?? 'Ask about your security data…'}
          disabled={disabled}
          rows={1}
          style={{ minHeight: MIN_HEIGHT, maxHeight: MAX_HEIGHT }}
          className="flex-1 resize-none py-3 leading-snug"
        />
        <Button
          onClick={handleSend}
          disabled={!canSend}
          size="icon"
          aria-label="Send message"
          className="shrink-0"
        >
          <Send className="h-4 w-4" />
        </Button>
      </div>
      <div className="mx-auto max-w-3xl px-4 pb-2 text-[11px] text-muted-foreground">
        {'Press '}
        <kbd className="rounded border bg-muted px-1 py-0.5 font-mono">Enter</kbd>
        {' to send, '}
        <kbd className="rounded border bg-muted px-1 py-0.5 font-mono">Shift</kbd>
        {'+'}
        <kbd className="rounded border bg-muted px-1 py-0.5 font-mono">Enter</kbd>
        {' for a new line.'}
      </div>
    </div>
  );
}
