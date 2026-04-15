import { formatDistanceToNow } from 'date-fns';
import { MessageSquare, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';

import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { Conversation } from '@/types/chat';

interface Props {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly conversations: Conversation[];
  readonly activeId: string | null;
  readonly onSelect: (id: string) => void;
  readonly onCreate: () => void;
  readonly onDelete: (id: string) => void;
  readonly canDelete: boolean;
}

export function ConversationHistoryDialog({
  open,
  onOpenChange,
  conversations,
  activeId,
  onSelect,
  onCreate,
  onDelete,
  canDelete,
}: Props) {
  const [search, setSearch] = useState('');
  const filtered = search
    ? conversations.filter((c) =>
        c.title.toLowerCase().includes(search.toLowerCase()),
      )
    : conversations;

  const handleSelect = (id: string) => {
    onSelect(id);
    onOpenChange(false);
  };

  const handleCreate = () => {
    onCreate();
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Chat history</DialogTitle>
          <DialogDescription>
            Open a past conversation or start a new one.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search conversations…"
          />

          <div className="max-h-[50vh] overflow-y-auto rounded-md border">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 p-8 text-center text-sm text-muted-foreground">
                <MessageSquare className="h-6 w-6" />
                <span>
                  {conversations.length === 0
                    ? 'No conversations yet.'
                    : 'No matches.'}
                </span>
              </div>
            ) : (
              <ul className="divide-y">
                {filtered.map((conv) => {
                  const isActive = conv.id === activeId;
                  return (
                    <li
                      key={conv.id}
                      className={cn(
                        'group flex min-w-0 items-center gap-2 px-3 py-2 text-sm transition-colors hover:bg-muted/60',
                        isActive && 'bg-muted',
                      )}
                    >
                      <button
                        type="button"
                        onClick={() => handleSelect(conv.id)}
                        className="flex min-w-0 flex-1 flex-col items-start overflow-hidden text-left"
                      >
                        <span className="w-full truncate font-medium text-foreground">
                          {conv.title}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {formatDistanceToNow(new Date(conv.updated_at), {
                            addSuffix: true,
                          })}
                          {conv.message_count > 0 && (
                            <> · {conv.message_count} messages</>
                          )}
                        </span>
                      </button>
                      {canDelete && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-destructive"
                              onClick={(e: React.MouseEvent) => {
                                e.stopPropagation();
                                onDelete(conv.id);
                              }}
                              aria-label="Delete conversation"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Delete conversation</TooltipContent>
                        </Tooltip>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>

        <DialogFooter className="flex-row justify-between sm:justify-between">
          <span className="text-xs text-muted-foreground">
            {conversations.length} conversation
            {conversations.length === 1 ? '' : 's'}
          </span>
          <Button onClick={handleCreate} size="sm">
            <Plus className="mr-2 h-4 w-4" />
            New chat
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
