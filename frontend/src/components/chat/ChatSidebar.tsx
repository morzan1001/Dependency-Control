import { MessageSquarePlus, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/context';
import type { Conversation } from '@/types/chat';

interface ChatSidebarProps {
  conversations: Conversation[];
  activeId: string | null;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onDelete: (id: string) => void;
}

export function ChatSidebar({ conversations, activeId, onSelect, onCreate, onDelete }: ChatSidebarProps) {
  const { hasPermission } = useAuth();
  const canDelete = hasPermission('chat:history_delete');

  return (
    <div className="flex h-full w-64 flex-col border-r bg-muted/30">
      <div className="p-3">
        <Button onClick={onCreate} className="w-full" variant="outline" size="sm">
          <MessageSquarePlus className="mr-2 h-4 w-4" />
          New Chat
        </Button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {conversations.map((conv) => (
          <div
            key={conv.id}
            onClick={() => onSelect(conv.id)}
            className={`group flex cursor-pointer items-center gap-2 px-3 py-2 text-sm hover:bg-muted ${
              activeId === conv.id ? 'bg-muted font-medium' : ''
            }`}
          >
            <span className="flex-1 truncate">{conv.title}</span>
            {canDelete && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(conv.id);
                }}
                className="hidden text-muted-foreground hover:text-destructive group-hover:block"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
