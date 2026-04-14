import { ChevronRight, Wrench } from 'lucide-react';
import { useState } from 'react';

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { Badge } from '@/components/ui/badge';
import { Spinner } from '@/components/ui/spinner';
import { cn } from '@/lib/utils';
import type { ToolCall } from '@/types/chat';

export function ToolCallBlock({ toolCall }: { toolCall: ToolCall }) {
  const [open, setOpen] = useState(false);

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="my-2">
      <CollapsibleTrigger
        className={cn(
          'group flex w-full items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground transition-colors hover:bg-muted',
          open && 'rounded-b-none',
        )}
      >
        <Wrench className="h-3.5 w-3.5 shrink-0" />
        <span className="font-medium text-foreground">{toolCall.tool_name}</span>
        <Badge variant="secondary" className="ml-auto font-normal">
          tool call
        </Badge>
        <ChevronRight
          className={cn(
            'h-3.5 w-3.5 shrink-0 transition-transform',
            open && 'rotate-90',
          )}
        />
      </CollapsibleTrigger>
      <CollapsibleContent className="overflow-hidden rounded-b-md border border-t-0 bg-muted/20">
        {Object.keys(toolCall.arguments ?? {}).length > 0 && (
          <div className="border-b px-3 py-2">
            <div className="mb-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
              Arguments
            </div>
            <pre className="max-h-40 overflow-auto text-xs">
              {JSON.stringify(toolCall.arguments, null, 2)}
            </pre>
          </div>
        )}
        <div className="px-3 py-2">
          <div className="mb-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            Result
          </div>
          <pre className="max-h-60 overflow-auto text-xs">
            {JSON.stringify(toolCall.result, null, 2)}
          </pre>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

export function ToolCallLoading({ toolName }: { toolName: string }) {
  return (
    <div className="my-2 flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
      <Spinner className="h-3.5 w-3.5" />
      <span>
        {'Running '}
        <span className="font-medium text-foreground">{toolName}</span>
        {' …'}
      </span>
    </div>
  );
}
