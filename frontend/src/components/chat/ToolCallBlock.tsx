import { ChevronDown, ChevronRight, Wrench } from 'lucide-react';
import { useState } from 'react';
import type { ToolCall } from '@/types/chat';

export function ToolCallBlock({ toolCall }: { toolCall: ToolCall }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="my-2 rounded-md border bg-muted/50 text-sm">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted"
      >
        <Wrench className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-medium">{toolCall.tool_name}</span>
        {expanded ? (
          <ChevronDown className="ml-auto h-3.5 w-3.5" />
        ) : (
          <ChevronRight className="ml-auto h-3.5 w-3.5" />
        )}
      </button>
      {expanded && (
        <pre className="max-h-60 overflow-auto border-t px-3 py-2 text-xs">
          {JSON.stringify(toolCall.result, null, 2)}
        </pre>
      )}
    </div>
  );
}

export function ToolCallLoading({ toolName }: { toolName: string }) {
  return (
    <div className="my-2 flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2 text-sm">
      <Wrench className="h-3.5 w-3.5 animate-pulse text-muted-foreground" />
      <span className="text-muted-foreground">Querying {toolName}...</span>
    </div>
  );
}
