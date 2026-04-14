export interface Conversation {
  id: string;
  user_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
}

export interface ToolCall {
  tool_name: string;
  arguments: Record<string, unknown>;
  result: Record<string, unknown>;
  duration_ms: number;
}

export interface Message {
  id: string;
  conversation_id: string;
  role: 'user' | 'assistant' | 'tool';
  content: string;
  images: string[];
  tool_calls: ToolCall[];
  token_count: number;
  created_at: string;
}

export interface ConversationListResponse {
  conversations: Conversation[];
  total: number;
}

export interface ConversationDetailResponse {
  conversation: Conversation;
  messages: Message[];
}

// SSE event types
export type ChatSSEEvent =
  | { type: 'token'; content: string }
  | { type: 'tool_call_start'; tool_name: string }
  | { type: 'tool_call_end'; tool_name: string; result: Record<string, unknown> }
  | { type: 'done' }
  | { type: 'error'; message: string };
