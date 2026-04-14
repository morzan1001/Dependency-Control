import { Info } from 'lucide-react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { SettingsTabProps } from '@/types/system';

const MAX_RATE_LIMIT = 1000;
const MIN_RATE_LIMIT = 1;

function clampRate(raw: string, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(Math.max(parsed, MIN_RATE_LIMIT), MAX_RATE_LIMIT);
}

export function ChatSettingsTab({
  formData,
  handleInputChange,
  handleSave,
  hasPermission,
  isPending,
}: Readonly<SettingsTabProps>) {
  const enabled = formData.chat_enabled ?? false;
  const perMinute = formData.chat_rate_limit_per_minute ?? 10;
  const perHour = formData.chat_rate_limit_per_hour ?? 60;
  const canManage = hasPermission('system:manage');

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>AI Chat Assistant</CardTitle>
          <CardDescription>
            Enable the AI chat feature backed by Ollama and configure per-user
            rate limits.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between space-x-2">
            <div className="space-y-0.5">
              <Label className="text-base">Enable chat feature</Label>
              <p className="text-sm text-muted-foreground">
                Users still need the <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">chat:access</code> permission
                to see the chat menu. Disabling this flag hides the feature
                globally regardless of permissions.
              </p>
            </div>
            <Switch
              checked={enabled}
              onCheckedChange={(checked) => handleInputChange('chat_enabled', checked)}
              disabled={!canManage}
            />
          </div>

          <Alert>
            <Info className="h-4 w-4" />
            <AlertTitle>Permissions</AlertTitle>
            <AlertDescription>
              Grant chat access via the user management page. Three permissions
              control the feature:
              <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
                <li>
                  <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">chat:access</code> — use the chat, create conversations, send messages
                </li>
                <li>
                  <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">chat:history_read</code> — browse past conversations
                </li>
                <li>
                  <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">chat:history_delete</code> — delete own conversations
                </li>
              </ul>
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Rate limits</CardTitle>
          <CardDescription>
            Per-user sliding-window limits applied on every chat message. The
            Ollama GPU node has finite throughput — use these to prevent a
            single user from starving the rest.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="chat-rate-per-minute">Messages per minute</Label>
              <Input
                id="chat-rate-per-minute"
                type="number"
                min={MIN_RATE_LIMIT}
                max={MAX_RATE_LIMIT}
                value={perMinute}
                disabled={!canManage || !enabled}
                onChange={(e) =>
                  handleInputChange(
                    'chat_rate_limit_per_minute',
                    clampRate(e.target.value, perMinute),
                  )
                }
              />
              <p className="text-xs text-muted-foreground">
                Short-burst cap. Default: 10.
              </p>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="chat-rate-per-hour">Messages per hour</Label>
              <Input
                id="chat-rate-per-hour"
                type="number"
                min={MIN_RATE_LIMIT}
                max={MAX_RATE_LIMIT}
                value={perHour}
                disabled={!canManage || !enabled}
                onChange={(e) =>
                  handleInputChange(
                    'chat_rate_limit_per_hour',
                    clampRate(e.target.value, perHour),
                  )
                }
              />
              <p className="text-xs text-muted-foreground">
                Long-window cap. Default: 60.
              </p>
            </div>
          </div>

          <Button
            onClick={handleSave}
            disabled={!canManage || isPending}
          >
            {isPending ? 'Saving…' : 'Save chat settings'}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
