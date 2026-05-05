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
import { SettingsTabProps } from '@/types/system';

const MAX_RATE_LIMIT = 1000;
const MIN_RATE_LIMIT = 1;
const MIN_TOOL_ROUNDS = 1;
const MAX_TOOL_ROUNDS = 50;

function clampRate(raw: string, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(Math.max(parsed, MIN_RATE_LIMIT), MAX_RATE_LIMIT);
}

function clampRounds(raw: string, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(Math.max(parsed, MIN_TOOL_ROUNDS), MAX_TOOL_ROUNDS);
}

export function ChatSettingsTab({
  formData,
  handleInputChange,
  handleSave,
  hasPermission,
  isPending,
}: Readonly<SettingsTabProps>) {
  const perMinute = formData.chat_rate_limit_per_minute ?? 10;
  const perHour = formData.chat_rate_limit_per_hour ?? 60;
  const maxRounds = formData.chat_max_tool_rounds ?? 20;
  const canManage = hasPermission('system:manage');

  return (
    <div className="space-y-4">
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
                disabled={!canManage}
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
                disabled={!canManage}
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

      <Card>
        <CardHeader>
          <CardTitle>Reasoning budget</CardTitle>
          <CardDescription>
            How many rounds of LLM ↔ tool-call iteration the assistant is
            allowed per message before we give up and show a fallback.
            Higher values let the model chain more tools but increase the
            worst-case latency.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2 sm:max-w-xs">
            <Label htmlFor="chat-max-tool-rounds">Max tool-call rounds</Label>
            <Input
              id="chat-max-tool-rounds"
              type="number"
              min={MIN_TOOL_ROUNDS}
              max={MAX_TOOL_ROUNDS}
              value={maxRounds}
              disabled={!canManage}
              onChange={(e) =>
                handleInputChange(
                  'chat_max_tool_rounds',
                  clampRounds(e.target.value, maxRounds),
                )
              }
            />
            <p className="text-xs text-muted-foreground">
              Default: 20. Clamped to {MIN_TOOL_ROUNDS}–{MAX_TOOL_ROUNDS}.
              Each round is one Ollama call and can include multiple tool
              invocations — a single round can already fire several tools
              in parallel.
            </p>
          </div>

          <Button
            onClick={handleSave}
            disabled={!canManage || isPending}
          >
            {isPending ? 'Saving…' : 'Save reasoning budget'}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
