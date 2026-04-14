import { format, formatDistanceToNow } from 'date-fns';
import { Copy, KeyRound, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import {
  useCreateMcpKey,
  useMcpKeys,
  useRevokeMcpKey,
} from '@/hooks/queries/use-mcp-keys';
import type { MCPApiKey } from '@/types/mcp';

const EXPIRY_OPTIONS = [
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: 90, label: '90 days' },
  { value: 180, label: '180 days' },
  { value: 365, label: '1 year (max)' },
];

function isActive(key: MCPApiKey): boolean {
  if (key.revoked_at) return false;
  return new Date(key.expires_at).getTime() > Date.now();
}

function statusLabel(key: MCPApiKey): { text: string; tone: string } {
  if (key.revoked_at) return { text: 'Revoked', tone: 'text-muted-foreground' };
  if (new Date(key.expires_at).getTime() < Date.now()) {
    return { text: 'Expired', tone: 'text-muted-foreground' };
  }
  return { text: 'Active', tone: 'text-emerald-600 dark:text-emerald-400' };
}

export function MCPApiKeysCard() {
  const { data, isLoading } = useMcpKeys(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newExpiry, setNewExpiry] = useState(90);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const createMutation = useCreateMcpKey();
  const revokeMutation = useRevokeMcpKey();

  const handleCreate = async () => {
    const trimmed = newName.trim();
    if (!trimmed) {
      toast.error('Give the key a name so you can recognise it later.');
      return;
    }
    try {
      const created = await createMutation.mutateAsync({
        name: trimmed,
        expires_in_days: newExpiry,
      });
      setRevealedToken(created.token);
      setNewName('');
      setNewExpiry(90);
      setCreateOpen(false);
    } catch {
      toast.error('Failed to create MCP API key.');
    }
  };

  const handleRevoke = async (keyId: string) => {
    if (!window.confirm('Revoke this key? Existing MCP clients using it will stop working immediately.')) {
      return;
    }
    try {
      await revokeMutation.mutateAsync(keyId);
      toast.success('Key revoked.');
    } catch {
      toast.error('Failed to revoke key.');
    }
  };

  const copyToken = async () => {
    if (!revealedToken) return;
    await navigator.clipboard.writeText(revealedToken);
    toast.success('Token copied to clipboard.');
  };

  const keys = data?.keys ?? [];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" />
              MCP API Keys
            </CardTitle>
            <CardDescription>
              Personal access tokens for external LLM clients (Claude Desktop,
              Cursor, custom bots) to call DependencyControl tools via MCP.
              Tokens act as you — every tool call uses your project access.
            </CardDescription>
          </div>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New key
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : keys.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No MCP API keys yet. Create one to connect an external LLM client.
          </p>
        ) : (
          <ul className="divide-y rounded-md border">
            {keys.map((k) => {
              const status = statusLabel(k);
              const expiresIn = formatDistanceToNow(new Date(k.expires_at), { addSuffix: true });
              return (
                <li key={k.id} className="flex flex-wrap items-center gap-3 px-3 py-2 text-sm">
                  <div className="flex-1 min-w-[12rem]">
                    <div className="font-medium">{k.name}</div>
                    <div className="text-xs text-muted-foreground">
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">
                        {k.prefix}…
                      </code>
                      {' · created '}
                      {format(new Date(k.created_at), 'yyyy-MM-dd')}
                      {' · expires '}
                      {expiresIn}
                      {k.last_used_at && (
                        <>
                          {' · last used '}
                          {formatDistanceToNow(new Date(k.last_used_at), { addSuffix: true })}
                        </>
                      )}
                    </div>
                  </div>
                  <span className={`text-xs font-medium ${status.tone}`}>{status.text}</span>
                  {isActive(k) && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-muted-foreground hover:text-destructive"
                      aria-label="Revoke key"
                      onClick={() => handleRevoke(k.id)}
                      disabled={revokeMutation.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create MCP API key</DialogTitle>
            <DialogDescription>
              The token will be shown exactly once after creation. Store it
              somewhere safe (your client config, a password manager). The
              server only keeps a hash.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="mcp-key-name">Name</Label>
              <Input
                id="mcp-key-name"
                placeholder="e.g. Claude Desktop on laptop"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                maxLength={80}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="mcp-key-expiry">Expires in</Label>
              <Select
                value={String(newExpiry)}
                onValueChange={(v) => setNewExpiry(Number(v))}
              >
                <SelectTrigger id="mcp-key-expiry">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EXPIRY_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={String(opt.value)}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              {createMutation.isPending ? 'Creating…' : 'Create key'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Token reveal dialog — non-dismissable until copied */}
      <Dialog
        open={revealedToken !== null}
        onOpenChange={(open) => {
          if (!open) setRevealedToken(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Copy your new key now</DialogTitle>
            <DialogDescription>
              This is the only time the full token will be displayed. Once you
              close this dialog, the server cannot show it again — only its
              prefix.
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-md border bg-muted/40 p-3">
            <code className="block break-all font-mono text-xs">
              {revealedToken}
            </code>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={copyToken}>
              <Copy className="mr-2 h-4 w-4" />
              Copy to clipboard
            </Button>
            <DialogClose asChild>
              <Button>I have stored the key</Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
