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
import { Checkbox } from '@/components/ui/checkbox';
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
import { useAuth } from '@/context';
import {
  useApiKeys,
  useCreateApiKey,
  useRevokeApiKey,
} from '@/hooks/queries/use-api-keys';
import { extractErrorMessage } from '@/lib/errors';
import { Permissions } from '@/lib/permissions';
import type { ApiKey, ApiKeySurface } from '@/types/apiKey';

const DEFAULT_EXPIRY_DAYS = 90;
const MAX_NAME_LENGTH = 80;
const MUTED_TONE = 'text-muted-foreground';

const EXPIRY_OPTIONS = [
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: DEFAULT_EXPIRY_DAYS, label: '90 days' },
  { value: 180, label: '180 days' },
  { value: 365, label: '1 year (max)' },
];

const SURFACE_ORDER: ApiKeySurface[] = ['mcp', 'adhoc'];

const SURFACE_LABELS: Record<ApiKeySurface, string> = {
  mcp: 'MCP',
  adhoc: 'Ad-hoc analysis',
};

const SURFACE_HINTS: Record<ApiKeySurface, string> = {
  mcp: 'Lets an external LLM client call DependencyControl tools as you.',
  adhoc: 'Lets a pipeline POST an SBOM to /api/v1/analyze.',
};

/** Mirrors the backend table the auth dependency and the mint endpoint share. */
const SURFACE_PERMISSIONS: Record<ApiKeySurface, string> = {
  mcp: Permissions.MCP_ACCESS,
  adhoc: Permissions.ANALYZE_ADHOC,
};

// /analyze persists nothing about a call, so an ad-hoc-only key is never stamped: an absent
// stamp says nothing about whether the key is in use.
const STAMPING_SURFACES: readonly ApiKeySurface[] = ['mcp'];

function statusLabel(key: ApiKey): { text: string; tone: string } {
  if (key.revoked_at) return { text: 'Revoked', tone: MUTED_TONE };
  // Authentication demands a future expires_at, so a key stored without one is already refused.
  if (!key.expires_at) return { text: 'Unusable', tone: MUTED_TONE };
  if (new Date(key.expires_at).getTime() < Date.now()) {
    return { text: 'Expired', tone: MUTED_TONE };
  }
  return { text: 'Active', tone: 'text-emerald-600 dark:text-emerald-400' };
}

function createdText(key: ApiKey): string {
  return key.created_at
    ? `created ${format(new Date(key.created_at), 'yyyy-MM-dd')}`
    : 'creation date not recorded';
}

function expiryText(key: ApiKey): string {
  return key.expires_at
    ? `expires ${formatDistanceToNow(new Date(key.expires_at), { addSuffix: true })}`
    : 'no expiry stored';
}

function usageText(key: ApiKey): string {
  if (key.last_used_at) {
    return `last used ${formatDistanceToNow(new Date(key.last_used_at), { addSuffix: true })}`;
  }
  return key.surfaces.some((surface) => STAMPING_SURFACES.includes(surface))
    ? 'never used'
    : 'usage not recorded';
}

export function ApiKeysCard() {
  const { hasPermission } = useAuth();
  // Listing and revoking are gated on ownership alone; only minting needs a permission.
  const { data, isLoading } = useApiKeys(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newExpiry, setNewExpiry] = useState(DEFAULT_EXPIRY_DAYS);
  const [newSurfaces, setNewSurfaces] = useState<ApiKeySurface[]>([]);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const createMutation = useCreateApiKey();
  const revokeMutation = useRevokeApiKey();

  const mintableSurfaces = SURFACE_ORDER.filter((surface) =>
    hasPermission(SURFACE_PERMISSIONS[surface]),
  );
  const canSubmit = newName.trim() !== '' && newSurfaces.length > 0;

  const toggleSurface = (surface: ApiKeySurface) => {
    setNewSurfaces((current) =>
      current.includes(surface)
        ? current.filter((entry) => entry !== surface)
        : [...current, surface],
    );
  };

  const handleCreate = async () => {
    try {
      const created = await createMutation.mutateAsync({
        name: newName.trim(),
        surfaces: newSurfaces,
        expires_in_days: newExpiry,
      });
      setRevealedToken(created.token);
      setNewName('');
      setNewExpiry(DEFAULT_EXPIRY_DAYS);
      setNewSurfaces([]);
      setCreateOpen(false);
    } catch (err) {
      // The refusal names the surface the caller cannot reach; a generic message would hide it.
      toast.error(extractErrorMessage(err));
    }
  };

  const handleRevoke = async (keyId: string) => {
    if (!window.confirm('Revoke this key? Every surface it names stops accepting it immediately.')) {
      return;
    }
    try {
      await revokeMutation.mutateAsync(keyId);
      toast.success('Key revoked.');
    } catch (err) {
      toast.error(extractErrorMessage(err));
    }
  };

  const copyToken = async () => {
    if (!revealedToken) return;
    await navigator.clipboard.writeText(revealedToken);
    toast.success('Token copied to clipboard.');
  };

  const dismissRevealedToken = () => {
    setRevealedToken(null);
    // The plaintext also sits in react-query's MutationCache until the mutation is reset.
    createMutation.reset();
  };

  const keys = data?.keys ?? [];
  const truncated = data?.truncated ?? null;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" />
              API Keys
            </CardTitle>
            <CardDescription>
              One token per key, opening only the surfaces the key names. A key
              you own stays listed and revocable here even once the permission
              that minted it is withdrawn.
            </CardDescription>
          </div>
          {mintableSurfaces.length > 0 && (
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              New key
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : keys.length === 0 ? (
          <p className="text-sm text-muted-foreground">No API keys yet.</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {keys.map((key) => {
              const status = statusLabel(key);
              return (
                <li key={key.id} className="flex flex-wrap items-center gap-3 px-3 py-2 text-sm">
                  <div className="min-w-[12rem] flex-1">
                    <div className="font-medium">
                      {key.name || <span className="italic text-muted-foreground">Unnamed key</span>}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1">
                      {key.surfaces.length === 0 ? (
                        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                          no surfaces stored
                        </span>
                      ) : (
                        key.surfaces.map((surface) => (
                          <span
                            key={surface}
                            className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium"
                          >
                            {/* The listing filters surfaces to strings, not to the set this card knows. */}
                            {SURFACE_LABELS[surface] ?? surface}
                          </span>
                        ))
                      )}
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">
                        {key.prefix ? `${key.prefix}…` : 'prefix not recorded'}
                      </code>
                      {' · '}
                      <span>{createdText(key)}</span>
                      {' · '}
                      <span>{expiryText(key)}</span>
                      {' · '}
                      <span>{usageText(key)}</span>
                    </div>
                  </div>
                  <span className={`text-xs font-medium ${status.tone}`}>{status.text}</span>
                  {/* Expiry and stored damage stop a key authenticating but do not clear it away. */}
                  {!key.revoked_at && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-muted-foreground hover:text-destructive"
                      aria-label="Revoke key"
                      onClick={() => handleRevoke(key.id)}
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
        {truncated && (
          <p className="mt-2 text-xs text-muted-foreground">
            Showing the newest {truncated.returned} of {truncated.total} keys. Revoke the ones you
            no longer need — the rest cannot be listed here.
          </p>
        )}
        {mintableSurfaces.length === 0 && (
          <p className="mt-2 text-xs text-muted-foreground">
            Minting a key needs the MCP or ad-hoc analysis permission.
          </p>
        )}
      </CardContent>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create API key</DialogTitle>
            <DialogDescription>
              The token will be shown exactly once after creation. Store it
              somewhere safe (your CI secret store, a password manager). The
              server only keeps a hash.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="api-key-name">Name</Label>
              <Input
                id="api-key-name"
                placeholder="e.g. release pipeline"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                maxLength={MAX_NAME_LENGTH}
              />
            </div>
            <div className="grid gap-2">
              <span className="text-sm font-medium">Surfaces</span>
              <p className="text-xs text-muted-foreground">
                The key reaches the surfaces you tick here and nothing else.
              </p>
              {mintableSurfaces.map((surface) => (
                <div key={surface} className="flex items-start gap-2">
                  <Checkbox
                    id={`api-key-surface-${surface}`}
                    checked={newSurfaces.includes(surface)}
                    onCheckedChange={() => toggleSurface(surface)}
                  />
                  <div className="grid gap-0.5 leading-none">
                    <Label htmlFor={`api-key-surface-${surface}`}>
                      {SURFACE_LABELS[surface]}
                    </Label>
                    <p className="text-xs text-muted-foreground">{SURFACE_HINTS[surface]}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="api-key-expiry">Expires in</Label>
              <Select
                value={String(newExpiry)}
                onValueChange={(v) => setNewExpiry(Number(v))}
              >
                <SelectTrigger id="api-key-expiry">
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
            <Button onClick={handleCreate} disabled={!canSubmit || createMutation.isPending}>
              {createMutation.isPending ? 'Creating…' : 'Create key'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={revealedToken !== null}
        onOpenChange={(open) => {
          if (!open) dismissRevealedToken();
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
