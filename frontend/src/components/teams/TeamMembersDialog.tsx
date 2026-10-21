import { useUpdateTeamMember, useRemoveTeamMember } from '@/hooks/queries/use-teams';
import { useInstanceNames } from '@/hooks/queries/use-instances';
import { BindingProvider, Team } from '@/types/team';
import { useAuth } from '@/context/useAuth';
import { useCurrentUser } from '@/hooks/queries/use-users';
import { canManageTeamMembers } from '@/lib/team-roles';
import { PROVIDER_LABEL, sourceLabel } from '@/lib/team-binding';
import { Button } from '@/components/ui/button';
import { UserMinus, Loader2 } from 'lucide-react';
import type { ReactNode } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { toast } from "sonner"
import { TEAM_ROLES } from '@/lib/constants';

interface TeamMembersDialogProps {
  team: Team | null;
  isOpen: boolean;
  onClose: () => void;
}

// A synced member's source is "<provider>:<instance id>"; anything else is shown as stored.
function syncSource(source: string, instanceNames: ReadonlyMap<string, string>): string {
  const [provider, instanceId] = source.split(':');
  return provider in PROVIDER_LABEL ? sourceLabel(provider as BindingProvider, instanceId, instanceNames) : source;
}

// A disabled control fires no pointer events; the wrapper stays unfocusable, or dialog autofocus would open the tooltip.
function SyncLock({ reason, children }: Readonly<{ reason: string | null; children: ReactNode }>) {
  if (!reason) return children;
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex">{children}</span>
        </TooltipTrigger>
        <TooltipContent>{reason}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

export function TeamMembersDialog({ team, isOpen, onClose }: Readonly<TeamMembersDialogProps>) {
  const updateMemberMutation = useUpdateTeamMember({ errorTitle: "Failed to update member role" });
  const removeMemberMutation = useRemoveTeamMember({ errorTitle: "Failed to remove member" });
  const { permissions } = useAuth();
  const { data: currentUser } = useCurrentUser();
  const instanceNames = useInstanceNames(isOpen);

  const canManage = team && currentUser
    ? canManageTeamMembers(team, currentUser.id, permissions)
    : false;

  const adminCount = team?.members.filter(m => m.role === 'admin').length ?? 0;



  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>Manage Members - {team?.name}</DialogTitle>
            <DialogDescription>
              Manage team members and their roles.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4 flex-1 overflow-y-auto min-h-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  {canManage && <TableHead className="w-[100px]">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {team?.members.map((member) => {
                  const isSelf = member.user_id === currentUser?.id;
                  const canEditRole = canManage && !isSelf && !member.sync_owned;
                  const synced = member.source && member.source !== 'manual' ? syncSource(member.source, instanceNames) : null;
                  const syncLock = member.sync_owned ? `Synced from ${synced}; change their membership there` : null;
                  const name = member.username || 'Unknown';
                  return (
                    <TableRow key={member.user_id}>
                      <TableCell>
                        <div className="flex flex-col min-w-0">
                          <span className="font-medium truncate">{name}</span>
                          <span className="text-xs text-muted-foreground break-all">{member.user_id}</span>
                          {synced && (
                            <span className="text-xs text-muted-foreground">Synced from {synced}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <SyncLock reason={syncLock}>
                          <Select
                            value={member.role}
                            onValueChange={(value) => {
                                if (team) {
                                    updateMemberMutation.mutate(
                                      { teamId: team.id, userId: member.user_id, role: value },
                                      { onSuccess: () => toast.success("Member role updated") }
                                    );
                                }
                            }}
                            disabled={!canEditRole || updateMemberMutation.isPending}
                          >
                            <SelectTrigger className="w-[120px]" aria-label={`${name}: Role`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {TEAM_ROLES.map((role) => (
                                <SelectItem key={role.value} value={role.value}>
                                  {role.label}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </SyncLock>
                      </TableCell>
                      {canManage && (
                        <TableCell>
                          {canManage && (!isSelf || adminCount > 1) && (
                            <SyncLock reason={syncLock}>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="text-destructive"
                                aria-label={`Remove ${name}`}
                                disabled={member.sync_owned || removeMemberMutation.isPending}
                                onClick={() => {
                                    if (team) {
                                        removeMemberMutation.mutate(
                                          { teamId: team.id, userId: member.user_id },
                                          { onSuccess: () => toast.success("Member removed") }
                                        );
                                    }
                                }}
                              >
                                {removeMemberMutation.isPending ? (
                                  <Loader2 className="h-4 w-4 animate-spin" />
                                ) : (
                                  <UserMinus className="h-4 w-4" />
                                )}
                              </Button>
                            </SyncLock>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {team?.members.length === 0 && (
              <p className="p-4 text-center text-sm text-muted-foreground">No members in this team.</p>
            )}
          </div>
          <DialogFooter>
              <Button onClick={onClose}>Close</Button>
          </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
