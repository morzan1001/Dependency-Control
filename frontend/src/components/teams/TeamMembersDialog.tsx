import { useUpdateTeamMember, useRemoveTeamMember } from '@/hooks/queries/use-teams';
import { Team } from '@/types/team';
import { useAuth } from '@/context/useAuth';
import { useCurrentUser } from '@/hooks/queries/use-users';
import { canManageTeamMembers } from '@/lib/team-roles';
import { Button } from '@/components/ui/button';
import { UserMinus, Loader2 } from 'lucide-react';
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
import { toast } from "sonner"
import { TEAM_ROLES } from '@/lib/constants';

interface TeamMembersDialogProps {
  team: Team | null;
  isOpen: boolean;
  onClose: () => void;
}

export function TeamMembersDialog({ team, isOpen, onClose }: TeamMembersDialogProps) {
  const updateMemberMutation = useUpdateTeamMember();
  const removeMemberMutation = useRemoveTeamMember();
  const { permissions } = useAuth();
  const { data: currentUser } = useCurrentUser();

  const canManage = team && currentUser
    ? canManageTeamMembers(team, currentUser.id, permissions)
    : false;

  const adminCount = team?.members.filter(m => m.role === 'admin').length ?? 0;



  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Manage Members - {team?.name}</DialogTitle>
            <DialogDescription>
              Manage team members and their roles.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
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
                  const canEditRole = canManage && !isSelf;
                  return (
                    <TableRow key={member.user_id}>
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-medium">{member.username || 'Unknown'}</span>
                          <span className="text-xs text-muted-foreground">{member.user_id}</span>
                        </div>
                      </TableCell>
                      <TableCell>
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
                          <SelectTrigger className="w-[120px]">
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
                      </TableCell>
                      {canManage && (
                        <TableCell>
                          {canManage && (!isSelf || adminCount > 1) && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="text-destructive"
                              disabled={removeMemberMutation.isPending}
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
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  );
                })}
                {team?.members.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={canManage ? 3 : 2} className="text-center text-muted-foreground">
                      No members in this team.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
          <DialogFooter>
              <Button onClick={onClose}>Close</Button>
          </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
