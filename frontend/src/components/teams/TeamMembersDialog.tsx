import { useMutation, useQueryClient } from '@tanstack/react-query';
import { updateTeamMember, removeTeamMember, Team } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { UserMinus } from 'lucide-react';
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

interface TeamMembersDialogProps {
  team: Team | null;
  isOpen: boolean;
  onClose: () => void;
}

export function TeamMembersDialog({ team, isOpen, onClose }: TeamMembersDialogProps) {
  const queryClient = useQueryClient();

  const updateMemberMutation = useMutation({
    mutationFn: (data: { teamId: string; userId: string; role: string }) => updateTeamMember(data.teamId, data.userId, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['teams'] });
      toast.success("Member role updated");
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: (data: { teamId: string; userId: string }) => removeTeamMember(data.teamId, data.userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['teams'] });
      toast.success("Member removed");
    },
  });

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
                  <TableHead className="w-[100px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {team?.members.map((member) => (
                  <TableRow key={member.user_id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{member.username || 'Unknown'}</span>
                        <span className="text-xs text-muted-foreground">{member.user_id}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Select 
                        defaultValue={member.role} 
                        onValueChange={(value) => {
                            if (team) {
                                updateMemberMutation.mutate({ teamId: team._id, userId: member.user_id, role: value })
                            }
                        }}
                      >
                        <SelectTrigger className="w-[120px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="member">Member</SelectItem>
                          <SelectItem value="admin">Admin</SelectItem>
                          <SelectItem value="owner">Owner</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell>
                      <Button 
                        variant="ghost" 
                        size="icon" 
                        className="text-destructive"
                        onClick={() => {
                            if (team) {
                                removeMemberMutation.mutate({ teamId: team._id, userId: member.user_id })
                            }
                        }}
                      >
                        <UserMinus className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
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
