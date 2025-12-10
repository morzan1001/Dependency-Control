import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { inviteProjectMember, updateProjectMember, removeProjectMember, Project } from '@/lib/api'
import { useAuth } from '@/context/AuthContext'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Spinner } from '@/components/ui/spinner'
import { UserPlus, UserMinus } from 'lucide-react'
import { toast } from "sonner"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
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

interface ProjectMembersProps {
  project: Project
  projectId: string
}

export function ProjectMembers({ project, projectId }: ProjectMembersProps) {
  const queryClient = useQueryClient()
  const { hasPermission } = useAuth()
  const [isInviteMemberOpen, setIsInviteMemberOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("viewer")

  const inviteMemberMutation = useMutation({
    mutationFn: (data: { email: string, role: string }) => inviteProjectMember(projectId, data.email, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] })
      setIsInviteMemberOpen(false)
      setInviteEmail("")
      setInviteRole("viewer")
      toast.success("Member invited successfully")
    },
    onError: (error: any) => {
      toast.error("Failed to invite member", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const updateMemberMutation = useMutation({
    mutationFn: (data: { userId: string, role: string }) => updateProjectMember(projectId, data.userId, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] })
      toast.success("Member role updated")
    },
    onError: (error: any) => {
      toast.error("Failed to update member role", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) => removeProjectMember(projectId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] })
      toast.success("Member removed")
    },
    onError: (error: any) => {
      toast.error("Failed to remove member", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Project Members</CardTitle>
          <CardDescription>Manage who has access to this project.</CardDescription>
        </div>
        {hasPermission('project:update') && (
          <Dialog open={isInviteMemberOpen} onOpenChange={setIsInviteMemberOpen}>
            <DialogTrigger asChild>
              <Button className="gap-2">
                <UserPlus className="h-4 w-4" />
                Invite Member
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Invite Member</DialogTitle>
                <DialogDescription>Add a user to this project.</DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid gap-2">
                  <Label htmlFor="email">Email</Label>
                  <Input 
                    id="email" 
                    value={inviteEmail} 
                    onChange={(e) => setInviteEmail(e.target.value)} 
                    placeholder="user@example.com"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="role">Role</Label>
                  <Select value={inviteRole} onValueChange={setInviteRole}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="viewer">Viewer</SelectItem>
                      <SelectItem value="editor">Editor</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button onClick={() => inviteMemberMutation.mutate({ email: inviteEmail, role: inviteRole })} disabled={inviteMemberMutation.isPending}>
                  {inviteMemberMutation.isPending ? <Spinner className="mr-2 h-4 w-4" /> : null}
                  Invite
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>User</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Source</TableHead>
              <TableHead className="w-[100px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {project.members?.map((member) => (
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
                    onValueChange={(value) => updateMemberMutation.mutate({ userId: member.user_id, role: value })}
                    disabled={member.user_id === project.owner_id || !hasPermission('project:update') || !!member.inherited_from}
                  >
                    <SelectTrigger className="w-[120px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="viewer">Viewer</SelectItem>
                      <SelectItem value="editor">Editor</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  {member.inherited_from ? (
                    <span className="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                      {member.inherited_from}
                    </span>
                  ) : (
                    <span className="text-muted-foreground text-sm">Direct</span>
                  )}
                </TableCell>
                <TableCell>
                  {member.user_id !== project.owner_id && hasPermission('project:update') && !member.inherited_from && (
                    <Button 
                      variant="ghost" 
                      size="icon" 
                      className="text-destructive"
                      onClick={() => removeMemberMutation.mutate(member.user_id)}
                    >
                      <UserMinus className="h-4 w-4" />
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {(!project.members || project.members.length === 0) && (
              <TableRow>
                <TableCell colSpan={4} className="text-center text-muted-foreground">
                  No members found.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
