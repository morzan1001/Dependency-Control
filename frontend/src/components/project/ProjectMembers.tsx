import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { projectApi } from '@/api/projects'
import { projectKeys } from '@/hooks/queries/use-projects'
import { Project } from '@/types/project'
import { useAuth } from '@/context/useAuth'
import { refusesEmail, useCurrentUser } from '@/hooks/queries/use-users'
import { isProjectAdmin } from '@/lib/project-roles'
import { getErrorMessage } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { UserPlus, UserMinus } from 'lucide-react'
import { toast } from "sonner"
import {
  Dialog,
  DialogClose,
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

export function ProjectMembers({ project, projectId }: Readonly<ProjectMembersProps>) {
  const queryClient = useQueryClient()
  const { permissions } = useAuth()
  const { data: currentUser } = useCurrentUser()
  const canManageMembers = currentUser
    ? isProjectAdmin(project, currentUser.id, permissions)
    : false
  const [isInviteMemberOpen, setIsInviteMemberOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState("")
  const [blankEmail, setBlankEmail] = useState(false)
  const [inviteRole, setInviteRole] = useState("viewer")

  const inviteMemberMutation = useMutation({
    mutationFn: (data: { email: string, role: string }) => projectApi.inviteMember(projectId, data.email, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) })
      setIsInviteMemberOpen(false)
      setInviteEmail("")
      setInviteRole("viewer")
      toast.success("Member invited successfully")
    },
    onError: (error) => {
      if (!refusesEmail(error)) toast.error("Failed to invite member", { description: getErrorMessage(error) })
    },
  })
  const emailRefusal =
    inviteMemberMutation.isError && refusesEmail(inviteMemberMutation.error) ? getErrorMessage(inviteMemberMutation.error) : null
  const emailError = blankEmail ? 'Enter an email address' : emailRefusal

  const updateMemberMutation = useMutation({
    mutationFn: (data: { userId: string, role: string }) => projectApi.updateMember(projectId, data.userId, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) })
      toast.success("Member role updated")
    },
    meta: { errorTitle: "Failed to update member role" },
  })

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) => projectApi.removeMember(projectId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) })
      toast.success("Member removed")
    },
    meta: { errorTitle: "Failed to remove member" },
  })

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Project Members</CardTitle>
          <CardDescription>Manage who has access to this project.</CardDescription>
        </div>
        {canManageMembers && (
          <Dialog open={isInviteMemberOpen} onOpenChange={(open) => {
            setIsInviteMemberOpen(open)
            if (!open) {
              setInviteEmail("")
              setBlankEmail(false)
              setInviteRole("viewer")
              if (!inviteMemberMutation.isPending) inviteMemberMutation.reset()
            }
          }}>
            <DialogTrigger asChild>
              <Button className="gap-2">
                <UserPlus className="h-4 w-4" />
                Invite Member
              </Button>
            </DialogTrigger>
            <DialogContent>
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  const nextEmail = inviteEmail.trim()
                  if (!nextEmail) {
                    setBlankEmail(true)
                    return
                  }
                  inviteMemberMutation.mutate({ email: nextEmail, role: inviteRole })
                }}
                className="grid gap-4"
                noValidate
              >
                <DialogHeader>
                  <DialogTitle>Invite Member</DialogTitle>
                  <DialogDescription>Add a user to this project.</DialogDescription>
                </DialogHeader>
                <div className="grid gap-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => {
                      setInviteEmail(e.target.value)
                      setBlankEmail(false)
                      if (!inviteMemberMutation.isPending) inviteMemberMutation.reset()
                    }}
                    aria-invalid={!!emailError}
                    aria-describedby={emailError ? 'invite-member-email-error' : undefined}
                    required
                  />
                  {emailError && (
                    <p id="invite-member-email-error" role="alert" className="text-xs text-destructive">{emailError}</p>
                  )}
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="role">Role</Label>
                  <Select value={inviteRole} onValueChange={setInviteRole}>
                    <SelectTrigger id="role">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="viewer">Viewer</SelectItem>
                      <SelectItem value="editor">Editor</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button type="button" variant="outline">Cancel</Button>
                  </DialogClose>
                  <Button type="submit" disabled={inviteMemberMutation.isPending}>
                    {inviteMemberMutation.isPending ? "Inviting..." : "Invite"}
                  </Button>
                </DialogFooter>
              </form>
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
                    value={member.role}
                    onValueChange={(value) => updateMemberMutation.mutate({ userId: member.user_id, role: value })}
                    disabled={!canManageMembers || !!member.inherited_from}
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
                  {canManageMembers && !member.inherited_from && (
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
