import { useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { projectApi } from '@/api/projects'
import { projectKeys } from '@/hooks/queries/use-projects'
import { useTeams } from '@/hooks/queries/use-teams'
import { getErrorMessage } from '@/lib/utils'
import { MAX_PROJECT_TEAMS } from '@/lib/constants'
import { Project } from '@/types/project'
import type { TeamSource } from '@/types/team'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { Users } from 'lucide-react'
import { toast } from 'sonner'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

interface ProjectOwningTeamsProps {
  project: Project
  projectId: string
  canManage: boolean
}

interface Owner {
  id: string
  name?: string
  source: TeamSource
}

const SOURCE_LABEL: Record<TeamSource, string> = {
  gitlab: 'GitLab',
  github: 'GitHub',
  manual: 'Manual',
}

const ACCESS_CONSEQUENCE =
  'Its members lose access to this project unless another owning team or a direct membership still grants it.'

function removalConsequence({ name, id, source }: Owner): string {
  const label = name || id
  if (source === 'manual') {
    return `${label} was assigned by hand, so removing it is final: only another assignment brings it back. ${ACCESS_CONSEQUENCE}`
  }
  return `${SOURCE_LABEL[source]} established ${label} as an owner. Removing it here takes effect now, but the next ${SOURCE_LABEL[source]} sync that still finds this repository under that team puts it straight back — change it in ${SOURCE_LABEL[source]} to keep it off. ${ACCESS_CONSEQUENCE}`
}

export function ProjectOwningTeams({ project, projectId, canManage }: ProjectOwningTeamsProps) {
  const queryClient = useQueryClient()
  const { data: teams } = useTeams()
  const [isAddOpen, setIsAddOpen] = useState(false)
  const [teamToAdd, setTeamToAdd] = useState<string | undefined>(undefined)
  const [ownerToRemove, setOwnerToRemove] = useState<Owner | null>(null)

  const teamIds = useMemo(() => project.team_ids ?? [], [project.team_ids])

  const owners: Owner[] = useMemo(() => {
    const names = new Map((teams ?? []).map((team) => [team.id, team.name]))
    return teamIds
      .map((id) => ({ id, name: names.get(id), source: project.team_sources?.[id] ?? 'manual' }))
      .sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id))
  }, [teams, teamIds, project.team_sources])

  const addableTeams = (teams ?? []).filter((team) => !teamIds.includes(team.id))
  const atCap = teamIds.length >= MAX_PROJECT_TEAMS

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) })
    queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
  }

  const addTeamMutation = useMutation({
    mutationFn: (teamId: string) => projectApi.addTeam(projectId, teamId),
    onSuccess: () => {
      invalidate()
      setIsAddOpen(false)
      setTeamToAdd(undefined)
      toast.success('Owning team added')
    },
    onError: (error) => {
      toast.error('Failed to add owning team', { description: getErrorMessage(error) })
    },
  })

  const removeTeamMutation = useMutation({
    mutationFn: (teamId: string) => projectApi.removeTeam(projectId, teamId),
    onSuccess: () => {
      invalidate()
      setOwnerToRemove(null)
      toast.success('Owning team removed')
    },
    onError: (error) => {
      toast.error('Failed to remove owning team', { description: getErrorMessage(error) })
    },
  })

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Owning Teams</CardTitle>
          <CardDescription>
            Every owning team's members can open this project, and it is listed under each of them.
          </CardDescription>
        </div>
        {canManage && (
          <Dialog open={isAddOpen} onOpenChange={setIsAddOpen}>
            <DialogTrigger asChild>
              <Button className="gap-2" disabled={atCap}>
                <Users className="h-4 w-4" />
                Add Team
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Owning Team</DialogTitle>
                <DialogDescription>
                  The team joins the owners this project already has; none of them is replaced.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-2 py-4">
                <Label htmlFor="owning-team">Team</Label>
                <Select value={teamToAdd} onValueChange={setTeamToAdd}>
                  <SelectTrigger id="owning-team">
                    <SelectValue placeholder="Select a team" />
                  </SelectTrigger>
                  <SelectContent>
                    {addableTeams.map((team) => (
                      <SelectItem key={team.id} value={team.id}>
                        {team.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button
                  onClick={() => teamToAdd && addTeamMutation.mutate(teamToAdd)}
                  disabled={!teamToAdd || addTeamMutation.isPending}
                >
                  {addTeamMutation.isPending ? 'Adding...' : 'Add'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </CardHeader>
      <CardContent>
        {atCap && (
          <p className="mb-4 text-sm text-muted-foreground">
            This project has the most owners it may have ({MAX_PROJECT_TEAMS}). Remove one before adding another.
          </p>
        )}
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Team</TableHead>
              <TableHead>Assigned by</TableHead>
              <TableHead className="w-[120px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {owners.map((owner) => (
              <TableRow key={owner.id}>
                <TableCell>
                  <div className="flex flex-col">
                    <span className="font-medium">{owner.name || 'Team you cannot see'}</span>
                    <span className="text-xs text-muted-foreground">{owner.id}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant={owner.source === 'manual' ? 'outline' : 'secondary'}>
                    {SOURCE_LABEL[owner.source]}
                  </Badge>
                </TableCell>
                <TableCell>
                  {canManage && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive"
                      aria-label={`Remove ${owner.name || owner.id}`}
                      onClick={() => setOwnerToRemove(owner)}
                    >
                      Remove
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {owners.length === 0 && (
              <TableRow>
                <TableCell colSpan={3} className="text-center text-muted-foreground">
                  No team owns this project. Only its own members can open it.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>

      <Dialog open={!!ownerToRemove} onOpenChange={(open) => !open && setOwnerToRemove(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove Owning Team</DialogTitle>
            <DialogDescription>{ownerToRemove && removalConsequence(ownerToRemove)}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOwnerToRemove(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={removeTeamMutation.isPending}
              onClick={() => ownerToRemove && removeTeamMutation.mutate(ownerToRemove.id)}
            >
              {removeTeamMutation.isPending ? 'Removing...' : 'Remove'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
