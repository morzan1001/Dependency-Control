import { useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { projectApi } from '@/api/projects'
import { projectKeys } from '@/hooks/queries/use-projects'
import { useTeams } from '@/hooks/queries/use-teams'
import { cn, getErrorMessage } from '@/lib/utils'
import { MAX_PROJECT_TEAMS } from '@/lib/constants'
import { Project } from '@/types/project'
import type { TeamSource } from '@/types/team'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
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
  const [selectedTeamIds, setSelectedTeamIds] = useState<string[]>([])
  const [ownerToRemove, setOwnerToRemove] = useState<Owner | null>(null)

  const teamIds = useMemo(() => project.team_ids ?? [], [project.team_ids])

  const teamNames = useMemo(
    () => new Map((teams ?? []).map((team) => [team.id, team.name])),
    [teams],
  )
  const teamLabel = (id: string) => teamNames.get(id) || id

  const owners: Owner[] = useMemo(
    () =>
      teamIds
        .map((id) => ({ id, name: teamNames.get(id), source: project.team_sources?.[id] ?? 'manual' }))
        .sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id)),
    [teamNames, teamIds, project.team_sources],
  )

  const addableTeams = (teams ?? []).filter((team) => !teamIds.includes(team.id))
  const atCap = teamIds.length >= MAX_PROJECT_TEAMS
  const room = MAX_PROJECT_TEAMS - teamIds.length
  const overRoom = selectedTeamIds.length > room

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) })
    queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
  }

  const addTeamsMutation = useMutation({
    // There is no bulk route, so each team is its own POST; running them one after another
    // keeps a failure attributable to the team that caused it.
    mutationFn: async (ids: string[]) => {
      const added: string[] = []
      const failed: string[] = []
      const reasons = new Set<string>()
      for (const id of ids) {
        try {
          await projectApi.addTeam(projectId, id)
          added.push(id)
        } catch (error) {
          failed.push(id)
          reasons.add(getErrorMessage(error))
        }
      }
      return { added, failed, reason: [...reasons].join(' · ') }
    },
    onSuccess: ({ added, failed, reason }) => {
      invalidate()
      setSelectedTeamIds(failed)
      if (failed.length === 0) {
        setIsAddOpen(false)
        toast.success(added.length === 1 ? 'Owning team added' : `${added.length} owning teams added`)
        return
      }
      if (added.length === 0) {
        toast.error(`Failed to add ${failed.map(teamLabel).join(', ')}`, { description: reason })
        return
      }
      toast.warning(
        `Added ${added.map(teamLabel).join(', ')} — ${failed.map(teamLabel).join(', ')} could not be added`,
        { description: reason },
      )
    },
  })

  const addSelectedTeams = () => {
    if (overRoom) {
      toast.error(`A project may have ${MAX_PROJECT_TEAMS} owning teams at most`, {
        description: `There is room for ${room} more, but ${selectedTeamIds.length} are selected. Nothing was added.`,
      })
      return
    }
    addTeamsMutation.mutate(selectedTeamIds)
  }

  const toggleTeam = (id: string) =>
    setSelectedTeamIds((current) =>
      current.includes(id) ? current.filter((selected) => selected !== id) : [...current, id],
    )

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
          <Dialog
            open={isAddOpen}
            onOpenChange={(open) => {
              setIsAddOpen(open)
              if (!open) setSelectedTeamIds([])
            }}
          >
            <DialogTrigger asChild>
              <Button className="gap-2" disabled={atCap}>
                <Users className="h-4 w-4" />
                Add Teams
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Owning Teams</DialogTitle>
                <DialogDescription>
                  Every team you tick joins the owners this project already has; none of them is
                  replaced.
                </DialogDescription>
              </DialogHeader>
              {addableTeams.length === 0 ? (
                <p className="py-4 text-sm text-muted-foreground">
                  Every team you can see already owns this project.
                </p>
              ) : (
                <div className="grid gap-3 py-2">
                  <div className="max-h-64 space-y-2 overflow-y-auto pr-1">
                    {addableTeams.map((team) => (
                      <div key={team.id} className="flex items-center gap-2">
                        <Checkbox
                          id={`owning-team-${team.id}`}
                          checked={selectedTeamIds.includes(team.id)}
                          onCheckedChange={() => toggleTeam(team.id)}
                        />
                        <Label htmlFor={`owning-team-${team.id}`} className="font-normal">
                          {team.name}
                        </Label>
                      </div>
                    ))}
                  </div>
                  <p className={cn('text-sm', overRoom ? 'text-destructive' : 'text-muted-foreground')}>
                    {overRoom
                      ? `${selectedTeamIds.length} selected, but there is room for only ${room} more.`
                      : `${selectedTeamIds.length} selected · room for ${room} more.`}
                  </p>
                </div>
              )}
              <DialogFooter>
                <Button
                  onClick={addSelectedTeams}
                  disabled={selectedTeamIds.length === 0 || addTeamsMutation.isPending}
                >
                  {addTeamsMutation.isPending ? 'Adding...' : 'Add'}
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
