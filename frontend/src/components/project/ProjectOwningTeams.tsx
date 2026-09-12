import { useCallback, useMemo, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { projectApi } from '@/api/projects'
import { projectKeys } from '@/hooks/queries/use-projects'
import { useTeams } from '@/hooks/queries/use-teams'
import { useClickOutside } from '@/hooks/use-click-outside'
import { cn, getErrorMessage } from '@/lib/utils'
import { MAX_PROJECT_TEAMS } from '@/lib/constants'
import { Project } from '@/types/project'
import type { Team, TeamSource } from '@/types/team'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Check, ChevronDown } from 'lucide-react'
import { toast } from 'sonner'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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

interface TeamPickerProps {
  teams: Team[]
  selectedIds: string[]
  room: number
  open: boolean
  onOpenChange: (open: boolean) => void
  onToggle: (id: string) => void
}

function TeamPicker({ teams, selectedIds, room, open, onOpenChange, onToggle }: TeamPickerProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  // Pressing Add closes the picker through click-outside, on a mousedown that precedes the click —
  // so closing must leave the selection alone or Add would fire on an empty one.
  const close = useCallback(() => onOpenChange(false), [onOpenChange])
  useClickOutside(containerRef, close, open)

  const atCap = room <= 0
  const nothingToAdd = teams.length === 0
  const overRoom = selectedIds.length > room
  const selectedNames = teams.filter((team) => selectedIds.includes(team.id)).map((team) => team.name)

  let label: string
  if (overRoom) {
    label = `${selectedIds.length} selected, room for ${room} more`
  } else if (selectedNames.length > 0) {
    label = selectedNames.join(', ')
  } else if (atCap) {
    label = `${MAX_PROJECT_TEAMS} owning teams is the limit`
  } else if (nothingToAdd) {
    label = 'Every team you can see already owns this project'
  } else {
    label = 'Select teams to add'
  }

  return (
    <div
      ref={containerRef}
      className="relative w-full sm:max-w-xs"
      onKeyDown={(event) => event.key === 'Escape' && close()}
    >
      <button
        type="button"
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-invalid={overRoom}
        disabled={atCap || nothingToAdd}
        onClick={() => onOpenChange(!open)}
        className={cn(
          'flex h-10 w-full items-center justify-between gap-2 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
          overRoom && 'border-destructive',
        )}
      >
        <span
          className={cn(
            'truncate text-left',
            overRoom && 'text-destructive',
            selectedNames.length === 0 && !overRoom && 'text-muted-foreground',
          )}
        >
          {label}
        </span>
        <ChevronDown className="h-4 w-4 shrink-0 opacity-50" />
      </button>

      {open && (
        <div className="absolute z-50 mt-1 w-full rounded-md border bg-popover text-popover-foreground shadow-md">
          <div role="listbox" aria-multiselectable className="max-h-64 overflow-y-auto p-1">
            {teams.map((team) => {
              const selected = selectedIds.includes(team.id)
              return (
                <button
                  key={team.id}
                  type="button"
                  role="option"
                  aria-selected={selected}
                  onClick={() => onToggle(team.id)}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground"
                >
                  <Check className={cn('h-4 w-4 shrink-0', selected ? 'opacity-100' : 'opacity-0')} />
                  <span className="truncate">{team.name}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

export function ProjectOwningTeams({ project, projectId, canManage }: ProjectOwningTeamsProps) {
  const queryClient = useQueryClient()
  const { data: teams } = useTeams()
  const [isPickerOpen, setIsPickerOpen] = useState(false)
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
        setIsPickerOpen(false)
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
      <CardHeader>
        <CardTitle>Owning Teams</CardTitle>
        <CardDescription>
          Every owning team's members can open this project, and it is listed under each of them.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {atCap && (
          <p className="mb-4 text-sm text-muted-foreground">
            This project has the most owners it may have ({MAX_PROJECT_TEAMS}). Remove one before adding another.
          </p>
        )}
        {canManage && (
          <div className="mb-4 flex items-start gap-2">
            <TeamPicker
              teams={addableTeams}
              selectedIds={selectedTeamIds}
              room={room}
              open={isPickerOpen}
              onOpenChange={setIsPickerOpen}
              onToggle={toggleTeam}
            />
            <Button
              onClick={addSelectedTeams}
              disabled={selectedTeamIds.length === 0 || addTeamsMutation.isPending}
            >
              {addTeamsMutation.isPending ? 'Adding...' : 'Add'}
            </Button>
          </div>
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
