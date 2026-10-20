import { useInstanceNames } from '@/hooks/queries/use-instances'
import { useProjectDetails } from '@/hooks/queries/use-projects'
import { OwningTeamsCell } from '@/components/teams/OwningTeamsCell'
import { PROVIDER_LABEL, sourceLabel } from '@/lib/team-binding'
import { cn } from '@/lib/utils'
import type { Project } from '@/types/project'

function vcsLink(project: Project) {
  if (project.github_instance_id) {
    return { provider: 'github', instanceId: project.github_instance_id, kind: 'repository', externalId: project.github_repository_id } as const
  }
  if (project.gitlab_instance_id) {
    return { provider: 'gitlab', instanceId: project.gitlab_instance_id, kind: 'project', externalId: project.gitlab_project_id } as const
  }
  return undefined
}

const TRAITS = {
  // OwningTeamsCell lays out the first team and a count, so owners behind +N tell no namesake apart.
  owner: (project: Project) => {
    const teams = project.teams ?? []
    return teams.length ? `${teams[0].name} +${teams.length - 1}` : ''
  },
  path: (project: Project) => project.gitlab_project_path ?? project.github_repository_path ?? '',
  instance: (project: Project, instanceNames: ReadonlyMap<string, string>) => {
    const link = vcsLink(project)
    return link ? sourceLabel(link.provider, link.instanceId, instanceNames) : ''
  },
  repository: (project: Project) => {
    const link = vcsLink(project)
    return link?.externalId ? `${PROVIDER_LABEL[link.provider]} ${link.kind} ${link.externalId}` : ''
  },
}

type Trait = keyof typeof TRAITS

// CI names a project after its path, so namesakes often share path and team and differ only by where they live.
function distinguishingTrait(namesakes: readonly Project[], instanceNames: ReadonlyMap<string, string>): Trait {
  const spread = (trait: Trait) => new Set(namesakes.map((project) => TRAITS[trait](project, instanceNames))).size
  return (Object.keys(TRAITS) as Trait[]).reduce((best, trait) => (spread(trait) > spread(best) ? trait : best), 'owner')
}

export function ProjectOwner({ project, namesakes }: Readonly<{ project: Project; namesakes: readonly Project[] }>) {
  const instanceNames = useInstanceNames(new Set(namesakes.map((namesake) => vcsLink(namesake)?.instanceId)).size > 1)
  const trait = distinguishingTrait(namesakes, instanceNames)
  // Where owners tell namesakes apart, a teamless one says more by its path than by Unassigned.
  const shown = trait === 'owner' && !project.teams?.length && TRAITS.path(project) ? 'path' : trait
  const label = TRAITS[shown](project, instanceNames)
  return (
    <span className="min-w-0 max-w-[50%] shrink-0 text-xs text-muted-foreground">
      {shown === 'owner' || !label ? (
        <OwningTeamsCell teams={project.teams} />
      ) : (
        <span className={cn('block truncate', shown === 'path' && 'font-mono')} title={label}>{label}</span>
      )}
    </span>
  )
}

export function ProjectOwnerById({ projectId, namesakeIds = [] }: Readonly<{ projectId: string; namesakeIds?: readonly string[] }>) {
  const namesakes = useProjectDetails(namesakeIds)
  const project = namesakes.find((namesake) => namesake.id === projectId)
  return project ? <ProjectOwner project={project} namesakes={namesakes} /> : null
}

// A chart keys its bars by project id, so its tooltip resolves the name and adds the owner of a namesake.
export function ChartProjectLabel({ projectId, names, namesakes }: Readonly<{ projectId: string; names: ReadonlyMap<string, string>; namesakes: ReadonlyMap<string, string[]> }>) {
  const name = names.get(projectId) ?? ''
  return namesakes.has(name) ? (
    <span className="flex items-center gap-2">
      {name}
      <ProjectOwnerById projectId={projectId} namesakeIds={namesakes.get(name)} />
    </span>
  ) : name
}
