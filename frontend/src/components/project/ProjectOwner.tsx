import { useProject } from '@/hooks/queries/use-projects'
import { OwningTeamsCell } from '@/components/teams/OwningTeamsCell'
import type { Project } from '@/types/project'

export function ProjectOwner({ project }: Readonly<{ project: Project }>) {
  const repositoryPath = project.gitlab_project_path ?? project.github_repository_path
  if (!project.teams?.length && repositoryPath) {
    return <span className="truncate font-mono text-xs text-muted-foreground">{repositoryPath}</span>
  }
  return (
    <span className="min-w-0 max-w-[50%] text-xs text-muted-foreground">
      <OwningTeamsCell teams={project.teams} />
    </span>
  )
}

export function ProjectOwnerById({ projectId }: Readonly<{ projectId: string }>) {
  const { data: project } = useProject(projectId)
  return project ? <ProjectOwner project={project} /> : null
}
