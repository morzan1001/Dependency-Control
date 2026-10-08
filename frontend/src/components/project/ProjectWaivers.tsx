import { useAuth } from '@/context/useAuth'
import { useProject } from '@/hooks/queries/use-projects'
import { useCurrentUser } from '@/hooks/queries/use-users'
import { canDeleteProjectWaiver, canCreateProjectWaiver } from '@/lib/project-roles'
import { WaiverList } from '@/components/waivers/WaiverList'

export function ProjectWaivers({ projectId }: Readonly<{ projectId: string }>) {
    const { permissions } = useAuth()
    const { data: project } = useProject(projectId)
    const { data: currentUser } = useCurrentUser()
    const canEdit = !!project && !!currentUser && canCreateProjectWaiver(project, currentUser.id, permissions)
    const canDelete = !!project && !!currentUser && canDeleteProjectWaiver(project, currentUser.id, permissions)

    return <WaiverList projectId={projectId} canEdit={canEdit} canDelete={canDelete} />
}
