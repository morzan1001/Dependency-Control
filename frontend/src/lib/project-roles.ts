// Mirrors the backend's check_project_access() so the UI gates match the API.

import { Project } from '@/types/project';

export const PROJECT_ROLE_VIEWER = 'viewer';
export const PROJECT_ROLE_EDITOR = 'editor';
export const PROJECT_ROLE_ADMIN = 'admin';

const ROLE_HIERARCHY: string[] = [PROJECT_ROLE_VIEWER, PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN];

// 'owner' for the project owner, the member role, or null if not a member.
export function getUserProjectRole(
  project: Project,
  userId: string
): 'owner' | 'admin' | 'editor' | 'viewer' | null {
  if (project.owner_id === userId) {
    return 'owner';
  }
  const member = project.members?.find(m => m.user_id === userId);
  return (member?.role as 'admin' | 'editor' | 'viewer') ?? null;
}

// Minimum-role gate: viewer = read, editor/admin = write. project:update or
// project:delete bypass membership for any request (write implies read);
// project:read_all grants read only; owner satisfies any role.
export function hasProjectRole(
  project: Project,
  userId: string,
  requiredRole: 'viewer' | 'editor' | 'admin',
  globalPermissions?: string[]
): boolean {
  const isWriteRequest = requiredRole === 'editor' || requiredRole === 'admin';

  if (
    globalPermissions?.includes('project:update') ||
    globalPermissions?.includes('project:delete')
  ) {
    return true;
  }

  if (!isWriteRequest && globalPermissions?.includes('project:read_all')) {
    return true;
  }

  const role = getUserProjectRole(project, userId);
  if (role === null) return false;
  if (role === 'owner') return true;
  return ROLE_HIERARCHY.indexOf(role) >= ROLE_HIERARCHY.indexOf(requiredRole);
}

export function isProjectAdmin(
  project: Project,
  userId: string,
  globalPermissions?: string[]
): boolean {
  return hasProjectRole(project, userId, PROJECT_ROLE_ADMIN, globalPermissions);
}

export function isProjectEditor(
  project: Project,
  userId: string,
  globalPermissions?: string[]
): boolean {
  return hasProjectRole(project, userId, PROJECT_ROLE_EDITOR, globalPermissions);
}

/** Project update (name, settings, etc.): project admin OR global project:update */
export function canUpdateProject(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('project:update');
}

/** Rotate API key: project admin OR global project:update */
export function canRotateApiKey(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('project:update');
}

/** Invite / update / remove members: project admin */
export function canManageProjectMembers(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions);
}

/** Delete project: project admin OR global project:delete */
export function canDeleteProject(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('project:delete');
}

/** Toggle enforce notification settings: project admin OR global project:update */
export function canEnforceNotifications(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('project:update');
}

/** Create project webhook: project admin OR global webhook:create */
export function canCreateProjectWebhook(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('webhook:create');
}

/** Delete project webhook: project admin OR global webhook:delete */
export function canDeleteProjectWebhook(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('webhook:delete');
}

/** Create waiver (project-scoped): project editor or higher OR global waiver:manage */
export function canCreateProjectWaiver(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectEditor(project, userId, globalPermissions)
    || globalPermissions.includes('waiver:manage');
}

/** Delete waiver (project-scoped): project admin OR global waiver:delete */
export function canDeleteProjectWaiver(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('waiver:delete');
}
