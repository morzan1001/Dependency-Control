/**
 * Project Role Utilities
 *
 * Pure functions that mirror the backend's check_project_access() logic
 * (backend/app/api/v1/helpers/projects.py:64-139) to determine what
 * actions a user can perform on a project based on their project role
 * and global permissions.
 */

import { Project } from '@/types/project';

export const PROJECT_ROLE_VIEWER = 'viewer';
export const PROJECT_ROLE_EDITOR = 'editor';
export const PROJECT_ROLE_ADMIN = 'admin';

const ROLE_HIERARCHY: string[] = [PROJECT_ROLE_VIEWER, PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN];

/**
 * Get the effective project role for a user.
 * Returns 'owner' for the project owner, the member role string, or null if not a member.
 */
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

/**
 * Check if a user meets a minimum project role requirement.
 * Owner always satisfies any role. project:read_all acts as superuser bypass.
 */
export function hasProjectRole(
  project: Project,
  userId: string,
  requiredRole: 'viewer' | 'editor' | 'admin',
  globalPermissions?: string[]
): boolean {
  if (globalPermissions?.includes('project:read_all')) return true;

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
