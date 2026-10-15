// Mirrors the backend's check_project_access() so the UI gates match the API.

import { Project } from '@/types/project';

export const PROJECT_ROLE_VIEWER = 'viewer';
export const PROJECT_ROLE_EDITOR = 'editor';
export const PROJECT_ROLE_ADMIN = 'admin';

const ROLE_HIERARCHY: string[] = [PROJECT_ROLE_VIEWER, PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN];

export function getUserProjectRole(
  project: Project,
  userId: string
): 'admin' | 'editor' | 'viewer' | null {
  const member = project.members?.find(m => m.user_id === userId);
  return ((member?.effective_role ?? member?.role) as 'admin' | 'editor' | 'viewer') ?? null;
}

// project:delete is no bypass here: it opens canDeleteProject alone.
export function hasProjectRole(
  project: Project,
  userId: string,
  requiredRole: 'viewer' | 'editor' | 'admin',
  globalPermissions?: string[]
): boolean {
  const isWriteRequest = requiredRole === 'editor' || requiredRole === 'admin';

  if (globalPermissions?.includes('project:update')) {
    return true;
  }

  if (!isWriteRequest && globalPermissions?.includes('project:read_all')) {
    return true;
  }

  const role = getUserProjectRole(project, userId);
  if (role === null) return false;
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

// isProjectAdmin gets no global permissions: project:update must not delete.
export function canDeleteProject(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId) || globalPermissions.includes('project:delete');
}

// isProjectAdmin already admits project:update, so a webhook permission only needs membership in any role.
function canWriteProjectWebhook(
  project: Project,
  userId: string,
  globalPermissions: string[],
  webhookPermission: string
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || (globalPermissions.includes(webhookPermission) && getUserProjectRole(project, userId) !== null);
}

export function canCreateProjectWebhook(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return canWriteProjectWebhook(project, userId, globalPermissions, 'webhook:create');
}

export function canDeleteProjectWebhook(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return canWriteProjectWebhook(project, userId, globalPermissions, 'webhook:delete');
}

export function canUpdateProjectWebhook(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return canWriteProjectWebhook(project, userId, globalPermissions, 'webhook:update');
}

// waiver:manage covers global waivers only.
export function canCreateProjectWaiver(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectEditor(project, userId, globalPermissions);
}

export function canDeleteProjectWaiver(
  project: Project,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isProjectAdmin(project, userId, globalPermissions)
    || globalPermissions.includes('waiver:delete');
}
