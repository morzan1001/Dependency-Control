// Mirrors the backend's team gates (check_team_access, get_team_with_access and the team webhook
// gates) so the UI offers only what the API allows. Roles: member, admin.

import { Team } from '@/types/team';

export const TEAM_ROLE_MEMBER = 'member';
export const TEAM_ROLE_ADMIN = 'admin';

const ROLE_HIERARCHY: string[] = [TEAM_ROLE_MEMBER, TEAM_ROLE_ADMIN];

export function getUserTeamRole(
  team: Team,
  userId: string
): 'admin' | 'member' | null {
  const member = team.members?.find(m => m.user_id === userId);
  return (member?.role as 'admin' | 'member') ?? null;
}

export function hasTeamRole(
  team: Team,
  userId: string,
  requiredRole: 'member' | 'admin',
  globalPermissions?: string[]
): boolean {
  if (requiredRole === TEAM_ROLE_MEMBER && globalPermissions?.includes('team:read_all')) return true;

  const role = getUserTeamRole(team, userId);
  if (role === null) return false;
  return ROLE_HIERARCHY.indexOf(role) >= ROLE_HIERARCHY.indexOf(requiredRole);
}

export function isTeamAdmin(
  team: Team,
  userId: string,
  globalPermissions?: string[]
): boolean {
  return hasTeamRole(team, userId, TEAM_ROLE_ADMIN, globalPermissions);
}

/** Update team (name, description): team admin OR global team:update */
export function canUpdateTeam(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isTeamAdmin(team, userId, globalPermissions)
    || globalPermissions.includes('team:update');
}

/** Delete team: team admin OR global team:delete */
export function canDeleteTeam(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isTeamAdmin(team, userId, globalPermissions)
    || globalPermissions.includes('team:delete');
}

/** Add / update / remove members: team admin OR global team:update */
export function canManageTeamMembers(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isTeamAdmin(team, userId, globalPermissions)
    || globalPermissions.includes('team:update');
}

function canWriteTeamWebhook(
  team: Team,
  userId: string,
  globalPermissions: string[],
  webhookPermission: string
): boolean {
  return isTeamAdmin(team, userId, globalPermissions)
    || (globalPermissions.includes(webhookPermission)
      && (getUserTeamRole(team, userId) !== null || globalPermissions.includes('team:update')));
}

/** Create team webhook: team admin OR webhook:create plus (membership OR global team:update) */
export function canCreateTeamWebhooks(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:create');
}

/** Delete team webhook: team admin OR webhook:delete plus (membership OR global team:update) */
export function canDeleteTeamWebhooks(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:delete');
}

/** Update or test team webhook: team admin OR webhook:update plus (membership OR global team:update) */
export function canUpdateTeamWebhooks(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:update');
}
