/**
 * Team Role Utilities
 *
 * Pure functions that mirror the backend's check_team_access() logic
 * to determine what actions a user can perform on a team.
 * Roles: member, admin (owner role was removed).
 */

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
  if (globalPermissions?.includes('team:read_all')) return true;

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

/** Manage team webhooks: team admin OR global webhook:create */
export function canManageTeamWebhooks(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isTeamAdmin(team, userId, globalPermissions)
    || globalPermissions.includes('webhook:create');
}
