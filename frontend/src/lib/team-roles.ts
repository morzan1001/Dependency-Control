/**
 * Team Role Utilities
 *
 * Pure functions that mirror the backend's check_team_access() and
 * get_team_with_access() logic (backend/app/api/v1/helpers/teams.py)
 * to determine what actions a user can perform on a team based on
 * their team role and global permissions.
 */

import { Team } from '@/types/team';

export const TEAM_ROLE_MEMBER = 'member';
export const TEAM_ROLE_ADMIN = 'admin';
export const TEAM_ROLE_OWNER = 'owner';

const ROLE_HIERARCHY: string[] = [TEAM_ROLE_MEMBER, TEAM_ROLE_ADMIN, TEAM_ROLE_OWNER];

/**
 * Get the user's role in the team.
 * Returns the role string or null if the user is not a member.
 */
export function getUserTeamRole(
  team: Team,
  userId: string
): 'owner' | 'admin' | 'member' | null {
  const member = team.members?.find(m => m.user_id === userId);
  return (member?.role as 'owner' | 'admin' | 'member') ?? null;
}

/**
 * Check if a user meets a minimum team role requirement.
 * team:read_all acts as superuser bypass (mirrors backend check_team_access).
 */
export function hasTeamRole(
  team: Team,
  userId: string,
  requiredRole: 'member' | 'admin' | 'owner',
  globalPermissions?: string[]
): boolean {
  if (globalPermissions?.includes('team:read_all')) return true;

  const role = getUserTeamRole(team, userId);
  if (role === null) return false;
  return ROLE_HIERARCHY.indexOf(role) >= ROLE_HIERARCHY.indexOf(requiredRole);
}

export function isTeamOwner(team: Team, userId: string): boolean {
  return getUserTeamRole(team, userId) === 'owner';
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

/** Delete team: team owner OR global team:delete */
export function canDeleteTeam(
  team: Team,
  userId: string,
  globalPermissions: string[]
): boolean {
  return isTeamOwner(team, userId)
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
