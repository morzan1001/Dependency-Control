// Mirrors the backend's team gates (check_team_access, get_team_with_access and the team webhook
// gates) so the UI offers only what the API allows. Roles: member, admin.

import { Team } from '@/types/team';

function teamRole(team: Team, userId: string): string | null {
  return team.members?.find(m => m.user_id === userId)?.role ?? null;
}

/** Update team (name, description): team admin OR global team:update */
export function canUpdateTeam(team: Team, userId: string, globalPermissions: string[]): boolean {
  return teamRole(team, userId) === 'admin' || globalPermissions.includes('team:update');
}

/** Delete team: team admin OR global team:delete */
export function canDeleteTeam(team: Team, userId: string, globalPermissions: string[]): boolean {
  return teamRole(team, userId) === 'admin' || globalPermissions.includes('team:delete');
}

/** Add / update / remove members: the same gate as updating the team */
export const canManageTeamMembers = canUpdateTeam;

function canWriteTeamWebhook(
  team: Team,
  userId: string,
  globalPermissions: string[],
  webhookPermission: string
): boolean {
  const role = teamRole(team, userId);
  return role === 'admin'
    || (globalPermissions.includes(webhookPermission) && (role !== null || globalPermissions.includes('team:update')));
}

/** Create team webhook: team admin OR webhook:create plus (membership OR global team:update) */
export function canCreateTeamWebhooks(team: Team, userId: string, globalPermissions: string[]): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:create');
}

/** Delete team webhook: team admin OR webhook:delete plus (membership OR global team:update) */
export function canDeleteTeamWebhooks(team: Team, userId: string, globalPermissions: string[]): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:delete');
}

/** Update or test team webhook: team admin OR webhook:update plus (membership OR global team:update) */
export function canUpdateTeamWebhooks(team: Team, userId: string, globalPermissions: string[]): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:update');
}
