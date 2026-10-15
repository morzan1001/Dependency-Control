// Mirrors the backend's team gates (check_team_access, get_team_with_access, team webhook gates).

import { Team } from '@/types/team';

function teamRole(team: Team, userId: string): string | null {
  return team.members?.find(m => m.user_id === userId)?.role ?? null;
}

export function canUpdateTeam(team: Team, userId: string, globalPermissions: string[]): boolean {
  return teamRole(team, userId) === 'admin' || globalPermissions.includes('team:update');
}

export function canDeleteTeam(team: Team, userId: string, globalPermissions: string[]): boolean {
  return teamRole(team, userId) === 'admin' || globalPermissions.includes('team:delete');
}

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

export function canCreateTeamWebhooks(team: Team, userId: string, globalPermissions: string[]): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:create');
}

export function canDeleteTeamWebhooks(team: Team, userId: string, globalPermissions: string[]): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:delete');
}

export function canUpdateTeamWebhooks(team: Team, userId: string, globalPermissions: string[]): boolean {
  return canWriteTeamWebhook(team, userId, globalPermissions, 'webhook:update');
}
