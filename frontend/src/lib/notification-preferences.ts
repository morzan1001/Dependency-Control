import type { Project } from '@/types/project'

function nonEmpty(prefs?: Record<string, string[]>): Record<string, string[]> | undefined {
  return prefs && Object.keys(prefs).length > 0 ? prefs : undefined
}

/** The member's own project-level overrides, for admins and everyone else alike. */
export function memberPreferences(project: Project, userId: string): Record<string, string[]> | undefined {
  return nonEmpty(project.members?.find(m => m.user_id === userId)?.notification_preferences)
}

/** What the notification service enforces: the preferences the enforcing admin last saved. */
export function enforcedPreferences(project: Project): Record<string, string[]> | undefined {
  return nonEmpty(project.enforced_notification_preferences)
}
