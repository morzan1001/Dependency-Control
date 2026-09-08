import type { Project } from '@/types/project'

function nonEmpty(prefs?: Record<string, string[]>): Record<string, string[]> | undefined {
  return prefs && Object.keys(prefs).length > 0 ? prefs : undefined
}

/** The member's own project-level overrides, for admins and everyone else alike. */
export function memberPreferences(project: Project, userId: string): Record<string, string[]> | undefined {
  return nonEmpty(project.members?.find(m => m.user_id === userId)?.notification_preferences)
}

/**
 * What the notification service enforces: the first admin member that has any preferences set.
 * Mirrors NotificationService._resolve_recipients, which picks the same member.
 */
export function enforcedPreferences(project: Project): Record<string, string[]> | undefined {
  return nonEmpty(
    project.members?.find(m => m.role === 'admin' && nonEmpty(m.notification_preferences))
      ?.notification_preferences,
  )
}
