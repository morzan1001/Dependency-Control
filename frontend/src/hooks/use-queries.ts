/**
 * Custom React Query Hooks
 * 
 * Centralized hooks for commonly used queries to eliminate duplication
 * and ensure consistent query keys across the application.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { authApi } from '@/api/auth'
import { systemApi } from '@/api/system'

/**
 * Centralized query keys for consistency and easy invalidation
 */
export const queryKeys = {
  // User
  me: ['me'] as const,
  
  // System
  systemSettings: ['systemSettings'] as const,
  
  // Projects
  projects: ['projects'] as const,
  project: (id: string) => ['project', id] as const,
  projectScans: (id: string) => ['project', id, 'scans'] as const,
  projectFindings: (id: string) => ['project', id, 'findings'] as const,
  
  // Teams
  teams: ['teams'] as const,
  team: (id: string) => ['team', id] as const,
  
  // Scans
  scan: (id: string) => ['scan', id] as const,
  scanFindings: (scanId: string) => ['scan', scanId, 'findings'] as const,
  
  // Analytics
  recommendations: (projectId?: string, scanId?: string) => 
    ['recommendations', projectId, scanId] as const,
  
  // Dependencies
  dependencyMetadata: (component: string, version: string, type: string) =>
    ['dependency-metadata', component, version, type] as const,
} as const

/**
 * Hook to get current user data
 */
export function useCurrentUser() {
  return useQuery({
    queryKey: queryKeys.me,
    queryFn: authApi.getMe,
    staleTime: 5 * 60 * 1000, // 5 minutes
  })
}

/**
 * Hook to invalidate user data (after profile updates, etc.)
 */
export function useInvalidateCurrentUser() {
  const queryClient = useQueryClient()
  return () => queryClient.invalidateQueries({ queryKey: queryKeys.me })
}

/**
 * Hook to get system settings
 */
export function useSystemSettings() {
  return useQuery({
    queryKey: queryKeys.systemSettings,
    queryFn: systemApi.getSettings,
    staleTime: 10 * 60 * 1000, // 10 minutes - settings don't change often
  })
}

/**
 * Check if OIDC is enabled
 */
export function useIsOIDCEnabled() {
  const { data: settings } = useSystemSettings()
  return settings?.oidc_enabled ?? false
}

/**
 * Check if 2FA enforcement is enabled
 */
export function use2FAEnforcement() {
  const { data: settings } = useSystemSettings()
  return settings?.enforce_2fa ?? false
}

/**
 * Check if user has admin permission
 */
export function useIsAdmin() {
  const { data: user } = useCurrentUser()
  return user?.permissions?.includes('admin') ?? false
}

/**
 * Check if user has completed 2FA setup when required
 */
export function useIs2FACompliant() {
  const { data: user } = useCurrentUser()
  const enforce2FA = use2FAEnforcement()
  
  if (!enforce2FA) return true
  return user?.totp_enabled ?? false
}
