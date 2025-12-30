import React from 'react'
import { Navigate } from 'react-router-dom'

import { useAuth } from './useAuth'

export function RequirePermission({
  children,
  permission,
}: {
  children: React.ReactNode
  permission: string | string[]
}) {
  const { hasPermission, isLoading } = useAuth()

  if (isLoading) {
    return null
  }

  const hasAccess = Array.isArray(permission)
    ? permission.some((p) => hasPermission(p))
    : hasPermission(permission)

  if (!hasAccess) {
    return <Navigate to="/dashboard" replace />
  }

  return <>{children}</>
}
