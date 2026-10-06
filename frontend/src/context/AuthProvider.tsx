import React, { useEffect, useState, useCallback, useMemo, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { jwtDecode } from 'jwt-decode'

import { authApi } from '@/api/auth'
import { setLogoutCallback } from '@/api/client'
import { userApi } from '@/api/users'
import { LOGIN_RETURN_KEY } from '@/lib/constants'
import { logger } from '@/lib/logger'
import { hasPermission as checkPermission } from '@/lib/permissions'

import { AuthContext } from './auth-context'

interface DecodedToken {
  exp: number
  iat: number
  sub: string
  permissions: string[]
  type: string
}

export function AuthProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [permissions, setPermissions] = useState<string[]>([])
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const logout = useCallback(async () => {
    // Revoked while the tokens are still stored, so the interceptor can refresh an expired access token first.
    if (localStorage.getItem('token')) {
      await authApi.logout().catch((error: unknown) => logger.warn('Server logout failed', error))
    }
    localStorage.removeItem('token')
    localStorage.removeItem('refresh_token')
    queryClient.clear()
    setIsAuthenticated(false)
    setPermissions([])
    navigate('/login')
  }, [navigate, queryClient])

  const hasPermission = useCallback((permission: string) => {
    return checkPermission(permissions, permission)
  }, [permissions])

  // Ref keeps the latest logout so the mount-only init effect stays stable across navigation.
  const logoutRef = useRef(logout)
  useEffect(() => {
    logoutRef.current = logout
  }, [logout])

  useEffect(() => {
    setLogoutCallback(() => logoutRef.current())

    const initAuth = async () => {
      const token = localStorage.getItem('token')
      if (!token) {
        setIsAuthenticated(false)
        setIsLoading(false)
        return
      }

      try {
        const me = await userApi.getMe()
        setPermissions(me.permissions)
        setIsAuthenticated(true)
      } catch (error) {
        logger.error('Auth init failed', error)
        setIsAuthenticated(false)
        setPermissions([])
      } finally {
        setIsLoading(false)
      }
    }

    initAuth()
    // Mount-only: logout is read via logoutRef so navigation identity changes don't re-fire getMe.
  }, [])

  const login = useCallback((accessToken: string, refreshToken: string) => {
    localStorage.setItem('token', accessToken)
    localStorage.setItem('refresh_token', refreshToken)

    try {
      const decoded: DecodedToken = jwtDecode(accessToken)
      const perms = decoded.permissions || []
      setPermissions(perms)

      // Limited token issued for 2FA setup only.
      if (perms.length === 1 && perms[0] === 'auth:setup_2fa') {
        setIsAuthenticated(true)
        navigate('/setup-2fa', { replace: true })
        return
      }
    } catch (e) {
      logger.error('Failed to decode token on login', e)
    }

    setIsAuthenticated(true)
    const returnTo = sessionStorage.getItem(LOGIN_RETURN_KEY) ?? '/dashboard'
    sessionStorage.removeItem(LOGIN_RETURN_KEY)
    navigate(returnTo, { replace: true })
  }, [navigate])

  const contextValue = useMemo(() => ({
    isAuthenticated,
    login,
    logout,
    isLoading,
    permissions,
    hasPermission,
  }), [isAuthenticated, login, logout, isLoading, permissions, hasPermission])

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  )
}
