import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { jwtDecode } from 'jwt-decode'

import { setLogoutCallback } from '@/api/client'
import { userApi } from '@/api/users'
import { logger } from '@/lib/logger'

import { AuthContext } from './auth-context'

interface DecodedToken {
  exp: number
  iat: number
  sub: string
  permissions: string[]
  type: string
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [permissions, setPermissions] = useState<string[]>([])
  const navigate = useNavigate()

  const logout = useCallback(() => {
    localStorage.removeItem('token')
    localStorage.removeItem('refresh_token')
    setIsAuthenticated(false)
    setPermissions([])
    navigate('/login')
  }, [navigate])

  const hasPermission = useCallback((permission: string) => {
    return permissions.includes('*') || permissions.includes(permission)
  }, [permissions])

  useEffect(() => {
    setLogoutCallback(logout)

    const initAuth = async () => {
      const token = localStorage.getItem('token')
      if (!token) {
        setIsAuthenticated(false)
        setIsLoading(false)
        return
      }

      try {
        const decoded: DecodedToken = jwtDecode(token)
        setPermissions(decoded.permissions || [])
        await userApi.getMe()
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
  }, [logout])

  const login = useCallback((accessToken: string, refreshToken: string, skipNavigation = false) => {
    localStorage.setItem('token', accessToken)
    localStorage.setItem('refresh_token', refreshToken)

    try {
      const decoded: DecodedToken = jwtDecode(accessToken)
      const perms = decoded.permissions || []
      setPermissions(perms)

      // Check if this is a limited token for 2FA setup
      if (perms.length === 1 && perms[0] === 'auth:setup_2fa') {
        setIsAuthenticated(true)
        if (!skipNavigation) {
          navigate('/setup-2fa')
        }
        return
      }
    } catch (e) {
      logger.error('Failed to decode token on login', e)
    }

    setIsAuthenticated(true)
    if (!skipNavigation) {
      navigate('/dashboard')
    }
  }, [navigate])

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        login,
        logout,
        isLoading,
        permissions,
        hasPermission,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}
