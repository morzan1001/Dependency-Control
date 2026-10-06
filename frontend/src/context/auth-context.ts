import { createContext } from 'react'

export interface AuthContextType {
  isAuthenticated: boolean
  login: (accessToken: string, refreshToken: string) => void
  logout: (explicit?: boolean) => void
  isLoading: boolean
  permissions: string[]
  hasPermission: (permission: string) => boolean
  signedOut: boolean
}

export const AuthContext = createContext<AuthContextType | null>(null)
