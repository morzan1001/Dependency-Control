import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/useAuth'
import { Skeleton } from '@/components/ui/skeleton'

export default function LoginCallback() {
  const navigate = useNavigate()
  const { login, isAuthenticated } = useAuth()
  const processedRef = useRef(false)

  useEffect(() => {
    if (processedRef.current) return
    
    const hash = window.location.hash
    if (!hash) {
      navigate('/login', { state: { error: 'No token provided' }, replace: true })
      return
    }

    const params = new URLSearchParams(hash.substring(1))
    const accessToken = params.get('access_token')
    const refreshToken = params.get('refresh_token')

    if (accessToken && refreshToken) {
      processedRef.current = true
      // Clear tokens from URL hash before proceeding
      window.history.replaceState(null, '', window.location.pathname)
      login(accessToken, refreshToken, true)
    } else {
      navigate('/login', { state: { error: 'Invalid token response' }, replace: true })
    }
  }, [navigate, login])

  useEffect(() => {
    if (processedRef.current && isAuthenticated) {
      navigate('/dashboard', { replace: true })
    }
  }, [isAuthenticated, navigate])

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <Skeleton className="h-12 w-12 rounded-full" />
        <p className="text-muted-foreground">Completing login...</p>
      </div>
    </div>
  )
}
