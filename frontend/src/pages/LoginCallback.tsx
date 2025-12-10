import { useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { Spinner } from '@/components/ui/spinner'

export default function LoginCallback() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuth()

  useEffect(() => {
    const hash = location.hash
    if (!hash) {
      navigate('/login', { state: { error: 'No token provided' } })
      return
    }

    const params = new URLSearchParams(hash.substring(1)) // Remove #
    const accessToken = params.get('access_token')
    const refreshToken = params.get('refresh_token')

    if (accessToken && refreshToken) {
      login(accessToken, refreshToken)
    } else {
      navigate('/login', { state: { error: 'Invalid token response' } })
    }
  }, [location, navigate, login])

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <Spinner className="h-8 w-8" />
        <p className="text-muted-foreground">Completing login...</p>
      </div>
    </div>
  )
}
