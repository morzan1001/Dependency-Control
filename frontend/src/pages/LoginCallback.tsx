import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '@/api/auth'
import { useAuth } from '@/context/useAuth'
import { Skeleton } from '@/components/ui/skeleton'

const SSO_FAILED = 'Single sign-on failed. Please try again.'

const SSO_ERRORS = new Map([
  ['state_expired', 'The sign-in expired or was started in another browser. Please try again.'],
  ['idp_error', 'The identity provider did not complete the sign-in.'],
  ['no_email', 'The identity provider did not share your email address.'],
  ['local_user_blocked', 'This account signs in with a password. Please use the login form.'],
  ['inactive_user', 'This account is inactive.'],
  ['not_provisioned', 'No account exists for you yet. Please ask an administrator to create one.'],
  ['not_configured', 'Single sign-on is not set up on this server.'],
])

export default function LoginCallback() {
  const navigate = useNavigate()
  const { login, isAuthenticated } = useAuth()
  const processedRef = useRef(false)

  useEffect(() => {
    if (processedRef.current) return
    processedRef.current = true

    const error = new URLSearchParams(globalThis.location.hash.substring(1)).get('error')
    globalThis.history.replaceState(null, '', globalThis.location.pathname)
    const fail = (message: string) => navigate('/login', { state: { message }, replace: true })
    if (error !== null) {
      fail(SSO_ERRORS.get(error) ?? SSO_FAILED)
      return
    }
    authApi
      .exchangeOidcLogin()
      .then(({ access_token, refresh_token }) => login(access_token, refresh_token, true))
      .catch(() => fail(SSO_FAILED))
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
