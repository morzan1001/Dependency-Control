import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { useLogin } from '@/hooks/queries/use-auth'
import { usePublicConfig } from '@/hooks/queries/use-system'
import { useAuth } from '@/context/useAuth'
import { Link, useLocation } from 'react-router-dom'
import { getErrorMessage } from '@/lib/utils'

export default function Login() {
  const location = useLocation()
  const [error, setError] = useState<string | null>(location.state?.error ?? null)
  const [showOTP, setShowOTP] = useState(false)
  const [showResendLink, setShowResendLink] = useState(false)
  
  const { data: config } = usePublicConfig();
  const signupEnabled = config?.allow_public_registration || false;
  const oidcConfig = {
    enabled: config?.oidc_enabled || false,
    providerName: config?.oidc_provider_name || 'GitLab'
  }
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const { login } = useAuth()
  const message = location.state?.message
  const loginMutation = useLogin();
  const isLoading = loginMutation.isPending

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setShowResendLink(false)

    const formData = new FormData(event.currentTarget)
    const otp = formData.get('otp') as string

    loginMutation.mutate({ username, password, otp }, {
      onSuccess: (data) => {
        login(data.access_token, data.refresh_token)
      },
      onError: (err) => {
        const axiosError = err as { response?: { status?: number; data?: { detail?: string } | string } }

        if (axiosError.response?.status === 401) {
          const detail = typeof axiosError.response.data === 'object'
            ? axiosError.response.data?.detail
            : undefined

          if (detail === '2FA required') {
            setShowOTP(true)
            return
          }

          if (detail === 'Email not verified') {
            setError('Email not verified.')
            setShowResendLink(true)
            return
          }
        }

        setError(getErrorMessage(err))
      }
    })
  }

  return (
    <div className="flex h-screen items-center-safe justify-center bg-muted/50">
      <Card className="w-[350px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <img src="/logo.png" alt="Logo" className="h-12 w-auto object-contain" />
          </div>
          <CardTitle>Dependency Control</CardTitle>
          <CardDescription>
            {showOTP ? 'Enter your 2FA code.' : 'Enter your credentials to access the dashboard.'}
          </CardDescription>
        </CardHeader>
        <form onSubmit={onSubmit}>
          <CardContent>
            <div className="grid w-full items-center gap-4">
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  name="username"
                  autoComplete="username"
                  required
                  disabled={showOTP}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  disabled={showOTP}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                {config?.password_reset_enabled && (
                  <Link to="/forgot-password" className="self-end text-sm text-primary hover:underline">
                    Forgot password?
                  </Link>
                )}
              </div>
              {showOTP && (
                <div className="flex flex-col space-y-1.5 animate-accordion-down">
                  <Label htmlFor="otp">2FA Code</Label>
                  <Input
                    id="otp"
                    name="otp"
                    type="text"
                    placeholder="123456"
                    maxLength={6}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    required
                    autoFocus
                  />
                </div>
              )}
              {error && (
                <div role="alert" className="text-sm text-destructive">
                  {error}
                  {showResendLink && (
                    <div className="mt-1">
                      <Link to="/resend-verification" className="text-primary hover:underline">
                        Resend verification email
                      </Link>
                    </div>
                  )}
                </div>
              )}
              {message && (
                <output className="text-sm text-success">
                  {message}
                </output>
              )}
            </div>

            {oidcConfig.enabled && (
              <div className="mt-4">
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-background px-2 text-muted-foreground">
                      Or continue with
                    </span>
                  </div>
                </div>
                <Button 
                  variant="outline" 
                  type="button" 
                  className="w-full mt-4"
                  onClick={() => globalThis.location.href = `${import.meta.env.VITE_API_URL || '/api/v1'}/login/oidc/authorize`}
                >
                  {oidcConfig.providerName}
                </Button>
              </div>
            )}
          </CardContent>
          <CardFooter className="flex flex-col gap-2">
            <Button type="submit" className="w-full" disabled={isLoading}>
              {(() => {
                if (isLoading) return "Logging in..."
                if (showOTP) return "Verify"
                return "Login"
              })()}
            </Button>
            {showOTP && (
              <div className="text-sm text-center text-muted-foreground">
                <button
                  type="button"
                  className="text-primary hover:underline"
                  onClick={() => {
                    setShowOTP(false)
                    setError(null)
                  }}
                >
                  Cancel
                </button>
              </div>
            )}
            {!showOTP && signupEnabled && (
              <div className="text-sm text-center text-muted-foreground">
                Don't have an account? <Link to="/signup" className="text-primary hover:underline">Sign Up</Link>
              </div>
            )}
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
