import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { login as apiLogin, getPublicConfig } from '@/lib/api'
import { useAuth } from '@/context/AuthContext'
import { AxiosError } from 'axios'
import { Link, useLocation } from 'react-router-dom'

export default function Login() {
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showOTP, setShowOTP] = useState(false)
  const [showResendLink, setShowResendLink] = useState(false)
  const [signupEnabled, setSignupEnabled] = useState(false)
  const [oidcConfig, setOidcConfig] = useState<{ enabled: boolean, providerName: string }>({ enabled: false, providerName: 'GitLab' })
  
  // Form State
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const { login } = useAuth()
  const location = useLocation()
  const message = location.state?.message

  useEffect(() => {
    getPublicConfig().then(config => {
      setSignupEnabled(config.allow_public_registration)
      setOidcConfig({
        enabled: config.oidc_enabled || false,
        providerName: config.oidc_provider_name || 'GitLab'
      })
    }).catch(console.error)
  }, [])

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setIsLoading(true)
    setError(null)
    setShowResendLink(false)

    const formData = new FormData(event.currentTarget)
    const otp = formData.get('otp') as string

    try {
      const data = await apiLogin(username, password, otp)
      login(data.access_token, data.refresh_token)
    } catch (err) {
      const error = err as AxiosError<{ detail: string }>
      console.error('Login error:', error);
      
      if (error.response) {
        console.log('Error status:', error.response.status);
        console.log('Error data:', error.response.data);
        
        if (error.response.status === 401 && error.response.data?.detail === '2FA required') {
          setShowOTP(true)
          setError('Please enter your 2FA code')
          return;
        }

        if (error.response.status === 401 && error.response.data?.detail === 'Email not verified') {
          setError('Email not verified.')
          setShowResendLink(true)
          return;
        }
        
        // Handle cases where data might not be JSON (e.g. Pomerium HTML response)
        if (typeof error.response.data === 'string') {
             setError(`Login failed: Server returned ${error.response.status}. Check console for details.`);
        } else {
             setError(error.response.data?.detail || `Login failed with status ${error.response.status}`);
        }
      } else {
        setError('Network error or server unreachable');
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-muted/50">
      <Card className="w-[350px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <img src="/logo.png" alt="Logo" className="h-12 w-auto object-contain" />
          </div>
          <CardTitle>Dependency Control</CardTitle>
          <CardDescription>
            Enter your credentials to access the dashboard.
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
                  required 
                  disabled={showOTP} 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              {showOTP && (
                <div className="flex flex-col space-y-1.5 animate-accordion-down">
                  <Label htmlFor="otp">2FA Code</Label>
                  <Input id="otp" name="otp" type="text" placeholder="123456" required autoFocus />
                </div>
              )}
              {error && (
                <div className="text-sm text-destructive">
                  {error}
                  {showResendLink && (
                    <div className="mt-1">
                      <Link to="/resend-verification" className="underline hover:text-destructive/80">
                        Resend verification email
                      </Link>
                    </div>
                  )}
                </div>
              )}
              {message && (
                <div className="text-sm text-green-600">
                  {message}
                </div>
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
                  onClick={() => window.location.href = `${import.meta.env.VITE_API_URL || '/api/v1'}/auth/login/oidc/authorize`}
                >
                  {oidcConfig.providerName}
                </Button>
              </div>
            )}
          </CardContent>
          <CardFooter className="flex justify-between">
            {showOTP ? (
              <Button variant="ghost" type="button" onClick={() => setShowOTP(false)}>
                Cancel
              </Button>
            ) : (
              signupEnabled && (
                <Button variant="ghost" type="button" asChild>
                  <Link to="/signup">Sign Up</Link>
                </Button>
              )
            )}
            <Button type="submit" disabled={isLoading} className={!showOTP && !signupEnabled ? "ml-auto" : ""}>
              {isLoading ? "Logging in..." : (showOTP ? "Verify" : "Login")}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
