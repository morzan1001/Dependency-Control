import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { useAuth } from '@/context/useAuth'
import { useValidateInvitation, useAcceptInvitation, useLogin } from '@/hooks/queries/use-auth'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { Skeleton } from '@/components/ui/skeleton'
import { getErrorMessage } from '@/lib/utils'

export default function AcceptInvite() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const [error, setError] = useState<string | null>(!token ? "Invalid invitation link." : null)
  const [isLoading, setIsLoading] = useState(!!token)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [email, setEmail] = useState<string | null>(null)
  const navigate = useNavigate()
  const { login } = useAuth()
  
  const { mutate: validate } = useValidateInvitation();
  const acceptMutation = useAcceptInvitation();
  const loginMutation = useLogin();

  useEffect(() => {
    if (!token) return

    validate(token, {
       onSuccess: (data) => {
         setEmail(data.email)
         setIsLoading(false)
       },
       onError: (err) => {
         setError(getErrorMessage(err))
         setIsLoading(false)
       }
    })
  }, [token, validate])

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!token) return

    setIsSubmitting(true)
    setError(null)

    const formData = new FormData(event.currentTarget)
    const username = formData.get('username') as string
    const password = formData.get('password') as string
    const confirmPassword = formData.get('confirmPassword') as string

    if (password !== confirmPassword) {
      setError("Passwords do not match")
      setIsSubmitting(false)
      return
    }

    acceptMutation.mutate({ token, username, password }, {
       onSuccess: () => {
         // Auto-login
         loginMutation.mutate({ username, password }, {
             onSuccess: (data) => {
                 login(data.access_token, data.refresh_token)
             },
             onError: () => {
                 navigate('/login', { state: { message: 'Account created successfully. Please login.' } })
             }
         })
       },
       onError: (err) => {
          setError(getErrorMessage(err))
          setIsSubmitting(false)
       }
    })
  }

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-muted/50">
        <Card className="w-[350px]">
          <CardHeader>
            <Skeleton className="h-12 w-12 rounded-full mx-auto mb-2" />
            <Skeleton className="h-6 w-32 mx-auto mb-2" />
            <Skeleton className="h-4 w-48 mx-auto" />
          </CardHeader>
          <CardContent className="space-y-4">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error && !email) {
    return (
      <div className="flex h-screen items-center justify-center bg-muted/50">
        <Card className="w-[350px]">
          <CardHeader className="text-center">
            <CardTitle className="text-destructive">Error</CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardFooter className="flex justify-center">
            <Button asChild>
              <Link to="/login">Go to Login</Link>
            </Button>
          </CardFooter>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex h-screen items-center justify-center bg-muted/50">
      <Card className="w-[350px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <img src="/logo.png" alt="Logo" className="h-12 w-auto object-contain" />
          </div>
          <CardTitle>Accept Invitation</CardTitle>
          <CardDescription>
            Create your account for {email}
          </CardDescription>
        </CardHeader>
        <form onSubmit={onSubmit}>
          <CardContent>
            <div className="grid w-full items-center gap-4">
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="email">Email</Label>
                <Input id="email" value={email || ''} disabled />
              </div>
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="username">Username</Label>
                <Input id="username" name="username" required />
              </div>
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <Input id="password" name="password" type="password" required />
              </div>
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="confirmPassword">Confirm Password</Label>
                <Input id="confirmPassword" name="confirmPassword" type="password" required />
              </div>
              {error && (
                <div className="text-sm text-destructive">
                  {error}
                </div>
              )}
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-2">
            <Button type="submit" className="w-full" disabled={isSubmitting}>
              {isSubmitting ? "Creating account..." : "Create Account"}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
