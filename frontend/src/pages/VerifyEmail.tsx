import { useEffect } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { useVerifyEmail } from '@/hooks/queries/use-auth'
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { CheckCircle2, XCircle } from 'lucide-react'

export default function VerifyEmail() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const verifyEmailMutation = useVerifyEmail()
  
  const status = verifyEmailMutation.isPending ? 'loading' : verifyEmailMutation.isSuccess ? 'success' : verifyEmailMutation.isError ? 'error' : 'loading'
  const message = verifyEmailMutation.error ? (verifyEmailMutation.error as any).response?.data?.detail || 'Failed to verify email.' : verifyEmailMutation.data?.message || ''

  useEffect(() => {
    if (token) {
        verifyEmailMutation.mutate(token)
    }
  }, [token])

  const errorMessage = !token ? 'No verification token provided.' : message
  const displayStatus = !token ? 'error' : status

  return (
    <div className="flex h-screen items-center justify-center bg-muted/50">
      <Card className="w-[350px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            {displayStatus === 'loading' && <Skeleton className="h-12 w-12 rounded-full" />}
            {displayStatus === 'success' && <CheckCircle2 className="h-12 w-12 text-green-500" />}
            {displayStatus === 'error' && <XCircle className="h-12 w-12 text-destructive" />}
          </div>
          <CardTitle>Email Verification</CardTitle>
          <CardDescription>
            {displayStatus === 'loading' && 'Verifying your email...'}
            {displayStatus === 'success' && 'Your email has been verified!'}
            {displayStatus === 'error' && 'Verification failed.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center">
            {displayStatus === 'error' && <p className="text-sm text-destructive">{errorMessage}</p>}
            {displayStatus === 'success' && <p className="text-sm text-muted-foreground">{errorMessage}</p>}
        </CardContent>
        <CardFooter className="flex justify-center">
          <Button asChild>
            <Link to="/login">Go to Login</Link>
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}
