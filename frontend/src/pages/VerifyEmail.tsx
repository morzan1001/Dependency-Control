import { useEffect } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { CheckCircle2 } from 'lucide-react'
import { getErrorMessage } from '@/lib/utils'

interface VerifyEmailProps {
  verifyToken: (token: string) => Promise<{ message: string }>
}

export default function VerifyEmail({ verifyToken }: Readonly<VerifyEmailProps>) {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const { mutate: verify, isSuccess, error, data } = useMutation({ mutationFn: verifyToken })

  useEffect(() => {
    if (token) {
        verify(token)
    }
  }, [token, verify])

  if (!token || error) {
    return (
      <div className="flex h-screen items-center justify-center bg-muted/50">
        <Card className="w-[350px]">
          <CardHeader className="text-center">
            <CardTitle className="text-destructive">Error</CardTitle>
            <CardDescription role="alert">{token ? getErrorMessage(error) : 'No verification token provided.'}</CardDescription>
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
          <div className="flex justify-center mb-4">
            {isSuccess ? <CheckCircle2 className="h-12 w-12 text-success" /> : <Skeleton className="h-12 w-12 rounded-full" />}
          </div>
          <CardTitle>Email Verification</CardTitle>
          <CardDescription>
            {isSuccess ? 'Your email has been verified!' : 'Verifying your email...'}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center">
            {isSuccess && <output className="text-sm text-success">{data.message}</output>}
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
