import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { useResendVerificationEmail } from '@/hooks/queries/use-auth'
import { Link } from 'react-router-dom'
import { getErrorMessage } from "@/lib/utils"

export default function ResendVerification() {
  const [message, setMessage] = useState<string | null>(null)
  
  const resendMutation = useResendVerificationEmail()
  const isLoading = resendMutation.isPending
  const error = resendMutation.error ? getErrorMessage(resendMutation.error) : null

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setMessage(null)

    const formData = new FormData(event.currentTarget)
    const email = formData.get('email') as string
    
    resendMutation.mutate(email, {
        onSuccess: (data) => {
            setMessage(data.message)
        }
    })
  }

  return (
    <div className="flex h-screen items-center justify-center bg-muted/50">
      <Card className="w-[350px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <img src="/logo.png" alt="Logo" className="h-12 w-auto object-contain" />
          </div>
          <CardTitle>Resend Verification</CardTitle>
          <CardDescription>
            Enter your email to receive a new verification link.
          </CardDescription>
        </CardHeader>
        <form onSubmit={onSubmit}>
          <CardContent>
            <div className="grid w-full items-center gap-4">
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="email">Email</Label>
                <Input id="email" name="email" type="email" required />
              </div>
              {message && (
                <div className="text-sm text-success">
                  {message}
                </div>
              )}
              {error && (
                <div className="text-sm text-destructive">
                  {error}
                </div>
              )}
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-2">
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Sending..." : "Send Verification Email"}
            </Button>
            <div className="text-sm text-center text-muted-foreground">
              <Link to="/login" className="text-primary hover:underline">Back to Login</Link>
            </div>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
