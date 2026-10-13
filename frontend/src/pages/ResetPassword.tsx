import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { useResetPassword } from '@/hooks/queries/use-auth'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

const INVALID_RESET_TOKEN = 'Invalid or expired reset token'

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(token ? null : 'The password reset link is invalid or missing a token.')
  const navigate = useNavigate()

  const resetPasswordMutation = useResetPassword();
  const isLoading = resetPasswordMutation.isPending
  const isDisabled = isLoading || !token
  const offersNewLink = !token || error === INVALID_RESET_TOKEN

  function onSubmit(event: React.SubmitEvent) {
    event.preventDefault()
    if (!token) return
    setError(null)

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match")
      return
    }

    resetPasswordMutation.mutate({ token, newPassword }, {
      onSuccess: () => {
        toast.success("Password Reset Successful", {
          description: "You can now login with your new password.",
        })
        navigate('/login')
      },
      onError: (err) => setError(getErrorMessage(err)),
    })
  }

  return (
    <div className="flex h-screen items-center justify-center bg-muted/50">
      <Card className="w-[350px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <img src="/logo.png" alt="Logo" className="h-12 w-auto object-contain" />
          </div>
          <CardTitle>Reset Password</CardTitle>
          <CardDescription>
            Enter your new password below.
          </CardDescription>
        </CardHeader>
        <form onSubmit={onSubmit}>
          <CardContent>
            <div className="grid w-full items-center gap-4">
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="new-password">New Password</Label>
                <Input
                  id="new-password"
                  type="password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  disabled={isDisabled}
                  required
                />
                <p className="text-xs text-muted-foreground">
                  Must be at least 8 characters and contain uppercase, lowercase, digit, and special character.
                </p>
              </div>
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={isDisabled}
                  required
                />
              </div>
              {error && (
                <div role="alert" className="text-sm text-destructive">
                  {error}
                  {offersNewLink && (
                    <div className="mt-1">
                      <Link to="/forgot-password" className="underline hover:text-destructive/80">
                        Request a new link
                      </Link>
                    </div>
                  )}
                </div>
              )}
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-2">
            <Button type="submit" className="w-full" disabled={isDisabled}>
              {isLoading ? "Resetting..." : "Reset Password"}
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
