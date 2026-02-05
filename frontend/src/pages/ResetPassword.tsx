import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { useResetPassword } from '@/hooks/queries/use-auth'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

export default function ResetPassword() {
  const [isLoading, setIsLoading] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  
  const token = searchParams.get('token')
  const resetPasswordMutation = useResetPassword();

  const validatePassword = (password: string) => {
    if (password.length < 8) return "Password must be at least 8 characters long";
    if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter";
    if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter";
    if (!/\d/.test(password)) return "Password must contain at least one digit";
    if (!/[!@#$%^&*(),.?":{}|<>\-_+=[\]\\;'`~/]/.test(password)) return "Password must contain at least one special character";
    return null;
  };

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    
    if (!token) {
        toast.error("Invalid Link", { description: "Missing reset token." })
        return
    }

    if (newPassword !== confirmPassword) {
        toast.error("Error", { description: "Passwords do not match" })
        return
    }

    const validationError = validatePassword(newPassword)
    if (validationError) {
        toast.error("Invalid Password", { description: validationError })
        return
    }

    setIsLoading(true)
resetPasswordMutation.mutate({ token, newPassword }, {
         onSuccess: () => {
             toast.success("Password Reset Successful", {
                description: "You can now login with your new password.",
             })
             navigate('/login')
         },
         onError: (err) => {
             toast.error("Reset Failed", {
                description: getErrorMessage(err),
             })
         },
         onSettled: () => {
             setIsLoading(false)
         }
    })
  }

  if (!token) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-muted/50 px-4 py-12 sm:px-6 lg:px-8">
            <Card className="w-full max-w-md">
                <CardHeader>
                    <CardTitle className="text-center text-destructive">Invalid Link</CardTitle>
                    <CardDescription className="text-center">
                        The password reset link is invalid or missing a token.
                    </CardDescription>
                </CardHeader>
                <CardFooter className="flex justify-center">
                    <Button variant="link" asChild>
                        <Link to="/login">Back to Login</Link>
                    </Button>
                </CardFooter>
            </Card>
        </div>
      )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/50 px-4 py-12 sm:px-6 lg:px-8">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-center">Reset Password</CardTitle>
          <CardDescription className="text-center">
            Enter your new password below.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit}>
            <div className="grid gap-4">
              <div className="grid gap-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  disabled={isLoading}
                  required
                />
                <p className="text-xs text-muted-foreground">
                    Must be at least 8 characters and contain uppercase, lowercase, digit, and special character.
                </p>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? "Resetting..." : "Reset Password"}
              </Button>
            </div>
          </form>
        </CardContent>
        <CardFooter className="flex justify-center">
            <Button variant="link" asChild>
                <Link to="/login">Back to Login</Link>
            </Button>
        </CardFooter>
      </Card>
    </div>
  )
}
