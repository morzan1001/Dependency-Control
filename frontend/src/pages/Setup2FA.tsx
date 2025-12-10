import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { setup2FA, enable2FA, getMe, TwoFASetup } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Spinner } from '@/components/ui/spinner'
import { toast } from "sonner"
import { useNavigate } from 'react-router-dom'
import { getErrorMessage } from "@/lib/utils"

export default function Setup2FA() {
  const [step, setStep] = useState<'init' | 'verify'>('init')
  const [setupData, setSetupData] = useState<TwoFASetup | null>(null)
  const [otpCode, setOtpCode] = useState('')
  const [password, setPassword] = useState('')
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
  })

  useEffect(() => {
    if (user?.totp_enabled) {
      navigate('/dashboard')
    }
  }, [user, navigate])

  const setupMutation = useMutation({
    mutationFn: setup2FA,
    onSuccess: (data) => {
      setSetupData(data)
      setStep('verify')
    },
    onError: (error) => {
      toast.error("Failed to start 2FA setup", {
        description: getErrorMessage(error)
      })
    }
  })

  const enableMutation = useMutation({
    mutationFn: () => enable2FA(otpCode, password),
    onSuccess: () => {
      toast.success("2FA Enabled", {
        description: "Two-factor authentication has been successfully enabled."
      })
      queryClient.invalidateQueries({ queryKey: ['me'] })
      // Force a reload or re-login to get a full token
      // Since we might have a limited token, we need to re-authenticate or refresh
      // For now, redirecting to login is the safest way to ensure a clean state with full token
      navigate('/login', { state: { message: '2FA enabled. Please login again.' } })
    },
    onError: (error) => {
      toast.error("Failed to enable 2FA", {
        description: getErrorMessage(error)
      })
    }
  })

  const handleStartSetup = () => {
    setupMutation.mutate()
  }

  const handleVerify = (e: React.FormEvent) => {
    e.preventDefault()
    enableMutation.mutate()
  }

  return (
    <div className="flex h-screen items-center justify-center bg-muted/50">
      <Card className="w-[450px]">
        <CardHeader>
          <CardTitle>Setup Two-Factor Authentication</CardTitle>
          <CardDescription>
            Your organization requires 2FA to be enabled for your account.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step === 'init' && (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Two-factor authentication adds an extra layer of security to your account. 
                You will need to use an authenticator app (like Google Authenticator or Authy) to scan a QR code.
              </p>
              <Button onClick={handleStartSetup} disabled={setupMutation.isPending} className="w-full">
                {setupMutation.isPending ? <Spinner className="mr-2" /> : null}
                Start Setup
              </Button>
            </div>
          )}

          {step === 'verify' && setupData && (
            <form onSubmit={handleVerify} className="space-y-4">
              <div className="flex justify-center p-4 bg-white rounded-lg border">
                <img src={setupData.qr_code} alt="2FA QR Code" className="w-48 h-48" />
              </div>
              
              <div className="text-center text-sm font-mono bg-muted p-2 rounded">
                Secret: {setupData.secret}
              </div>

              <div className="space-y-2">
                <Label htmlFor="otp">Verification Code</Label>
                <Input
                  id="otp"
                  placeholder="123456"
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Confirm Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Current Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              <Button type="submit" className="w-full" disabled={enableMutation.isPending}>
                {enableMutation.isPending ? <Spinner className="mr-2" /> : null}
                Verify and Enable
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
