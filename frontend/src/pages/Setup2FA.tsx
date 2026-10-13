import { useState, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { ApiError } from '@/api/client'
import { INVALID_OTP_CODE, INVALID_PASSWORD, useSetup2FA, useEnable2FA } from '@/hooks/queries/use-auth'
import { useCurrentUser } from '@/hooks/queries/use-users'
import { TwoFASetup } from '@/types/user'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { TwoFAEnableFields } from '@/components/profile/TwoFAEnableFields'
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

  const { data: user } = useCurrentUser();

  useEffect(() => {
    if (user?.totp_enabled) {
      navigate('/dashboard')
    }
  }, [user, navigate])

  const setupMutation = useSetup2FA();
  const enableMutation = useEnable2FA();

  const resetRefusal = () => {
    if (!enableMutation.isPending) enableMutation.reset()
  }

  const handleStartSetup = () => {
    setupMutation.mutate(undefined, {
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
  }

  const handleVerify = (e: React.FormEvent) => {
    e.preventDefault()
    enableMutation.mutate({ code: otpCode, password }, {
       onSuccess: () => {
        toast.success("2FA enabled", {
           description: "Two-factor authentication has been enabled."
        })
        queryClient.invalidateQueries({ queryKey: ['me'] })
        navigate('/login', { state: { message: '2FA enabled. Please login again.' } })
      },
      onError: (error) => {
        const detail = (error as ApiError).response?.data?.detail
        if (detail !== INVALID_OTP_CODE && detail !== INVALID_PASSWORD) {
          toast.error("Failed to enable 2FA", { description: getErrorMessage(error) })
        }
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
          <CardTitle>Setup Two-Factor Authentication</CardTitle>
          <CardDescription>
            Your organization requires local accounts to enable 2FA.
          </CardDescription>
        </CardHeader>
        {step === 'init' && (
          <>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Two-factor authentication adds an extra layer of security to your account.
                You will need to use an authenticator app (like Google Authenticator or Authy) to scan a QR code.
              </p>
            </CardContent>
            <CardFooter className="flex flex-col gap-2">
              <Button onClick={handleStartSetup} disabled={setupMutation.isPending} className="w-full">
                {setupMutation.isPending ? "Starting..." : "Start Setup"}
              </Button>
            </CardFooter>
          </>
        )}

        {step === 'verify' && setupData && (
          <form onSubmit={handleVerify}>
            <CardContent>
              <div className="grid w-full items-center gap-4">
                <div className="flex justify-center p-4 bg-white rounded-lg border">
                  <img src={`data:image/png;base64,${setupData.qr_code}`} alt="2FA QR Code" className="w-48 h-48" />
                </div>

                <div className="text-center text-sm font-mono bg-muted p-2 rounded">
                  Secret: {setupData.secret}
                </div>

                <TwoFAEnableFields
                  code={otpCode}
                  password={password}
                  error={enableMutation.error}
                  onCodeChange={(code) => {
                    setOtpCode(code)
                    resetRefusal()
                  }}
                  onPasswordChange={(value) => {
                    setPassword(value)
                    resetRefusal()
                  }}
                />
              </div>
            </CardContent>
            <CardFooter className="flex flex-col gap-2">
              <Button type="submit" className="w-full" disabled={!otpCode || !password || enableMutation.isPending}>
                {enableMutation.isPending ? "Enabling..." : "Enable 2FA"}
              </Button>
            </CardFooter>
          </form>
        )}
      </Card>
    </div>
  )
}
