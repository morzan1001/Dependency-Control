import type { ApiError } from '@/api/client';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { INVALID_OTP_CODE, INVALID_PASSWORD } from '@/hooks/queries/use-auth';

interface TwoFAEnableFieldsProps {
  code: string;
  password: string;
  error: unknown;
  onCodeChange: (code: string) => void;
  onPasswordChange: (password: string) => void;
}

export function TwoFAEnableFields({ code, password, error, onCodeChange, onPasswordChange }: Readonly<TwoFAEnableFieldsProps>) {
  const refusal = (error as ApiError | null)?.response?.data?.detail;
  const codeError = refusal === INVALID_OTP_CODE ? refusal : null;
  const passwordError = refusal === INVALID_PASSWORD ? refusal : null;

  return (
    <>
      <div className="grid gap-2">
        <Label htmlFor="otp">Authenticator Code</Label>
        <Input
          id="otp"
          value={code}
          onChange={(e) => onCodeChange(e.target.value)}
          placeholder="123456"
          maxLength={6}
          inputMode="numeric"
          autoComplete="one-time-code"
          aria-invalid={!!codeError}
          aria-describedby={codeError ? 'otp-error' : undefined}
        />
        {codeError && (
          <p id="otp-error" role="alert" className="text-xs text-destructive">{codeError}</p>
        )}
      </div>
      <div className="grid gap-2">
        <Label htmlFor="password-2fa">Current Password</Label>
        <Input
          id="password-2fa"
          type="password"
          value={password}
          onChange={(e) => onPasswordChange(e.target.value)}
          placeholder="Confirm your password"
          aria-invalid={!!passwordError}
          aria-describedby={passwordError ? 'password-2fa-error' : undefined}
        />
        {passwordError && (
          <p id="password-2fa-error" role="alert" className="text-xs text-destructive">{passwordError}</p>
        )}
      </div>
    </>
  );
}
