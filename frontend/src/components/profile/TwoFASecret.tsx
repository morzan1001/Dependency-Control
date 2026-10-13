import type { TwoFASetup } from '@/types/user';

export function TwoFASecret({ setup }: Readonly<{ setup: TwoFASetup }>) {
  return (
    <div className="flex flex-col items-center gap-4">
      <img src={`data:image/png;base64,${setup.qr_code}`} alt="2FA QR Code" className="w-48 h-48" />
      <div className="text-center text-sm text-muted-foreground">
        Secret: <code className="bg-muted px-1 py-0.5 rounded">{setup.secret}</code>
      </div>
    </div>
  );
}
