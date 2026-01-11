import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { SettingsTabProps } from "./types"

export function SecuritySettingsTab({
  formData,
  handleInputChange,
  handleSave,
  hasPermission,
  isPending,
}: SettingsTabProps) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Security Settings</CardTitle>
          <CardDescription>
            Configure global security policies.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between space-x-2">
            <div className="space-y-0.5">
              <Label className="text-base">Allow Public Registration</Label>
              <p className="text-sm text-muted-foreground">
                If enabled, anyone can create an account.
              </p>
            </div>
            <Switch 
              checked={formData.allow_public_registration || false}
              onCheckedChange={(checked) => handleInputChange('allow_public_registration', checked)}
            />
          </div>
          <hr className="my-4" />
          <div className="flex items-center justify-between space-x-2">
            <div className="space-y-0.5">
              <Label className="text-base">Enforce 2FA</Label>
              <p className="text-sm text-muted-foreground">
                Require all users to set up Two-Factor Authentication.
              </p>
            </div>
            <Switch 
              checked={formData.enforce_2fa || false}
              onCheckedChange={(checked) => handleInputChange('enforce_2fa', checked)}
            />
          </div>
          <hr className="my-4" />
          <div className="flex items-center justify-between space-x-2">
            <div className="space-y-0.5">
              <Label className="text-base">Enforce Email Verification</Label>
              <p className="text-sm text-muted-foreground">
                Require users to verify their email address before accessing the system.
              </p>
            </div>
            <Switch 
              checked={formData.enforce_email_verification || false}
              onCheckedChange={(checked) => handleInputChange('enforce_email_verification', checked)}
            />
          </div>
          <div className="mt-4">
            <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
              {isPending ? "Saving..." : "Save Changes"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>OIDC / SSO Configuration</CardTitle>
          <CardDescription>
            Configure OpenID Connect for Single Sign-On (e.g. GitLab, Google).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between space-x-2">
            <div className="space-y-0.5">
              <Label className="text-base">Enable OIDC Login</Label>
              <p className="text-sm text-muted-foreground">
                Allow users to log in using an external provider.
              </p>
            </div>
            <Switch 
              checked={formData.oidc_enabled || false}
              onCheckedChange={(checked) => handleInputChange('oidc_enabled', checked)}
            />
          </div>
          
          {formData.oidc_enabled && (
            <div className="space-y-4 mt-4 border-t pt-4">
              <div className="grid gap-2">
                <Label htmlFor="oidc-provider-name">Provider Name</Label>
                <Input 
                  id="oidc-provider-name" 
                  placeholder="GitLab" 
                  value={formData.oidc_provider_name || 'GitLab'}
                  onChange={(e) => handleInputChange('oidc_provider_name', e.target.value)}
                />
                <p className="text-xs text-muted-foreground">Displayed on the login button (e.g. "Login with GitLab")</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="oidc-client-id">Client ID</Label>
                  <Input 
                    id="oidc-client-id" 
                    value={formData.oidc_client_id || ''}
                    onChange={(e) => handleInputChange('oidc_client_id', e.target.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="oidc-client-secret">Client Secret</Label>
                  <Input 
                    id="oidc-client-secret" 
                    type="password"
                    value={formData.oidc_client_secret || ''}
                    onChange={(e) => handleInputChange('oidc_client_secret', e.target.value)}
                  />
                </div>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="oidc-issuer">Issuer URL</Label>
                <Input 
                  id="oidc-issuer" 
                  placeholder="https://gitlab.com" 
                  value={formData.oidc_issuer || ''}
                  onChange={(e) => handleInputChange('oidc_issuer', e.target.value)}
                />
                <p className="text-xs text-muted-foreground">The OIDC Issuer URL (used for discovery).</p>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="oidc-auth-endpoint">Authorization Endpoint</Label>
                <Input 
                  id="oidc-auth-endpoint" 
                  placeholder="https://gitlab.com/oauth/authorize" 
                  value={formData.oidc_authorization_endpoint || ''}
                  onChange={(e) => handleInputChange('oidc_authorization_endpoint', e.target.value)}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="oidc-token-endpoint">Token Endpoint</Label>
                <Input 
                  id="oidc-token-endpoint" 
                  placeholder="https://gitlab.com/oauth/token" 
                  value={formData.oidc_token_endpoint || ''}
                  onChange={(e) => handleInputChange('oidc_token_endpoint', e.target.value)}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="oidc-userinfo-endpoint">UserInfo Endpoint</Label>
                <Input 
                  id="oidc-userinfo-endpoint" 
                  placeholder="https://gitlab.com/oauth/userinfo" 
                  value={formData.oidc_userinfo_endpoint || ''}
                  onChange={(e) => handleInputChange('oidc_userinfo_endpoint', e.target.value)}
                />
              </div>
              
              <div className="grid gap-2">
                <Label htmlFor="oidc-scopes">Scopes</Label>
                <Input 
                  id="oidc-scopes" 
                  placeholder="openid profile email" 
                  value={formData.oidc_scopes || 'openid profile email'}
                  onChange={(e) => handleInputChange('oidc_scopes', e.target.value)}
                />
              </div>
            </div>
          )}
          
          <div className="mt-4">
            <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
              {isPending ? "Saving..." : "Save Changes"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
