import { useEffect, useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { getSystemSettings, updateSystemSettings, SystemSettings as SystemSettingsType, getGlobalWebhooks, createGlobalWebhook, deleteWebhook } from "@/lib/api"
import { WebhookManager } from "@/components/WebhookManager"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { toast } from "sonner"
import { Spinner } from "@/components/ui/spinner"

export default function SystemSettings() {
  const queryClient = useQueryClient()
  const [formData, setFormData] = useState<Partial<SystemSettingsType>>({})

  const { data: settings, isLoading } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  })

  useEffect(() => {
    if (settings) {
      setFormData(settings)
    }
  }, [settings])

  const mutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] })
      toast.success("Settings updated successfully")
    },
    onError: () => {
      toast.error("Failed to update settings")
    }
  })

  const handleInputChange = (field: keyof SystemSettingsType, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const handleSave = () => {
    mutation.mutate(formData)
  }

  const { data: webhooks, isLoading: isLoadingWebhooks, refetch: refetchWebhooks } = useQuery({
    queryKey: ['globalWebhooks'],
    queryFn: getGlobalWebhooks,
  })

  const createWebhookMutation = useMutation({
    mutationFn: createGlobalWebhook,
    onSuccess: () => {
      refetchWebhooks()
    }
  })

  const deleteWebhookMutation = useMutation({
    mutationFn: deleteWebhook,
    onSuccess: () => {
      refetchWebhooks()
    }
  })

  if (isLoading) {
    return <div className="flex justify-center p-8"><Spinner /></div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">System Settings</h2>
        <p className="text-muted-foreground">
          Manage global system configurations and preferences.
        </p>
      </div>

      <Tabs defaultValue="general" className="space-y-4">
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="integrations">Integrations</TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>General Information</CardTitle>
              <CardDescription>
                Basic system information and configuration.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="instance-name">Instance Name</Label>
                <Input 
                  id="instance-name" 
                  value={formData.instance_name || ''} 
                  onChange={(e) => handleInputChange('instance_name', e.target.value)}
                />
              </div>
              <Button onClick={handleSave} disabled={mutation.isPending}>
                {mutation.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
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
                <Button onClick={handleSave} disabled={mutation.isPending}>
                    {mutation.isPending ? "Saving..." : "Save Changes"}
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
                <Button onClick={handleSave} disabled={mutation.isPending}>
                    {mutation.isPending ? "Saving..." : "Save Changes"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Email Configuration</CardTitle>
              <CardDescription>
                SMTP settings for sending system emails.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="smtp-host">SMTP Host</Label>
                <Input 
                  id="smtp-host" 
                  placeholder="smtp.example.com" 
                  value={formData.smtp_host || ''}
                  onChange={(e) => handleInputChange('smtp_host', e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="smtp-port">SMTP Port</Label>
                  <Input 
                    id="smtp-port" 
                    type="number"
                    placeholder="587" 
                    value={formData.smtp_port || 587}
                    onChange={(e) => handleInputChange('smtp_port', parseInt(e.target.value))}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="smtp-user">SMTP User</Label>
                  <Input 
                    id="smtp-user" 
                    placeholder="user@example.com" 
                    value={formData.smtp_user || ''}
                    onChange={(e) => handleInputChange('smtp_user', e.target.value)}
                  />
                </div>
              </div>
              <div className="grid gap-2">
                  <Label htmlFor="smtp-password">SMTP Password</Label>
                  <Input 
                    id="smtp-password" 
                    type="password"
                    placeholder="••••••••" 
                    value={formData.smtp_password || ''}
                    onChange={(e) => handleInputChange('smtp_password', e.target.value)}
                  />
              </div>
              <div className="grid gap-2">
                  <Label htmlFor="from-email">From Email</Label>
                  <Input 
                    id="from-email" 
                    placeholder="info@dependencycontrol.local" 
                    value={formData.emails_from_email || ''}
                    onChange={(e) => handleInputChange('emails_from_email', e.target.value)}
                  />
              </div>
              <Button onClick={handleSave} disabled={mutation.isPending}>
                {mutation.isPending ? "Saving..." : "Save Email Settings"}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Chat Notifications</CardTitle>
              <CardDescription>
                Configure Slack and Mattermost integrations.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                  <Label htmlFor="slack-token">Slack Bot Token</Label>
                  <Input 
                      id="slack-token" 
                      type="password"
                      value={formData.slack_bot_token || ''}
                      onChange={(e) => handleInputChange('slack_bot_token', e.target.value)}
                  />
              </div>
              <hr className="my-4" />
              <div className="grid gap-2">
                  <Label htmlFor="mattermost-url">Mattermost URL</Label>
                  <Input 
                      id="mattermost-url" 
                      placeholder="https://mattermost.example.com"
                      value={formData.mattermost_url || ''}
                      onChange={(e) => handleInputChange('mattermost_url', e.target.value)}
                  />
              </div>
              <div className="grid gap-2">
                  <Label htmlFor="mattermost-token">Mattermost Bot Token</Label>
                  <Input 
                      id="mattermost-token" 
                      type="password"
                      value={formData.mattermost_bot_token || ''}
                      onChange={(e) => handleInputChange('mattermost_bot_token', e.target.value)}
                  />
              </div>
              <Button onClick={handleSave} disabled={mutation.isPending}>
                  {mutation.isPending ? "Saving..." : "Save Chat Settings"}
              </Button>
            </CardContent>
          </Card>

          <WebhookManager 
            webhooks={webhooks || []}
            isLoading={isLoadingWebhooks}
            onCreate={(data) => createWebhookMutation.mutateAsync(data)}
            onDelete={(id) => deleteWebhookMutation.mutateAsync(id)}
            title="Global Webhooks"
            description="Configure webhooks that trigger on system-wide events."
          />
        </TabsContent>
        
        <TabsContent value="integrations" className="space-y-4">
            <Card>
                <CardHeader>
                    <CardTitle>External Integrations</CardTitle>
                    <CardDescription>Connect with other services.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="grid gap-2">
                        <Label htmlFor="malware-api">Open Source Malware API Key</Label>
                        <Input 
                            id="malware-api" 
                            type="password"
                            value={formData.open_source_malware_api_key || ''}
                            onChange={(e) => handleInputChange('open_source_malware_api_key', e.target.value)}
                        />
                    </div>
                    <Button onClick={handleSave} disabled={mutation.isPending}>
                        {mutation.isPending ? "Saving..." : "Save Integrations"}
                    </Button>
                </CardContent>
            </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
