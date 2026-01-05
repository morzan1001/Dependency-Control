import { useEffect, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { getSystemSettings, updateSystemSettings, SystemSettings as SystemSettingsType, getGlobalWebhooks, createGlobalWebhook, deleteWebhook } from "@/lib/api"
import { WebhookManager } from "@/components/WebhookManager"
import { useAuth } from "@/context/useAuth"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Slack, CheckCircle2 } from "lucide-react"
import { Mattermost } from "@/components/icons/Mattermost"
import { Switch } from "@/components/ui/switch"
import { toast } from "sonner"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

export default function SystemSettings() {
  const queryClient = useQueryClient()
  const { hasPermission } = useAuth()
  const [formData, setFormData] = useState<Partial<SystemSettingsType>>({})
  const [slackAuthMode, setSlackAuthMode] = useState("oauth")
  const [searchParams, setSearchParams] = useSearchParams()

  const { data: settings, isLoading } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  })

  useEffect(() => {
    if (settings) {
      setFormData(settings)
      if (settings.slack_bot_token && !settings.slack_client_id) {
        setSlackAuthMode("manual")
      }
    }
  }, [settings])

  useEffect(() => {
    if (searchParams.get('slack_connected') === 'true') {
        toast.success("Slack connected successfully!", {
            description: "Your Slack workspace has been linked."
        })
        // Remove the query param
        setSearchParams(params => {
            params.delete('slack_connected')
            return params
        })
        // Refresh settings to show the new token status
        queryClient.invalidateQueries({ queryKey: ['systemSettings'] })
    }
  }, [searchParams, setSearchParams, queryClient])

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

  const handleInputChange = (field: keyof SystemSettingsType, value: string | number | boolean) => {
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
    return (
      <div className="space-y-6">
        <div className="space-y-2">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Skeleton className="h-[500px] w-full" />
      </div>
    )
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
              <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
                {mutation.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Data Retention</CardTitle>
              <CardDescription>
                Configure how long scan data is kept.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label>Retention Mode</Label>
                <Select 
                    value={formData.retention_mode || 'project'} 
                    onValueChange={(value) => handleInputChange('retention_mode', value)}
                >
                    <SelectTrigger>
                        <SelectValue placeholder="Select mode" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="project">Per Project (Default)</SelectItem>
                        <SelectItem value="global">Global Enforcement</SelectItem>
                    </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground">
                    "Per Project" allows project owners to set their own retention period. "Global Enforcement" overrides all project settings.
                </p>
              </div>

              {formData.retention_mode === 'global' && (
                  <div className="grid gap-2">
                    <Label htmlFor="global-retention">Global Retention Period (Days)</Label>
                    <Input 
                      id="global-retention" 
                      type="number"
                      min="0"
                      value={formData.global_retention_days ?? 90} 
                      onChange={(e) => handleInputChange('global_retention_days', parseInt(e.target.value))}
                    />
                    <p className="text-sm text-muted-foreground">
                        Set to 0 to disable deletion (keep data forever).
                    </p>
                  </div>
              )}
              
              <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
                {mutation.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Periodic Scanning Defaults</CardTitle>
              <CardDescription>
                Configure default settings for automatic re-scanning of dependencies.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label>Re-scan Mode</Label>
                <Select 
                    value={formData.rescan_mode || 'project'} 
                    onValueChange={(value) => handleInputChange('rescan_mode', value)}
                >
                    <SelectTrigger>
                        <SelectValue placeholder="Select mode" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="project">Per Project (Default)</SelectItem>
                        <SelectItem value="global">Global Enforcement</SelectItem>
                    </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground">
                    "Per Project" allows project owners to configure re-scanning. "Global Enforcement" overrides all project settings.
                </p>
              </div>

              {formData.rescan_mode === 'global' && (
                  <div className="space-y-4 border p-4 rounded-md">
                    <div className="flex items-center justify-between space-x-2">
                        <div className="space-y-0.5">
                        <Label className="text-base">Enable Periodic Re-scanning</Label>
                        <p className="text-sm text-muted-foreground">
                            Automatically re-scan projects to detect new vulnerabilities in existing dependencies.
                        </p>
                        </div>
                        <Switch 
                        checked={formData.global_rescan_enabled || false}
                        onCheckedChange={(checked) => handleInputChange('global_rescan_enabled', checked)}
                        />
                    </div>
                    
                    {formData.global_rescan_enabled && (
                        <div className="grid gap-2">
                            <Label htmlFor="global-rescan-interval">Re-scan Interval (Hours)</Label>
                            <Input 
                            id="global-rescan-interval" 
                            type="number"
                            min="1"
                            value={formData.global_rescan_interval ?? 24} 
                            onChange={(e) => handleInputChange('global_rescan_interval', parseInt(e.target.value))}
                            />
                        </div>
                    )}
                  </div>
              )}
              
              <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
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
                <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
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
                <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
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
                  <Label htmlFor="smtp-encryption">Encryption Method</Label>
                  <Select 
                    value={formData.smtp_encryption || 'starttls'} 
                    onValueChange={(value) => handleInputChange('smtp_encryption', value)}
                  >
                    <SelectTrigger id="smtp-encryption">
                      <SelectValue placeholder="Select encryption method" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="starttls">STARTTLS (Recommended)</SelectItem>
                      <SelectItem value="ssl">SSL/TLS</SelectItem>
                      <SelectItem value="none">None (Insecure)</SelectItem>
                    </SelectContent>
                  </Select>
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
              <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
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
            <CardContent className="space-y-6">
                <div className="flex items-center gap-2 mb-4">
                    <Slack className="h-5 w-5" />
                    <h3 className="font-semibold text-lg">Slack Integration</h3>
                    {formData.slack_bot_token && (
                        <div className="flex items-center gap-1 text-sm text-green-600 bg-green-50 px-2 py-0.5 rounded-full border border-green-200 dark:bg-green-900/20 dark:text-green-400 dark:border-green-900">
                            <CheckCircle2 className="h-3 w-3" />
                            <span>Connected</span>
                        </div>
                    )}
                </div>
                <Tabs value={slackAuthMode} onValueChange={setSlackAuthMode} className="w-full">
                    <TabsList className="grid w-full grid-cols-2 mb-4">
                        <TabsTrigger value="oauth">OAuth (Recommended)</TabsTrigger>
                        <TabsTrigger value="manual">Manual Bot Token</TabsTrigger>
                    </TabsList>
                    
                    <TabsContent value="oauth" className="space-y-4">
                        <p className="text-sm text-muted-foreground mb-4">
                            Connect your Slack workspace using OAuth for secure authentication and automatic token rotation.
                        </p>
                        <div className="grid gap-4">
                            <div className="grid gap-2">
                                <Label htmlFor="slack-client-id">Client ID</Label>
                                <Input 
                                    id="slack-client-id" 
                                    placeholder="e.g. 123456789.123456789"
                                    value={formData.slack_client_id || ''}
                                    onChange={(e) => handleInputChange('slack_client_id', e.target.value)}
                                />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="slack-client-secret">Client Secret</Label>
                                <Input 
                                    id="slack-client-secret" 
                                    type="password"
                                    placeholder="e.g. 8f7d6e5c4b3a2..."
                                    value={formData.slack_client_secret || ''}
                                    onChange={(e) => handleInputChange('slack_client_secret', e.target.value)}
                                />
                            </div>

                            {formData.slack_client_id && formData.slack_client_secret && (
                                <div className="mt-4 space-y-4">
                                    {!formData.slack_bot_token && (
                                        <>
                                            <h4 className="text-sm font-medium mb-2">Setup Instructions</h4>
                                            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1 mb-4">
                                                <li>Go to your Slack App configuration.</li>
                                                <li>Navigate to <strong>OAuth & Permissions</strong>.</li>
                                                <li>Add the following <strong>Redirect URL</strong>:</li>
                                            </ol>
                                            <code className="block w-full p-2 bg-background border rounded text-xs font-mono mb-4 select-all">
                                                {window.location.origin}/api/v1/integrations/slack/callback
                                            </code>
                                        </>
                                    )}
                                    
                                    {/* Check if settings are dirty (unsaved changes) */}
                                    {(formData.slack_client_id !== settings?.slack_client_id || formData.slack_client_secret !== settings?.slack_client_secret) ? (
                                        <div className="p-3 mb-4 text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-md dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900">
                                            Please save your changes before connecting to Slack.
                                        </div>
                                    ) : (
                                        <>
                                            <Button
                                                type="button"
                                                variant={formData.slack_bot_token ? "outline" : "default"}
                                                className="w-full sm:w-auto"
                                                onClick={() => {
                                                    const redirectUri = `${window.location.origin}/api/v1/integrations/slack/callback`;
                                                    const targetUrl = `https://slack.com/oauth/v2/authorize?client_id=${formData.slack_client_id}&scope=chat:write&redirect_uri=${encodeURIComponent(redirectUri)}`;
                                                    window.location.href = targetUrl;
                                                }}
                                            >
                                                <Slack className="mr-2 h-4 w-4" />
                                                {formData.slack_bot_token ? "Reconnect Workspace" : "Connect to Slack Workspace"}
                                            </Button>
                                            <p className="text-xs text-muted-foreground mt-2">
                                                {formData.slack_bot_token 
                                                    ? "Clicking this will re-authorize the app, which can be useful if permissions have changed or the token has expired."
                                                    : "Clicking this will redirect you to Slack to authorize the app."
                                                }
                                            </p>
                                        </>
                                    )}
                                </div>
                            )}
                        </div>
                    </TabsContent>

                    <TabsContent value="manual" className="space-y-4">
                        <p className="text-sm text-muted-foreground mb-4">
                            Manually provide a Slack Bot User OAuth Token (starts with <code>xoxb-</code>). 
                            Use this if you cannot use the OAuth flow or want to manage the token yourself.
                        </p>
                        <div className="grid gap-2">
                            <Label htmlFor="slack-token-manual">Bot User OAuth Token</Label>
                            <Input 
                                id="slack-token-manual" 
                                type="password"
                                placeholder="xoxb-..."
                                value={formData.slack_bot_token || ''}
                                onChange={(e) => handleInputChange('slack_bot_token', e.target.value)}
                            />
                            <p className="text-xs text-muted-foreground">
                                You can find this token in your Slack App settings under <strong>OAuth & Permissions</strong>.
                            </p>
                        </div>
                    </TabsContent>
                </Tabs>
              
              <hr className="my-4" />

              <div className="flex items-center gap-2 mb-4">
                  <Mattermost className="h-5 w-5" />
                  <h3 className="font-semibold text-lg">Mattermost Integration</h3>
                  {formData.mattermost_url && formData.mattermost_bot_token && (
                      <div className="flex items-center gap-1 text-sm text-green-600 bg-green-50 px-2 py-0.5 rounded-full border border-green-200 dark:bg-green-900/20 dark:text-green-400 dark:border-green-900">
                          <CheckCircle2 className="h-3 w-3" />
                          <span>Configured</span>
                      </div>
                  )}
              </div>

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
              <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
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
                    <CardTitle>GitLab Integration</CardTitle>
                    <CardDescription>Configure GitLab integration for automatic project creation and CI/CD.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex items-center justify-between space-x-2">
                        <Label htmlFor="gitlab-enabled">Enable GitLab Integration</Label>
                        <Switch
                            id="gitlab-enabled"
                            checked={formData.gitlab_integration_enabled || false}
                            onCheckedChange={(checked) => handleInputChange('gitlab_integration_enabled', checked)}
                        />
                    </div>
                    {formData.gitlab_integration_enabled && (
                        <>
                            <div className="grid gap-2">
                                <Label htmlFor="gitlab-url">GitLab URL</Label>
                                <Input
                                    id="gitlab-url"
                                    placeholder="https://gitlab.com"
                                    value={formData.gitlab_url || ''}
                                    onChange={(e) => handleInputChange('gitlab_url', e.target.value)}
                                />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="gitlab-oidc-audience">OIDC Audience</Label>
                                <Input
                                    id="gitlab-oidc-audience"
                                    placeholder="dependency-control"
                                    value={formData.gitlab_oidc_audience || ''}
                                    onChange={(e) => handleInputChange('gitlab_oidc_audience', e.target.value)}
                                />
                                <p className="text-sm text-muted-foreground">
                                    The expected <code>aud</code> claim in GitLab OIDC tokens. Must match the <code>aud</code> value configured in your CI/CD pipeline's <code>id_tokens</code> section.
                                </p>
                            </div>
                            <div className="flex items-center justify-between space-x-2">
                                <Label htmlFor="gitlab-auto-create">Auto-Create Projects</Label>
                                <Switch
                                    id="gitlab-auto-create"
                                    checked={formData.gitlab_auto_create_projects || false}
                                    onCheckedChange={(checked) => handleInputChange('gitlab_auto_create_projects', checked)}
                                />
                            </div>
                            <div className="flex items-center justify-between space-x-2">
                                <div className="space-y-0.5">
                                    <Label htmlFor="gitlab-sync-teams">Sync GitLab Groups</Label>
                                    <p className="text-xs text-muted-foreground">
                                        Automatically create Teams from GitLab Groups and assign members.
                                    </p>
                                </div>
                                <Switch
                                    id="gitlab-sync-teams"
                                    checked={formData.gitlab_sync_teams || false}
                                    onCheckedChange={(checked) => handleInputChange('gitlab_sync_teams', checked)}
                                />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="gitlab-token">GitLab Access Token (Optional)</Label>
                                <Input
                                    id="gitlab-token"
                                    type="password"
                                    placeholder="glpat-..."
                                    value={formData.gitlab_access_token || ''}
                                    onChange={(e) => handleInputChange('gitlab_access_token', e.target.value)}
                                />
                                <div className="rounded-md bg-muted p-4 text-sm text-muted-foreground space-y-3 mt-2">
                                    <div>
                                        <span className="font-semibold text-foreground">Why is this needed?</span>
                                        <p className="mt-1">
                                            Projects are automatically created using the GitLab Identity Token (OIDC). However, syncing team members often requires higher privileges that the Identity Token lacks.
                                            <br/>
                                            <strong>Note:</strong> If you leave this empty, automatic project creation will still work, but team members might not be synced.
                                        </p>
                                    </div>
                                    <div>
                                        <span className="font-semibold text-foreground">How to create a token:</span>
                                        <ol className="list-decimal list-inside mt-1 space-y-1">
                                            <li>Go to GitLab <strong>User Settings</strong> (or Group Settings) &rarr; <strong>Access Tokens</strong>.</li>
                                            <li>Create a new token with the <code>read_api</code> scope.</li>
                                            <li>Copy the token (usually starts with <code>glpat-</code>) and paste it here.</li>
                                        </ol>
                                    </div>
                                </div>
                            </div>
                        </>
                    )}
                    <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
                        {mutation.isPending ? "Saving..." : "Save GitLab Settings"}
                    </Button>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>External Integrations</CardTitle>
                    <CardDescription>Connect with other services.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                    <div className="space-y-4">
                        <div className="grid gap-2">
                            <Label htmlFor="github-token">GitHub Personal Access Token</Label>
                            <Input 
                                id="github-token" 
                                type="password"
                                placeholder="ghp_..."
                                value={formData.github_token || ''}
                                onChange={(e) => handleInputChange('github_token', e.target.value)}
                            />
                            <p className="text-sm text-muted-foreground">
                                Used for GitHub Security Advisories (GHSA) lookups and maintainer health checks. 
                                Without a token, API requests are rate-limited to 60/hour. With a token, the limit increases to 5,000/hour.
                            </p>
                            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground space-y-2 mt-1">
                                <span className="font-medium text-foreground">Required Scopes:</span>
                                <ul className="list-disc list-inside ml-2">
                                    <li><code>public_repo</code> (for public repository health checks)</li>
                                    <li>No additional scopes needed for Security Advisory access</li>
                                </ul>
                            </div>
                        </div>

                        <hr className="my-4" />

                        <div className="grid gap-2">
                            <Label htmlFor="malware-api">Open Source Malware API Key</Label>
                            <Input 
                                id="malware-api" 
                                type="password"
                                value={formData.open_source_malware_api_key || ''}
                                onChange={(e) => handleInputChange('open_source_malware_api_key', e.target.value)}
                            />
                        </div>
                    </div>
                    <Button onClick={handleSave} disabled={!hasPermission('system:manage') || mutation.isPending}>
                        {mutation.isPending ? "Saving..." : "Save Integrations"}
                    </Button>
                </CardContent>
            </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
