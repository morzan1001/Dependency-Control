import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { CheckCircle2 } from "lucide-react"
import { Slack, Mattermost } from "@/components/icons"
import { WebhookManager } from "@/components/WebhookManager"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SettingsTabProps, SystemSettings } from "@/types/system"
import { Webhook, WebhookCreate } from "@/types/webhook"

interface NotificationsSettingsTabProps extends SettingsTabProps {
  slackAuthMode: string
  setSlackAuthMode: (mode: string) => void
  settings: SystemSettings | undefined
  webhooks: Webhook[]
  isLoadingWebhooks: boolean
  onCreateWebhook: (data: WebhookCreate) => Promise<Webhook>
  onDeleteWebhook: (id: string) => Promise<void>
}

export function NotificationsSettingsTab({
  formData,
  handleInputChange,
  handleSave,
  hasPermission,
  isPending,
  slackAuthMode,
  setSlackAuthMode,
  settings,
  webhooks,
  isLoadingWebhooks,
  onCreateWebhook,
  onDeleteWebhook,
}: NotificationsSettingsTabProps) {
  return (
    <div className="space-y-4">
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
                min="1"
                max="65535"
                value={formData.smtp_port || 587}
                onChange={(e) => {
                  const port = Number.parseInt(e.target.value) || 587;
                  handleInputChange('smtp_port', Math.min(65535, Math.max(1, port)));
                }}
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
            <Label htmlFor="from-name">From Name</Label>
            <Input
              id="from-name"
              placeholder="Dependency Control"
              value={formData.emails_from_name || ''}
              onChange={(e) => handleInputChange('emails_from_name', e.target.value)}
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
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save Email Settings"}
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
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save Chat Settings"}
          </Button>
        </CardContent>
      </Card>

      <WebhookManager 
        webhooks={webhooks || []}
        isLoading={isLoadingWebhooks}
        onCreate={onCreateWebhook}
        onDelete={onDeleteWebhook}
        title="Global Webhooks"
        description="Configure webhooks that trigger on system-wide events."
      />
    </div>
  )
}
