import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { SettingsTabProps } from "./types"

export function IntegrationsSettingsTab({
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
                      This token enables advanced integration features that the standard CI Job Token cannot perform:
                    </p>
                    <ul className="list-disc list-inside mt-1 space-y-1 ml-1">
                      <li><strong>Merge Request Decoration:</strong> Posting scan results and security warnings as comments on Merge Requests.</li>
                      <li><strong>Team Sync:</strong> Automatically importing members from GitLab Groups/Projects to manage access.</li>
                    </ul>
                    <p className="mt-2">
                       If left empty, basic scans and project creation via OIDC will still work, but these features will be disabled.
                    </p>
                  </div>
                  <div>
                    <span className="font-semibold text-foreground">How to create a token:</span>
                    <ol className="list-decimal list-inside mt-1 space-y-1">
                      <li>Go to <strong>User Settings</strong> (for a Bot user) or <strong>Group Settings</strong> &rarr; <strong>Access Tokens</strong>.</li>
                      <li>Create a new token with the <code>api</code> scope (required for writing comments).</li>
                      <li>Ensure the user has at least <strong>Reporter</strong> role in the projects to post comments.</li>
                      <li>Copy the token (starts with <code>glpat-</code>) and paste it here.</li>
                    </ol>
                  </div>
                </div>
              </div>
            </>
          )}
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save GitLab Settings"}
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
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save Integrations"}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
