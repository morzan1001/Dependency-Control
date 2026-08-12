import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { SecretInput } from "@/components/settings/SecretInput"
import { SettingsTabProps } from "@/types/system"
import { CICDInstancesManagement } from "@/components/settings/CICDInstancesManagement"

export function IntegrationsSettingsTab({
  formData,
  handleInputChange,
  handleSave,
  hasPermission,
  isPending,
}: SettingsTabProps) {
  return (
    <div className="space-y-4">
      <CICDInstancesManagement />

      <Card>
        <CardHeader>
          <CardTitle>External Integrations</CardTitle>
          <CardDescription>Connect with other services.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="github-token">GitHub Personal Access Token</Label>
              <SecretInput
                id="github-token"
                placeholder="ghp_..."
                value={formData.github_token || ''}
                configured={!!formData.github_token_configured}
                onChange={(value) => handleInputChange('github_token', value)}
              />
              <p className="text-sm text-muted-foreground">
                Used for GitHub Security Advisories (GHSA) lookups and maintainer health checks.
                Without a token, API requests are rate-limited to 60/hour. With a token, the limit increases to 5,000/hour.
                If left empty, the access token from a configured GitHub instance will be used automatically.
              </p>
              <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground space-y-2 mt-1">
                <span className="font-medium text-foreground">Required Scopes:</span>
                <ul className="list-disc list-inside ml-2">
                  <li><code>public_repo</code> (for public repository health checks)</li>
                </ul>
              </div>
            </div>

            <hr className="my-4" />

            <div className="grid gap-2">
              <Label htmlFor="malware-api">Open Source Malware API Key</Label>
              <SecretInput
                id="malware-api"
                value={formData.open_source_malware_api_key || ''}
                configured={!!formData.open_source_malware_api_key_configured}
                onChange={(value) => handleInputChange('open_source_malware_api_key', value)}
              />
            </div>
          </div>
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save External Integrations"}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
