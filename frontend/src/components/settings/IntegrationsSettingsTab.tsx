import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
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
            {isPending ? "Saving..." : "Save External Integrations"}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
