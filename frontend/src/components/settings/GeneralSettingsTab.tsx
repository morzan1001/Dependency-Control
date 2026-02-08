import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SettingsTabProps } from "@/types/system"

export function GeneralSettingsTab({
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
          <div className="grid gap-2">
            <Label htmlFor="dashboard-url">Dashboard URL</Label>
            <Input
              id="dashboard-url"
              placeholder="https://dc.example.com"
              value={formData.dashboard_url || ''}
              onChange={(e) => handleInputChange('dashboard_url', e.target.value)}
            />
            <p className="text-sm text-muted-foreground">
              Public URL of this instance. Used in email notifications and links.
            </p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="project-limit">Project Limit per User</Label>
            <Input 
              id="project-limit" 
              type="number"
              min="0"
              value={formData.project_limit_per_user ?? 0} 
              onChange={(e) => handleInputChange('project_limit_per_user', parseInt(e.target.value) || 0)}
            />
            <p className="text-sm text-muted-foreground">
              Maximum number of projects a user can create. Set to 0 for unlimited.
            </p>
          </div>
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save General Settings"}
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
                onChange={(e) => handleInputChange('global_retention_days', parseInt(e.target.value) || 0)}
              />
              <p className="text-sm text-muted-foreground">
                Set to 0 to disable deletion (keep data forever).
              </p>
            </div>
          )}
          
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save Retention Settings"}
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
                    onChange={(e) => handleInputChange('global_rescan_interval', parseInt(e.target.value) || 1)}
                  />
                </div>
              )}
            </div>
          )}
          
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save Rescan Settings"}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
