import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { AlertTriangle } from "lucide-react"
import { AVAILABLE_ANALYZERS, ANALYZER_CATEGORIES } from "@/lib/constants"
import { SettingsTabProps } from "@/types/system"

const DEFAULT_ANALYZERS = ["trivy", "osv", "license_compliance", "end_of_life"];

export function GeneralSettingsTab({
  formData,
  handleInputChange,
  handleSave,
  hasPermission,
  isPending,
}: SettingsTabProps) {
  const analyzers = (formData.default_active_analyzers as string[] | undefined) ?? DEFAULT_ANALYZERS;

  const toggleAnalyzer = (analyzerId: string) => {
    const updated = analyzers.includes(analyzerId)
      ? analyzers.filter(a => a !== analyzerId)
      : [...analyzers, analyzerId];
    handleInputChange('default_active_analyzers', updated);
  };
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

      <Card>
        <CardHeader>
          <CardTitle>Default Analyzers for Auto-Created Projects</CardTitle>
          <CardDescription>
            Select which analyzers are enabled by default when projects are automatically created via CI/CD pipeline (OIDC).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-2 border rounded-md p-4 max-h-[400px] overflow-y-auto">
            {Object.entries(ANALYZER_CATEGORIES).map(([categoryId, categoryInfo]) => {
              const categoryAnalyzers = AVAILABLE_ANALYZERS.filter(a => a.category === categoryId);
              if (categoryAnalyzers.length === 0) return null;

              return (
                <div key={categoryId} className="mb-3 last:mb-0">
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 pb-1 border-b">
                    {categoryInfo.label}
                  </div>
                  {categoryAnalyzers.map((analyzer) => {
                    const hasRequiredDeps = !analyzer.dependsOn || analyzer.dependsOn.some(dep => analyzers.includes(dep));
                    return (
                      <div key={analyzer.id} className="flex items-start space-x-2 py-2">
                        <Checkbox
                          id={`default-analyzer-${analyzer.id}`}
                          checked={analyzers.includes(analyzer.id)}
                          onCheckedChange={() => toggleAnalyzer(analyzer.id)}
                          className="mt-1"
                        />
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-2">
                            <Label htmlFor={`default-analyzer-${analyzer.id}`} className="font-medium cursor-pointer">
                              {analyzer.label}
                            </Label>
                            {analyzer.isPostProcessor && (
                              <span className="text-[10px] px-1.5 py-0.5 bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 rounded">
                                Post-Processor
                              </span>
                            )}
                            {analyzer.requiresCallgraph && (
                              <span className="text-[10px] px-1.5 py-0.5 bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 rounded">
                                Callgraph Required
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {analyzer.description}
                          </p>
                          {analyzer.isPostProcessor && !hasRequiredDeps && analyzers.includes(analyzer.id) && (
                            <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3" />
                              Requires at least one vulnerability scanner to be enabled
                            </p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
          <Button onClick={handleSave} disabled={!hasPermission('system:manage') || isPending}>
            {isPending ? "Saving..." : "Save Default Analyzers"}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
