import { useState } from "react";
import { useCreateProject } from "@/hooks/queries/use-projects";
import { useTeams } from "@/hooks/queries/use-teams";
import { useSystemSettings } from "@/hooks/queries/use-system";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Copy, Check, Plus } from "lucide-react";
import { toast } from "sonner";
import { AVAILABLE_ANALYZERS, ANALYZER_CATEGORIES } from "@/lib/constants";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

interface CreateProjectDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CreateProjectDialog({
  open,
  onOpenChange,
}: CreateProjectDialogProps) {
  const [name, setName] = useState("");
  const [teamId, setTeamId] = useState<string | undefined>(undefined);
  const [retentionDays, setRetentionDays] = useState(90);
  const [analyzers, setAnalyzers] = useState<string[]>([
    "trivy",
    "osv",
    "license_compliance",
    "end_of_life",
  ]);
  const [createdProjectData, setCreatedProjectData] = useState<{
    project_id: string;
    api_key: string;
    note: string;
  } | null>(null);
  const [hasCopied, setHasCopied] = useState(false);
  
  const { data: teams } = useTeams();
  const { data: systemSettings } = useSystemSettings();

  const createProjectMutation = useCreateProject();

  const handleCreateProject = (e: React.FormEvent) => {
    e.preventDefault();
    createProjectMutation.mutate(
      {
        name,
        team_id: teamId === "none" ? undefined : teamId,
        active_analyzers: analyzers,
        retention_days: retentionDays,
      },
      {
        onSuccess: (data) => {
          setCreatedProjectData(data);
          toast.success("Project created successfully");
        },
        onError: (error: any) => {
            const description = error?.response?.data?.detail || "An error occurred";
            toast.error("Failed to create project", {
                description
            });
        },
      }
    );
  };

  const handleClose = () => {
    onOpenChange(false);
    setTimeout(() => {
      setCreatedProjectData(null);
      setName("");
      setTeamId(undefined);
      setRetentionDays(90);
      setAnalyzers(["trivy", "osv", "license_compliance", "end_of_life"]);
      setHasCopied(false);
    }, 300);
  };

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setHasCopied(true);
    toast.success("API Key copied to clipboard");
    setTimeout(() => setHasCopied(false), 2000);
  };

  const toggleAnalyzer = (id: string) => {
    setAnalyzers((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id]
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button onClick={() => onOpenChange(true)}>
          <Plus className="mr-2 h-4 w-4" /> New Project
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[600px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {createdProjectData ? "Project Created" : "Create New Project"}
          </DialogTitle>
          <DialogDescription>
            {createdProjectData
              ? "Please save your API key securely. It will not be shown again."
              : "Add a new project to start scanning your dependencies."}
          </DialogDescription>
        </DialogHeader>

        {createdProjectData ? (
          <div className="space-y-4 py-4">
            <Alert>
              <Check className="h-4 w-4" />
              <AlertTitle>Success</AlertTitle>
              <AlertDescription>{createdProjectData.note}</AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label>Project ID</Label>
              <div className="flex items-center space-x-2">
                <Input
                  value={createdProjectData.project_id}
                  readOnly
                  className="font-mono bg-muted"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>API Key</Label>
              <div className="flex items-center space-x-2">
                <Input
                  value={createdProjectData.api_key}
                  readOnly
                  className="font-mono bg-muted"
                  type="password"
                />
                <Button
                  size="icon"
                  variant="outline"
                  onClick={() => copyToClipboard(createdProjectData.api_key)}
                >
                  {hasCopied ? (
                    <Check className="h-4 w-4" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
              <p className="text-sm text-muted-foreground text-red-500 font-medium">
                Make sure to copy your API Key now. You won't be able to see it
                again!
              </p>
            </div>
          </div>
        ) : (
          <form onSubmit={handleCreateProject} className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Project Name</Label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="my-awesome-project"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="team">Team (Optional)</Label>
              <Select
                value={teamId || "none"}
                onValueChange={(val) => setTeamId(val)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a team" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No Team (Personal)</SelectItem>
                  {teams?.map((team) => (
                    <SelectItem key={team.id} value={team.id || ""}>
                      {team.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
                <Label htmlFor="retention">Data Retention (Days)</Label>
                <Input
                    id="retention"
                    type="number"
                    min="1"
                    value={retentionDays}
                    onChange={(e) => setRetentionDays(parseInt(e.target.value))}
                    required
                />
                 {systemSettings?.retention_days && (
                    <p className="text-xs text-muted-foreground">
                        Global default: {systemSettings.retention_days} days. Set to 0 to use global default.
                    </p>
                )}
            </div>

            <div className="space-y-3 pt-2">
              <Label>Active Analyzers</Label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(ANALYZER_CATEGORIES).map(
                  ([category, info]) => {
                    const categoryAnalyzers = AVAILABLE_ANALYZERS.filter(
                      (a) => a.category === category
                    );
                    if (categoryAnalyzers.length === 0) return null;

                    return (
                      <div key={category} className="space-y-2">
                        <h4 className="font-medium text-sm text-muted-foreground border-b pb-1">
                          {info.label}
                        </h4>
                        <div className="space-y-2">
                          {categoryAnalyzers.map((analyzer) => (
                            <div
                              key={analyzer.id}
                              className="flex items-start space-x-2"
                            >
                              <Checkbox
                                id={analyzer.id}
                                checked={analyzers.includes(analyzer.id)}
                                onCheckedChange={() =>
                                  toggleAnalyzer(analyzer.id)
                                }
                              />
                              <div className="grid gap-1.5 leading-none">
                                <label
                                  htmlFor={analyzer.id}
                                  className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                                >
                                  {analyzer.label}
                                </label>
                                <p className="text-xs text-muted-foreground">
                                  {analyzer.description}
                                </p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  }
                )}
              </div>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createProjectMutation.isPending}>
                {createProjectMutation.isPending && (
                  <span className="mr-2">Creating...</span>
                )}
                Create Project
              </Button>
            </DialogFooter>
          </form>
        )}
        {createdProjectData && (
          <DialogFooter>
            <Button onClick={handleClose}>Close</Button>
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  );
}
