import { useState } from "react";
import { useCreateProject } from "@/hooks/queries/use-projects";
import { useTeams } from "@/hooks/queries/use-teams";
import { useAppConfig } from "@/hooks/queries/use-system";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy-field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Check } from "lucide-react";
import { toast } from "sonner";
import type { RetentionAction } from "@/types/project";
import { AnalyzerChecklist } from "./AnalyzerChecklist";
import { RetentionFields } from "./RetentionRescanFields";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const EMPTY_FORM = {
  name: "",
  team_id: undefined as string | undefined,
  retention_days: 90,
  retention_action: "delete" as RetentionAction,
  // null until the user picks: the selection follows the backend default until then.
  pickedAnalyzers: null as string[] | null,
};

type CreateProjectForm = typeof EMPTY_FORM;

interface CreateProjectDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CreateProjectDialog({
  open,
  onOpenChange,
}: Readonly<CreateProjectDialogProps>) {
  const [form, setForm] = useState(EMPTY_FORM);
  const set = (patch: Partial<CreateProjectForm>) => setForm((current) => ({ ...current, ...patch }));
  const [createdProjectData, setCreatedProjectData] = useState<{
    project_id: string;
    api_key: string;
    note: string;
  } | null>(null);

  const { data: teams } = useTeams(undefined, undefined, undefined, { enabled: open });
  const { data: appConfig } = useAppConfig({ enabled: open });

  const createProjectMutation = useCreateProject({ errorTitle: "Failed to create project" });
  const analyzers = form.pickedAnalyzers ?? appConfig?.default_project_analyzers ?? [];
  const retentionIsGlobal = appConfig?.retention_mode === 'global';

  const handleCreateProject = (e: React.FormEvent) => {
    e.preventDefault();
    createProjectMutation.mutate(
      {
        name: form.name,
        team_id: form.team_id === "none" ? undefined : form.team_id,
        active_analyzers: form.pickedAnalyzers ?? undefined,
        retention_days: retentionIsGlobal ? undefined : form.retention_days,
        retention_action: retentionIsGlobal ? undefined : form.retention_action,
      },
      {
        onSuccess: (data) => {
          setCreatedProjectData(data);
          toast.success("Project created successfully");
        },
      }
    );
  };

  const handleClose = () => {
    onOpenChange(false);
    setTimeout(() => {
      setCreatedProjectData(null);
      setForm(EMPTY_FORM);
    }, 300);
  };

  const toggleAnalyzer = (id: string) => {
    set({ pickedAnalyzers: analyzers.includes(id) ? analyzers.filter((a) => a !== id) : [...analyzers, id] });
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
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
              <CopyField value={createdProjectData.api_key} what="API key" />
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
                value={form.name}
                onChange={(e) => set({ name: e.target.value })}
                placeholder="my-awesome-project"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="team">Team (Optional)</Label>
              <Select
                value={form.team_id || "none"}
                onValueChange={(team_id) => set({ team_id })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a team" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No Team (Personal)</SelectItem>
                  {teams?.map((team) => (
                    <SelectItem key={team.id} value={team.id}>
                      {team.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <RetentionFields
              days={form.retention_days}
              action={form.retention_action}
              onChange={set}
              appConfig={appConfig}
            />

            <div className="space-y-3 pt-2">
              <Label>Active Analyzers</Label>
              <AnalyzerChecklist
                idPrefix="create-analyzer"
                selected={analyzers}
                onToggle={toggleAnalyzer}
                className="max-h-[300px]"
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={handleClose}>
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
