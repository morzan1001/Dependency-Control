import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getProjects, createProject, getTeams, Project } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Plus, FolderGit2, AlertTriangle, AlertCircle, Info, Copy, Check } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from "sonner";
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

const AVAILABLE_ANALYZERS = [
  { id: 'end_of_life', label: 'End of Life (EOL)' },
  { id: 'os_malware', label: 'Open Source Malware' },
  { id: 'trivy', label: 'Trivy (Container/FS)' },
  { id: 'osv', label: 'OSV (Open Source Vulnerabilities)' },
  { id: 'deps_dev', label: 'Deps.dev (Google)' },
  { id: 'license_compliance', label: 'License Compliance' },
  { id: 'grype', label: 'Grype (Anchore)' },
  { id: 'outdated_packages', label: 'Outdated Packages' },
  { id: 'typosquatting', label: 'Typosquatting' },
];

export default function ProjectsPage() {
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [teamId, setTeamId] = useState<string | undefined>(undefined);
  const [retentionDays, setRetentionDays] = useState(90);
  const [analyzers, setAnalyzers] = useState<string[]>(['end_of_life']);
  const [createdProjectData, setCreatedProjectData] = useState<{ project_id: string, api_key: string, note: string } | null>(null);
  const [hasCopied, setHasCopied] = useState(false);

  const { data: projects, isLoading: isLoadingProjects, error: errorProjects } = useQuery({
    queryKey: ['projects'],
    queryFn: getProjects,
  });

  const { data: teams } = useQuery({
    queryKey: ['teams'],
    queryFn: getTeams,
  });

  const createProjectMutation = useMutation({
    mutationFn: (data: { name: string; team_id?: string; active_analyzers: string[]; retention_days: number }) => createProject(data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setCreatedProjectData(data);
      toast.success("Project created successfully");
    },
    onError: (error: any) => {
        toast.error("Failed to create project", {
            description: error.response?.data?.detail || "An error occurred"
        });
    }
  });

  const handleCreateProject = (e: React.FormEvent) => {
    e.preventDefault();
    createProjectMutation.mutate({
        name,
        team_id: teamId === "none" ? undefined : teamId,
        active_analyzers: analyzers,
        retention_days: retentionDays
    });
  };

  const handleCloseCreate = () => {
    setIsCreateOpen(false);
    setCreatedProjectData(null);
    setName('');
    setTeamId(undefined);
    setRetentionDays(90);
    setAnalyzers(['end_of_life']);
    setHasCopied(false);
  }

  const copyToClipboard = () => {
    if (createdProjectData?.api_key) {
      navigator.clipboard.writeText(createdProjectData.api_key);
      setHasCopied(true);
      toast.success("API Key copied to clipboard");
      setTimeout(() => setHasCopied(false), 2000);
    }
  }

  const toggleAnalyzer = (analyzer: string) => {
      setAnalyzers(prev => 
          prev.includes(analyzer) 
              ? prev.filter(a => a !== analyzer)
              : [...prev, analyzer]
      );
  }

  if (isLoadingProjects) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-10 w-32" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
        </div>
      </div>
    );
  }

  if (errorProjects) {
    return <div className="text-destructive">Error loading projects: {errorProjects.message}</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight">Projects</h1>
        
        {hasPermission('project:create') && (
          <Dialog open={isCreateOpen} onOpenChange={(open) => {
            if (!open && createdProjectData) {
              handleCloseCreate();
            } else if (!open) {
              setIsCreateOpen(false);
            } else {
              setIsCreateOpen(true);
            }
          }}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Project
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[500px]">
              <DialogHeader>
                <DialogTitle>{createdProjectData ? 'Project Created' : 'Create Project'}</DialogTitle>
                <DialogDescription>
                  {createdProjectData 
                    ? 'Your project has been created. Please save this API Key securely as it will not be shown again.' 
                    : 'Create a new project to start scanning for vulnerabilities.'}
                </DialogDescription>
              </DialogHeader>
              
              {createdProjectData ? (
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label>Project ID</Label>
                    <div className="p-2 bg-muted rounded-md font-mono text-sm select-all">
                      {createdProjectData.project_id}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label>API Key</Label>
                    <div className="flex items-center gap-2">
                      <div className="p-2 bg-muted rounded-md font-mono text-sm flex-1 break-all">
                        {createdProjectData.api_key}
                      </div>
                      <Button size="icon" variant="outline" onClick={copyToClipboard}>
                        {hasCopied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground text-red-500 font-medium">
                      {createdProjectData.note}
                    </p>
                  </div>
                  <DialogFooter>
                    <Button onClick={handleCloseCreate} className="w-full">
                      I have saved the key
                    </Button>
                  </DialogFooter>
                </div>
              ) : (
                <form onSubmit={handleCreateProject}>
                  <div className="grid gap-4 py-4">
                    <div className="grid gap-2">
                      <Label htmlFor="name">Project Name</Label>
                      <Input
                        id="name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="My Awesome App"
                        required
                      />
                    </div>
                    
                    <div className="grid gap-2">
                      <Label htmlFor="team">Team (Optional)</Label>
                      <Select value={teamId} onValueChange={setTeamId}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select a team" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">No Team</SelectItem>
                          {teams?.map((team) => (
                            <SelectItem key={team._id} value={team._id}>
                              {team.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="grid gap-2">
                      <Label htmlFor="retention">Retention Period (Days)</Label>
                      <Input
                        id="retention"
                        type="number"
                        min="1"
                        value={retentionDays}
                        onChange={(e) => setRetentionDays(parseInt(e.target.value))}
                        required
                      />
                    </div>

                    <div className="grid gap-2">
                      <Label>Active Analyzers</Label>
                      <div className="flex flex-col gap-2 border rounded-md p-4 max-h-[200px] overflow-y-auto">
                        {AVAILABLE_ANALYZERS.map((analyzer) => (
                          <div key={analyzer.id} className="flex items-center space-x-2">
                            <Checkbox 
                              id={`analyzer-${analyzer.id}`}
                              checked={analyzers.includes(analyzer.id)}
                              onCheckedChange={() => toggleAnalyzer(analyzer.id)}
                            />
                            <Label htmlFor={`analyzer-${analyzer.id}`} className="font-normal cursor-pointer">
                              {analyzer.label}
                            </Label>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button type="button" variant="outline" onClick={() => setIsCreateOpen(false)}>
                      Cancel
                    </Button>
                    <Button type="submit" disabled={createProjectMutation.isPending}>
                      {createProjectMutation.isPending ? "Creating..." : "Create Project"}
                    </Button>
                  </DialogFooter>
                </form>
              )}
            </DialogContent>
          </Dialog>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {projects?.map((project: Project) => (
          <Link key={project._id} to={`/projects/${project._id}`}>
            <Card className="hover:bg-muted/50 transition-colors cursor-pointer h-full">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium truncate pr-4">
                  {project.name}
                </CardTitle>
                <FolderGit2 className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2 mt-2">
                    <div className="flex items-center gap-2 text-sm text-red-500">
                        <AlertCircle className="h-4 w-4" />
                        <span className="font-bold">{project.stats?.critical || 0}</span> Critical
                    </div>
                    <div className="flex items-center gap-2 text-sm text-orange-500">
                        <AlertTriangle className="h-4 w-4" />
                        <span className="font-bold">{project.stats?.high || 0}</span> High
                    </div>
                    <div className="flex items-center gap-2 text-sm text-yellow-500">
                        <Info className="h-4 w-4" />
                        <span className="font-bold">{project.stats?.medium || 0}</span> Medium
                    </div>
                    <div className="flex items-center gap-2 text-sm text-blue-500">
                        <Info className="h-4 w-4" />
                        <span className="font-bold">{project.stats?.low || 0}</span> Low
                    </div>
                </div>
                
                <div className="mt-4 text-xs text-muted-foreground">
                    Last scan: {project.last_scan_at ? new Date(project.last_scan_at).toLocaleDateString() : 'Never'}
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                    {project.active_analyzers?.map(analyzer => (
                        <span key={analyzer} className="inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                            {analyzer}
                        </span>
                    ))}
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
