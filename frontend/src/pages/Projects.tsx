import { useState, useEffect } from 'react';
import { useProjects } from '@/hooks/queries/use-projects';
import { useAppConfig } from '@/hooks/queries/use-system';
import { useAuth } from '@/context/useAuth';
import { useDebounce } from '@/hooks/use-debounce';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Plus, FolderGit2, AlertTriangle, AlertCircle, Info, ArrowUp, ArrowDown } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Project } from '@/types/project';
import { Skeleton } from '@/components/ui/skeleton';
import { AVAILABLE_ANALYZERS } from '@/lib/constants';
import { CreateProjectDialog } from '@/components/project/CreateProjectDialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export default function ProjectsPage() {
  const { hasPermission } = useAuth();
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const limit = 12;

  const debouncedSearch = useDebounce(search, 300);

  // Reset page when search changes
  useEffect(() => {
    setPage(1);
  }, [debouncedSearch]);

  const { data: projectsData, isLoading: isLoadingProjects, error: errorProjects } = useProjects(
    debouncedSearch,
    page,
    limit,
    sortBy,
    sortOrder
  );

  const projects = projectsData?.items || [];
  const totalPages = projectsData?.pages || 0;

  const { data: appConfig } = useAppConfig();

  const isLimitReached = () => {
      if (hasPermission('sysadmin')) return false;
      // 0 means unlimited
      if (!appConfig?.project_limit_per_user) return false;
      if (projectsData?.total !== undefined) {
         return projectsData.total >= appConfig.project_limit_per_user;
      }
      return false;
  };

  if (isLoadingProjects) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-10 w-32" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3, 4, 5, 6].map(i => (
             <Skeleton key={i} className="h-48 rounded-xl" />
          ))}
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
        
        <div className="flex items-center gap-2">
          <Input 
            placeholder="Search projects..." 
            value={search} 
            onChange={(e) => setSearch(e.target.value)}
            className="w-[250px]"
          />
          <Select value={sortBy} onValueChange={setSortBy}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="created_at">Created Date</SelectItem>
              <SelectItem value="name">Name</SelectItem>
              <SelectItem value="last_scan_at">Last Scan</SelectItem>
              <SelectItem value="critical">Critical Vulns</SelectItem>
              <SelectItem value="high">High Vulns</SelectItem>
              <SelectItem value="risk_score">Risk Score</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="icon"
            onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
          >
            {sortOrder === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />}
          </Button>
          {hasPermission('project:create') && (
            <Button onClick={() => setIsCreateOpen(true)} disabled={isLimitReached()}>
              <Plus className="mr-2 h-4 w-4" />
              New Project
            </Button>
          )}
        </div>
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
                    {project.active_analyzers?.slice(0, 6).map(analyzerId => {
                        const analyzerInfo = AVAILABLE_ANALYZERS.find(a => a.id === analyzerId);
                        return (
                          <span 
                            key={analyzerId} 
                            className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent ${
                              analyzerInfo?.isPostProcessor 
                                ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                                : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
                            }`}
                            title={analyzerInfo?.description}
                          >
                            {analyzerInfo?.label || analyzerId}
                          </span>
                        );
                    })}
                    {(project.active_analyzers?.length || 0) > 6 && (
                      <span className="inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold bg-muted text-muted-foreground">
                        +{project.active_analyzers!.length - 6} more
                      </span>
                    )}
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
      
      <div className="flex items-center justify-center space-x-2 py-4">
        <Button
          variant="outline"
          size="sm"
          onClick={() => setPage((p) => Math.max(1, p - 1))}
          disabled={page === 1}
        >
          Previous
        </Button>
        <div className="text-sm text-muted-foreground">
          Page {page} of {totalPages || 1}
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          disabled={page === totalPages || totalPages === 0}
        >
          Next
        </Button>
      </div>

      <CreateProjectDialog 
        open={isCreateOpen} 
        onOpenChange={setIsCreateOpen} 
      />
    </div>
  );
}
    