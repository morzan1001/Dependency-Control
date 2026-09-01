import { useParams, Link, useNavigate } from 'react-router-dom'
import { projectApi } from '@/api/projects'
import { useProject, useProjectBranches } from '@/hooks/queries/use-projects'
import { useCurrentUser } from '@/hooks/queries/use-users'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { ArrowLeft, Download, Filter, Trash2 } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { downloadFile, downloadServerFile } from '@/lib/download'
import { ProjectOverview } from '@/components/project/ProjectOverview'
import { ProjectScans } from '@/components/project/ProjectScans'
import { ProjectWaivers } from '@/components/project/ProjectWaivers'
import { ProjectMembers } from '@/components/project/ProjectMembers'
import { ProjectSettings } from '@/components/project/ProjectSettings'
import { ProjectArchives } from '@/components/project/ProjectArchives'
import { ProjectInventory } from '@/components/project/inventory/ProjectInventory'
import { initialBranchSelection } from '@/lib/branches'


import { useState, useMemo } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"

export default function ProjectDetails() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [selectedBranches, setSelectedBranches] = useState<string[]>([])
  const [isBranchFilterOpen, setIsBranchFilterOpen] = useState(false)
  const [activeTab, setActiveTab] = useState("overview")

  const [hasInitializedBranches, setHasInitializedBranches] = useState(false)

  const { data: project, isLoading: isLoadingProject } = useProject(id!)

  const { data: branches, isSuccess: branchesSuccess } = useProjectBranches(id!)

  const { data: user } = useCurrentUser()

  const allBranchNames = branches?.map(b => b.name) || []
  const activeBranchNames = useMemo(() => branches?.filter(b => b.is_active).map(b => b.name) || [], [branches])
  const deletedBranchNames = useMemo(() => branches?.filter(b => !b.is_active).map(b => b.name) || [], [branches])

  // Initialize once; the flag (not length===0) preserves an intentionally empty selection and
  // short-circuits next render, so this render-phase set doesn't loop.
  if (branchesSuccess && !hasInitializedBranches) {
    setHasInitializedBranches(true)
    setSelectedBranches(initialBranchSelection(branches ?? []))
  }

  const toggleBranch = (branch: string) => {
      setSelectedBranches(prev =>
          prev.includes(branch)
              ? prev.filter(b => b !== branch)
              : [...prev, branch]
      )
  }

  const toggleAllBranches = () => {
      if (selectedBranches.length === activeBranchNames.length) {
          setSelectedBranches([])
      } else {
          setSelectedBranches(activeBranchNames)
      }
  }

  const handleExportCsv = () => downloadFile(
    () => projectApi.exportCsv(id!),
    `project-${project?.name}-export.csv`,
    "Failed to export CSV"
  )

  const handleExportSbom = () => downloadServerFile(
    () => projectApi.exportSbom(id!),
    `project-${project?.name}-sbom.json`,
    "Failed to export SBOM"
  )

  if (isLoadingProject) {
    return (
      <div className="container mx-auto py-6 space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-10 rounded-full" />
          <div className="space-y-2">
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-4 w-32" />
          </div>
        </div>
        <Skeleton className="h-[400px] w-full" />
      </div>
    )
  }

  if (!project) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-4">
        <h1 className="text-2xl font-bold">Project not found</h1>
        <Button onClick={() => navigate('/dashboard')}>Go to Dashboard</Button>
      </div>
    )
  }

  return (
    <div className="container mx-auto py-10 space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4 min-w-0">
          <Button variant="ghost" size="icon" asChild className="shrink-0">
            <Link to="/dashboard">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <div className="min-w-0">
            <h1 className="text-3xl font-bold tracking-tight break-words">{project.name}</h1>
            <p className="text-muted-foreground truncate">
              Project ID: {project.id}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" onClick={handleExportCsv}>
            <Download className="mr-2 h-4 w-4" />
            Export CSV
          </Button>
          <Button variant="outline" onClick={handleExportSbom}>
            <Download className="mr-2 h-4 w-4" />
            Export SBOM
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <div className="flex items-center justify-between">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="inventory">Inventory</TabsTrigger>
            <TabsTrigger value="scans">Pipelines</TabsTrigger>
            <TabsTrigger value="waivers">Waivers</TabsTrigger>
            <TabsTrigger value="members">Members</TabsTrigger>
            <TabsTrigger value="archives">Archives</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>
          
          {activeTab === 'overview' && (
            <Dialog open={isBranchFilterOpen} onOpenChange={setIsBranchFilterOpen}>
              <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="gap-2">
                      <Filter className="h-4 w-4" />
                      Filter Branches
                      {selectedBranches.length < activeBranchNames.length && (
                          <span className="bg-primary text-primary-foreground text-xs rounded-full w-5 h-5 flex items-center justify-center">
                              {selectedBranches.length}
                          </span>
                      )}
                  </Button>
              </DialogTrigger>
              <DialogContent>
                  <DialogHeader>
                      <DialogTitle>Filter Branches</DialogTitle>
                      <DialogDescription>
                          Select which branches to include in the analysis and charts.
                      </DialogDescription>
                  </DialogHeader>
                  <div className="py-4 space-y-4">
                      <div className="flex items-center space-x-2 border-b pb-2">
                          <Checkbox
                              id="select-all"
                              checked={selectedBranches.length === activeBranchNames.length && activeBranchNames.length > 0}
                              onCheckedChange={toggleAllBranches}
                          />
                          <Label htmlFor="select-all" className="font-bold cursor-pointer">Select All Active</Label>
                      </div>
                      <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2">
                          {activeBranchNames.length > 0 && (
                            <>
                              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider pt-1">Active</p>
                              {activeBranchNames.map(branch => (
                                  <div key={branch} className="flex items-center space-x-2">
                                      <Checkbox
                                          id={`branch-${branch}`}
                                          checked={selectedBranches.includes(branch)}
                                          onCheckedChange={() => toggleBranch(branch)}
                                      />
                                      <Label htmlFor={`branch-${branch}`} className="cursor-pointer font-normal">{branch}</Label>
                                  </div>
                              ))}
                            </>
                          )}
                          {deletedBranchNames.length > 0 && (
                            <>
                              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider pt-3 flex items-center gap-1">
                                <Trash2 className="h-3 w-3" /> Deleted
                              </p>
                              {deletedBranchNames.map(branch => (
                                  <div key={branch} className="flex items-center space-x-2">
                                      <Checkbox
                                          id={`branch-${branch}`}
                                          checked={selectedBranches.includes(branch)}
                                          onCheckedChange={() => toggleBranch(branch)}
                                      />
                                      <Label htmlFor={`branch-${branch}`} className="cursor-pointer font-normal text-muted-foreground">{branch}</Label>
                                  </div>
                              ))}
                            </>
                          )}
                          {allBranchNames.length === 0 && (
                              <p className="text-sm text-muted-foreground">No branches found.</p>
                          )}
                      </div>
                  </div>
                  <DialogFooter>
                      <Button onClick={() => setIsBranchFilterOpen(false)}>Done</Button>
                  </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
        </div>
        
        <TabsContent value="overview" className="space-y-4">
          <ProjectOverview projectId={project.id} selectedBranches={selectedBranches} />
        </TabsContent>

        <TabsContent value="inventory" className="space-y-4">
          <ProjectInventory projectId={id!} projectName={project.name} defaultBranch={project.default_branch} />
        </TabsContent>

        <TabsContent value="scans" className="space-y-4">
          <ProjectScans projectId={project.id} />
        </TabsContent>
        
        <TabsContent value="waivers" className="space-y-4">
          <ProjectWaivers projectId={project.id} />
        </TabsContent>
        
        <TabsContent value="members" className="space-y-4">
          <ProjectMembers project={project} projectId={project.id} />
        </TabsContent>

        <TabsContent value="archives" className="space-y-4">
          <ProjectArchives projectId={project.id} />
        </TabsContent>

        {user && (
          <TabsContent value="settings" className="space-y-4">
            <ProjectSettings key={project.id} project={project} projectId={project.id} user={user} />
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}
