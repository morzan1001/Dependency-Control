import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getProject, getMe, getProjectBranches, exportProjectCsv, exportProjectSbom } from '@/lib/api'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { ArrowLeft, Download, Filter } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { toast } from "sonner"
import { ProjectOverview } from '@/components/project/ProjectOverview'
import { ProjectScans } from '@/components/project/ProjectScans'
import { ProjectWaivers } from '@/components/project/ProjectWaivers'
import { ProjectMembers } from '@/components/project/ProjectMembers'
import { ProjectSettings } from '@/components/project/ProjectSettings'
import { useState, useEffect } from 'react'
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
  
  const { data: project, isLoading: isLoadingProject } = useQuery({
    queryKey: ['project', id],
    queryFn: () => getProject(id!),
    enabled: !!id
  })

  const { data: branches } = useQuery({
    queryKey: ['project-branches', id],
    queryFn: () => getProjectBranches(id!),
    enabled: !!id
  })

  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
  })

  const allBranches = branches || []

  // Initialize selected branches with default branch or all branches
  useEffect(() => {
    if (allBranches.length > 0 && selectedBranches.length === 0) {
      if (project?.default_branch && allBranches.includes(project.default_branch)) {
        setSelectedBranches([project.default_branch])
      } else {
        setSelectedBranches(allBranches)
      }
    }
    // Only run when branches data changes, not when selectedBranches changes (to avoid infinite loop)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allBranches, project])

  const toggleBranch = (branch: string) => {
      setSelectedBranches(prev => 
          prev.includes(branch) 
              ? prev.filter(b => b !== branch)
              : [...prev, branch]
      )
  }

  const toggleAllBranches = () => {
      if (selectedBranches.length === allBranches.length) {
          setSelectedBranches([])
      } else {
          setSelectedBranches(allBranches)
      }
  }

  const handleExportCsv = async () => {
    try {
      const blob = await exportProjectCsv(id!)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `project-${project?.name}-export.csv`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch {
      toast.error("Failed to export CSV")
    }
  }

  const handleExportSbom = async () => {
    try {
      const blob = await exportProjectSbom(id!)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `project-${project?.name}-sbom.json`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch {
      toast.error("Failed to export SBOM")
    }
  }

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
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Button variant="ghost" size="icon" asChild>
            <Link to="/dashboard">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">{project.name}</h1>
            <p className="text-muted-foreground">
              Project ID: {project._id}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
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
            <TabsTrigger value="scans">Pipelines</TabsTrigger>
            <TabsTrigger value="waivers">Waivers</TabsTrigger>
            <TabsTrigger value="members">Members</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>
          
          {activeTab === 'overview' && (
            <Dialog open={isBranchFilterOpen} onOpenChange={setIsBranchFilterOpen}>
              <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="gap-2">
                      <Filter className="h-4 w-4" />
                      Filter Branches
                      {selectedBranches.length < allBranches.length && (
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
                              checked={selectedBranches.length === allBranches.length && allBranches.length > 0}
                              onCheckedChange={toggleAllBranches}
                          />
                          <Label htmlFor="select-all" className="font-bold cursor-pointer">Select All</Label>
                      </div>
                      <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2">
                          {allBranches.map(branch => (
                              <div key={branch} className="flex items-center space-x-2">
                                  <Checkbox 
                                      id={`branch-${branch}`}
                                      checked={selectedBranches.includes(branch)}
                                      onCheckedChange={() => toggleBranch(branch)}
                                  />
                                  <Label htmlFor={`branch-${branch}`} className="cursor-pointer font-normal">{branch}</Label>
                              </div>
                          ))}
                          {allBranches.length === 0 && (
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
          <ProjectOverview projectId={project._id} selectedBranches={selectedBranches} />
        </TabsContent>
        
        <TabsContent value="scans" className="space-y-4">
          <ProjectScans projectId={project._id} />
        </TabsContent>
        
        <TabsContent value="waivers" className="space-y-4">
          <ProjectWaivers projectId={project._id} />
        </TabsContent>
        
        <TabsContent value="members" className="space-y-4">
          <ProjectMembers project={project} projectId={project._id} />
        </TabsContent>
        
        {user && (
          <TabsContent value="settings" className="space-y-4">
            <ProjectSettings project={project} projectId={project._id} user={user} />
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}
