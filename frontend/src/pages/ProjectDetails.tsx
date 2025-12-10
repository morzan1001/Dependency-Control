import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getProject, getMe } from '@/lib/api'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { ArrowLeft, Download } from 'lucide-react'
import { Spinner } from '@/components/ui/spinner'
import { toast } from "sonner"
import { ProjectOverview } from '@/components/project/ProjectOverview'
import { ProjectScans } from '@/components/project/ProjectScans'
import { ProjectWaivers } from '@/components/project/ProjectWaivers'
import { ProjectMembers } from '@/components/project/ProjectMembers'
import { ProjectSettings } from '@/components/project/ProjectSettings'
import { exportProjectCsv, exportProjectSbom } from '@/lib/api'

export default function ProjectDetails() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  
  const { data: project, isLoading: isLoadingProject } = useQuery({
    queryKey: ['project', id],
    queryFn: () => getProject(id!),
    enabled: !!id
  })

  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
  })

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
    } catch (error) {
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
    } catch (error) {
      toast.error("Failed to export SBOM")
    }
  }

  if (isLoadingProject) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Spinner className="h-8 w-8" />
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

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="scans">Scans</TabsTrigger>
          <TabsTrigger value="waivers">Waivers</TabsTrigger>
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview" className="space-y-4">
          <ProjectOverview projectId={project._id} />
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
        
        <TabsContent value="settings" className="space-y-4">
          <ProjectSettings project={project} projectId={project._id} user={user} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
