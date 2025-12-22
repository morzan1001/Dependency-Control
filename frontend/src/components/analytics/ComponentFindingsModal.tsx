import { useQuery } from '@tanstack/react-query'
import { getComponentFindings } from '@/lib/api'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { AlertTriangle, ExternalLink, Shield } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

interface ComponentFindingsModalProps {
  component: string;
  version?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ComponentFindingsModal({ 
  component, 
  version, 
  open, 
  onOpenChange 
}: ComponentFindingsModalProps) {
  const { data: findings, isLoading } = useQuery({
    queryKey: ['component-findings', component, version],
    queryFn: () => getComponentFindings(component, version),
    enabled: open && !!component,
  })

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'destructive'
      case 'HIGH': return 'bg-orange-500 hover:bg-orange-600'
      case 'MEDIUM': return 'bg-yellow-500 hover:bg-yellow-600 text-black'
      case 'LOW': return 'bg-blue-500 hover:bg-blue-600'
      default: return 'secondary'
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Findings for {component}
            {version && <Badge variant="outline">{version}</Badge>}
          </DialogTitle>
          <DialogDescription>
            All vulnerabilities and findings associated with this component across your projects.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="space-y-2">
            {Array(3).fill(0).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : findings && findings.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Finding</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Description</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((finding, index) => (
                <TableRow key={`${finding.id}-${index}`}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-destructive" />
                      <span className="font-mono text-sm">{finding.id}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">{finding.type}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge className={getSeverityColor(finding.severity)}>
                      {finding.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Link 
                      to={`/projects/${(finding as any).project_id}`}
                      className="hover:underline text-primary"
                    >
                      {(finding as any).project_name || 'Unknown'}
                    </Link>
                  </TableCell>
                  <TableCell className="max-w-[300px]">
                    <p className="truncate text-sm text-muted-foreground" title={finding.description}>
                      {finding.description}
                    </p>
                  </TableCell>
                  <TableCell>
                    {finding.details?.references?.[0] && (
                      <Button variant="ghost" size="icon" asChild>
                        <a 
                          href={finding.details.references[0]} 
                          target="_blank" 
                          rel="noopener noreferrer"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
            <Shield className="h-12 w-12 mb-4 text-green-500" />
            <p>No findings found for this component</p>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
