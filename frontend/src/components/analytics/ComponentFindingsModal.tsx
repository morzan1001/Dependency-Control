import { useState, useMemo } from 'react'
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
import { AlertTriangle, ExternalLink, Shield, ArrowUp, ArrowDown } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

type SortField = 'id' | 'type' | 'severity' | 'project_name' | 'description'
type SortOrder = 'asc' | 'desc'

// Severity order for sorting
const severityOrder: Record<string, number> = {
  'CRITICAL': 4,
  'HIGH': 3,
  'MEDIUM': 2,
  'LOW': 1,
  'UNKNOWN': 0,
}

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
  const [sortBy, setSortBy] = useState<SortField>('severity')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')

  const { data: findings, isLoading } = useQuery({
    queryKey: ['component-findings', component, version],
    queryFn: () => getComponentFindings(component, version),
    enabled: open && !!component,
  })

  const sortedFindings = useMemo(() => {
    if (!findings) return []
    
    return [...findings].sort((a, b) => {
      let comparison = 0
      
      switch (sortBy) {
        case 'id':
          comparison = (a.id || '').localeCompare(b.id || '')
          break
        case 'type':
          comparison = (a.type || '').localeCompare(b.type || '')
          break
        case 'severity':
          const sevA = severityOrder[a.severity?.toUpperCase() || 'UNKNOWN'] || 0
          const sevB = severityOrder[b.severity?.toUpperCase() || 'UNKNOWN'] || 0
          comparison = sevA - sevB
          break
        case 'project_name':
          comparison = ((a as any).project_name || '').localeCompare((b as any).project_name || '')
          break
        case 'description':
          comparison = (a.description || '').localeCompare(b.description || '')
          break
      }
      
      return sortOrder === 'asc' ? comparison : -comparison
    })
  }, [findings, sortBy, sortOrder])

  const handleSort = (field: SortField) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      // Default to desc for severity, asc for others
      setSortOrder(field === 'severity' ? 'desc' : 'asc')
    }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortBy !== field) return null
    return sortOrder === 'asc' 
      ? <ArrowUp className="h-4 w-4 inline-block ml-1" />
      : <ArrowDown className="h-4 w-4 inline-block ml-1" />
  }

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
        ) : sortedFindings && sortedFindings.length > 0 ? (
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead 
                  className="w-[150px] cursor-pointer hover:bg-muted/50"
                  onClick={() => handleSort('id')}
                >
                  Finding
                  <SortIcon field="id" />
                </TableHead>
                <TableHead 
                  className="w-[100px] cursor-pointer hover:bg-muted/50"
                  onClick={() => handleSort('type')}
                >
                  Type
                  <SortIcon field="type" />
                </TableHead>
                <TableHead 
                  className="w-[100px] cursor-pointer hover:bg-muted/50"
                  onClick={() => handleSort('severity')}
                >
                  Severity
                  <SortIcon field="severity" />
                </TableHead>
                <TableHead 
                  className="w-[150px] cursor-pointer hover:bg-muted/50"
                  onClick={() => handleSort('project_name')}
                >
                  Project
                  <SortIcon field="project_name" />
                </TableHead>
                <TableHead 
                  className="w-[250px] cursor-pointer hover:bg-muted/50"
                  onClick={() => handleSort('description')}
                >
                  Description
                  <SortIcon field="description" />
                </TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedFindings.map((finding, index) => (
                <TableRow key={`${finding.id}-${index}`}>
                  <TableCell className="truncate">
                    <div className="flex items-center gap-2 min-w-0">
                      <AlertTriangle className="h-4 w-4 text-destructive flex-shrink-0" />
                      <span className="font-mono text-sm truncate">{finding.id}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="truncate">{finding.type}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge className={getSeverityColor(finding.severity)}>
                      {finding.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="truncate">
                    <Link 
                      to={`/projects/${(finding as any).project_id}`}
                      className="hover:underline text-primary truncate block"
                    >
                      {(finding as any).project_name || 'Unknown'}
                    </Link>
                  </TableCell>
                  <TableCell className="truncate">
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
