import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useState, useMemo } from 'react'
import { getScanResults, getScan, AnalysisResult } from '@/lib/api'
import { FindingDetailsModal } from '@/components/FindingDetailsModal'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ArrowLeft, FileJson, CheckCircle, Package, Scale, ShieldAlert, Activity, AlertTriangle, Info, GitBranch, GitCommit, Calendar, ArrowUpDown } from 'lucide-react'
import { Spinner } from '@/components/ui/spinner'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'

export default function ScanDetails() {
  const { projectId, scanId } = useParams<{ projectId: string, scanId: string }>()

  const { data: scan, isLoading: isScanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId
  })

  const { data: results, isLoading: isResultsLoading } = useQuery({
    queryKey: ['scan-results', scanId],
    queryFn: () => getScanResults(scanId!),
    enabled: !!scanId
  })

  if (isScanLoading || isResultsLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <Spinner size={48} />
      </div>
    )
  }

  if (!scan || !results) {
    return <div>No results found</div>
  }

  const findingsByCategory = {
      Security: 0,
      Compliance: 0,
      Quality: 0
  };

  const severityCounts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
      UNKNOWN: 0
  };
  
  if (scan && scan.findings_summary) {
      scan.findings_summary.forEach((finding: any) => {
          if (finding.waived) return;

          const type = finding.type || 'unknown';
          
          if (['vulnerability', 'secret', 'malware', 'typosquatting'].includes(type)) {
              findingsByCategory.Security++;
          } else if (['license', 'eol'].includes(type)) {
              findingsByCategory.Compliance++;
          } else if (['outdated', 'quality'].includes(type)) {
              findingsByCategory.Quality++;
          }

          const severity = finding.severity || 'UNKNOWN';
          if (severity in severityCounts) {
              severityCounts[severity]++;
          } else {
              severityCounts.UNKNOWN++;
          }
      });
  }

  const categoryData = Object.entries(findingsByCategory)
      .map(([name, value]) => ({ name, value }))
      .filter(d => d.value > 0);

  const severityData = [
      { name: 'Critical', value: severityCounts.CRITICAL, color: '#ef4444' },
      { name: 'High', value: severityCounts.HIGH, color: '#f97316' },
      { name: 'Medium', value: severityCounts.MEDIUM, color: '#eab308' },
      { name: 'Low', value: severityCounts.LOW, color: '#3b82f6' },
      { name: 'Info', value: severityCounts.INFO, color: '#60a5fa' },
      { name: 'Unknown', value: severityCounts.UNKNOWN, color: '#9ca3af' },
  ].filter(d => d.value > 0);

  const CATEGORY_COLORS: Record<string, string> = {
      Security: '#ef4444',
      Compliance: '#3b82f6',
      Quality: '#10b981'
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link to={`/projects/${projectId}`}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Scan Details</h2>
          <p className="text-muted-foreground text-sm">ID: {scanId}</p>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="compliance">Compliance</TabsTrigger>
            <TabsTrigger value="quality">Quality</TabsTrigger>
            <TabsTrigger value="raw">Raw Data</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
            <Card>
                <CardHeader>
                    <CardTitle>Scan Metadata</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Status</span>
                            <div>
                                <Badge variant={scan.status === 'completed' ? 'default' : 'secondary'}>
                                    {scan.status}
                                </Badge>
                            </div>
                        </div>
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Branch</span>
                            <div className="flex items-center gap-2">
                                <GitBranch className="h-4 w-4" />
                                <span className="font-medium">{scan.branch}</span>
                            </div>
                        </div>
                        {scan.commit_hash && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Commit</span>
                                <div className="flex items-center gap-2">
                                    <GitCommit className="h-4 w-4" />
                                    <span className="font-medium font-mono text-xs">{scan.commit_hash.substring(0, 7)}</span>
                                </div>
                            </div>
                        )}
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Ignored Findings</span>
                            <div className="flex items-center gap-2">
                                <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                                <span className="font-medium">{scan.ignored_count || 0}</span>
                            </div>
                        </div>
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Started</span>
                            <div className="flex items-center gap-2">
                                <Calendar className="h-4 w-4" />
                                <span className="text-sm">{new Date(scan.created_at).toLocaleString()}</span>
                            </div>
                        </div>
                        {scan.completed_at && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Completed</span>
                                <div className="flex items-center gap-2">
                                    <CheckCircle className="h-4 w-4 text-green-500" />
                                    <span className="text-sm">{new Date(scan.completed_at).toLocaleString()}</span>
                                </div>
                            </div>
                        )}
                    </div>
                </CardContent>
            </Card>

            {categoryData.length > 0 ? (
                <div className="grid gap-4 md:grid-cols-2">
                    <Card>
                        <CardHeader>
                            <CardTitle>Findings by Category</CardTitle>
                            <CardDescription>Overview of this scan's results</CardDescription>
                        </CardHeader>
                        <CardContent className="h-[300px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={categoryData} layout="vertical" margin={{ left: 40 }}>
                                    <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                                    <XAxis type="number" allowDecimals={false} />
                                    <YAxis dataKey="name" type="category" width={100} />
                                    <Tooltip />
                                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                                        {categoryData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={CATEGORY_COLORS[entry.name] || '#8884d8'} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>Severity Distribution</CardTitle>
                            <CardDescription>Breakdown by severity level</CardDescription>
                        </CardHeader>
                        <CardContent className="h-[300px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={severityData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {severityData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                    </Pie>
                                    <Tooltip />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                </div>
            ) : (
                <div className="flex h-[200px] items-center justify-center rounded-md border border-dashed">
                    <p className="text-muted-foreground">No findings found in this scan.</p>
                </div>
            )}
        </TabsContent>

        <TabsContent value="security">
            <SecurityTab findings={scan.findings_summary || []} projectId={projectId!} />
        </TabsContent>

        <TabsContent value="compliance">
            <ComplianceTab findings={scan.findings_summary || []} projectId={projectId!} />
        </TabsContent>

        <TabsContent value="quality">
            <QualityTab findings={scan.findings_summary || []} projectId={projectId!} />
        </TabsContent>

        <TabsContent value="raw">
            <Tabs defaultValue={results[0]?.analyzer_name || 'sbom'} className="space-y-4">
                <div className="w-full overflow-x-auto rounded-md border">
                    <div className="flex w-max space-x-4 p-4">
                        <TabsList className="h-auto flex-wrap justify-start gap-2 bg-transparent p-0">
                            {results.map((result) => (
                                <TabsTrigger 
                                    key={result.analyzer_name} 
                                    value={result.analyzer_name}
                                    className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground border px-4 py-2"
                                >
                                {result.analyzer_name.replace(/_/g, ' ').toUpperCase()}
                                </TabsTrigger>
                            ))}
                            <TabsTrigger 
                                value="sbom"
                                className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground border px-4 py-2"
                            >
                                SBOM
                            </TabsTrigger>
                        </TabsList>
                    </div>
                </div>

                {results.map((result) => (
                <TabsContent key={result.analyzer_name} value={result.analyzer_name}>
                    <AnalyzerResultView result={result} />
                </TabsContent>
                ))}

                <TabsContent value="sbom">
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <FileJson className="h-5 w-5" />
                                SBOM (Software Bill of Materials)
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            <pre className="bg-muted p-4 rounded-lg overflow-auto max-h-[600px] text-xs">
                                {JSON.stringify(scan.sbom, null, 2)}
                            </pre>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>
        </TabsContent>
      </Tabs>
    </div>
  )
}

function SecurityTab({ findings, projectId }: { findings: any[], projectId: string }) {
    const [selectedFinding, setSelectedFinding] = useState<any>(null)
    const [isModalOpen, setIsModalOpen] = useState(false)

    const securityFindings = findings.filter(f => ['vulnerability', 'secret', 'malware', 'typosquatting'].includes(f.type) && !f.waived);
    
    const stats = {
        critical: securityFindings.filter(f => f.severity === 'CRITICAL').length,
        high: securityFindings.filter(f => f.severity === 'HIGH').length,
        medium: securityFindings.filter(f => f.severity === 'MEDIUM').length,
        low: securityFindings.filter(f => f.severity === 'LOW').length,
    };

    const severityData = [
        { name: 'Critical', value: stats.critical, color: '#ef4444' },
        { name: 'High', value: stats.high, color: '#f97316' },
        { name: 'Medium', value: stats.medium, color: '#eab308' },
        { name: 'Low', value: stats.low, color: '#3b82f6' },
    ].filter(d => d.value > 0);

    return (
        <div className="space-y-6">
            <FindingDetailsModal 
                finding={selectedFinding} 
                isOpen={isModalOpen} 
                onClose={() => setIsModalOpen(false)} 
                projectId={projectId} 
            />
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Critical</CardTitle>
                        <ShieldAlert className="h-4 w-4 text-destructive" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.critical}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">High</CardTitle>
                        <Activity className="h-4 w-4 text-orange-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.high}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Medium</CardTitle>
                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.medium}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Low</CardTitle>
                        <Info className="h-4 w-4 text-blue-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.low}</div>
                    </CardContent>
                </Card>
            </div>

            {severityData.length > 0 && (
                <div className="grid gap-4 md:grid-cols-2">
                    <Card>
                        <CardHeader>
                            <CardTitle>Severity Distribution</CardTitle>
                        </CardHeader>
                        <CardContent className="h-[300px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={severityData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {severityData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                    </Pie>
                                    <Tooltip />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                </div>
            )}

            <Card>
                <CardHeader>
                    <CardTitle>Security Findings</CardTitle>
                </CardHeader>
                <CardContent>
                    <FindingsTable 
                        findings={securityFindings} 
                        showSeverity={true} 
                        onFindingClick={(f) => {
                            setSelectedFinding(f)
                            setIsModalOpen(true)
                        }} 
                    />
                </CardContent>
            </Card>
        </div>
    );
}

function ComplianceTab({ findings, projectId }: { findings: any[], projectId: string }) {
    const [selectedFinding, setSelectedFinding] = useState<any>(null)
    const [isModalOpen, setIsModalOpen] = useState(false)

    const complianceFindings = findings.filter(f => ['license', 'eol'].includes(f.type) && !f.waived);
    
    const stats = {
        license: complianceFindings.filter(f => f.type === 'license').length,
        eol: complianceFindings.filter(f => f.type === 'eol').length,
    };

    return (
        <div className="space-y-6">
            <FindingDetailsModal 
                finding={selectedFinding} 
                isOpen={isModalOpen} 
                onClose={() => setIsModalOpen(false)} 
                projectId={projectId} 
            />
            <div className="grid gap-4 md:grid-cols-2">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">License Issues</CardTitle>
                        <Scale className="h-4 w-4 text-blue-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.license}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">End of Life</CardTitle>
                        <AlertTriangle className="h-4 w-4 text-red-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.eol}</div>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Compliance Findings</CardTitle>
                </CardHeader>
                <CardContent>
                    <FindingsTable 
                        findings={complianceFindings} 
                        showSeverity={false} 
                        onFindingClick={(f) => {
                            setSelectedFinding(f)
                            setIsModalOpen(true)
                        }} 
                    />
                </CardContent>
            </Card>
        </div>
    );
}

function QualityTab({ findings, projectId }: { findings: any[], projectId: string }) {
    const [selectedFinding, setSelectedFinding] = useState<any>(null)
    const [isModalOpen, setIsModalOpen] = useState(false)

    const qualityFindings = findings.filter(f => ['outdated', 'quality'].includes(f.type) && !f.waived);
    
    const stats = {
        outdated: qualityFindings.filter(f => f.type === 'outdated').length,
        quality: qualityFindings.filter(f => f.type === 'quality').length,
    };

    return (
        <div className="space-y-6">
            <FindingDetailsModal 
                finding={selectedFinding} 
                isOpen={isModalOpen} 
                onClose={() => setIsModalOpen(false)} 
                projectId={projectId} 
            />
            <div className="grid gap-4 md:grid-cols-2">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Outdated Packages</CardTitle>
                        <Package className="h-4 w-4 text-orange-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.outdated}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Quality Issues</CardTitle>
                        <CheckCircle className="h-4 w-4 text-green-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats.quality}</div>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Quality Findings</CardTitle>
                </CardHeader>
                <CardContent>
                    <FindingsTable 
                        findings={qualityFindings} 
                        showSeverity={false} 
                        onFindingClick={(f) => {
                            setSelectedFinding(f)
                            setIsModalOpen(true)
                        }} 
                    />
                </CardContent>
            </Card>
        </div>
    );
}

function AnalyzerResultView({ result }: { result: AnalysisResult }) {
    const data = result.result;
    
    return (
        <div className="space-y-4">
            <Card>
                <CardContent className="pt-6">
                    <pre className="bg-muted p-4 rounded-lg overflow-auto max-h-[600px] text-xs">
                        {JSON.stringify(data, null, 2)}
                    </pre>
                </CardContent>
            </Card>
        </div>
    )
}

function FindingsTable({ findings, showSeverity = false, onFindingClick }: { findings: any[], showSeverity?: boolean, onFindingClick: (f: any) => void }) {
    const [searchQuery, setSearchQuery] = useState('')
    const [sortConfig, setSortConfig] = useState<{ key: string, direction: 'asc' | 'desc' } | null>(null)

    const sortedFindings = useMemo(() => {
        let result = [...findings]

        if (searchQuery) {
            const lowerQuery = searchQuery.toLowerCase()
            result = result.filter(f => 
                (f.component || '').toLowerCase().includes(lowerQuery) ||
                (f.description || '').toLowerCase().includes(lowerQuery) ||
                (f.type || '').toLowerCase().includes(lowerQuery)
            )
        }

        if (sortConfig) {
            result.sort((a, b) => {
                let aValue = a[sortConfig.key]
                let bValue = b[sortConfig.key]

                if (sortConfig.key === 'severity') {
                    const severityOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNKNOWN: -1 }
                    aValue = severityOrder[aValue] || -1
                    bValue = severityOrder[bValue] || -1
                }

                if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1
                if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1
                return 0
            })
        }

        return result
    }, [findings, searchQuery, sortConfig])

    const requestSort = (key: string) => {
        let direction: 'asc' | 'desc' = 'asc'
        if (sortConfig && sortConfig.key === key && sortConfig.direction === 'asc') {
            direction = 'desc'
        }
        setSortConfig({ key, direction })
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center gap-2">
                <Input 
                    placeholder="Search findings..." 
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="max-w-sm"
                />
            </div>
            <div className="rounded-md border">
                <Table>
                    <TableHeader>
                        <TableRow>
                            {showSeverity && (
                                <TableHead className="cursor-pointer" onClick={() => requestSort('severity')}>
                                    <div className="flex items-center gap-1">
                                        Severity
                                        {sortConfig?.key === 'severity' && <ArrowUpDown className="h-3 w-3" />}
                                    </div>
                                </TableHead>
                            )}
                            <TableHead className="cursor-pointer" onClick={() => requestSort('type')}>
                                <div className="flex items-center gap-1">
                                    Type
                                    {sortConfig?.key === 'type' && <ArrowUpDown className="h-3 w-3" />}
                                </div>
                            </TableHead>
                            <TableHead className="cursor-pointer" onClick={() => requestSort('component')}>
                                <div className="flex items-center gap-1">
                                    Component
                                    {sortConfig?.key === 'component' && <ArrowUpDown className="h-3 w-3" />}
                                </div>
                            </TableHead>
                            <TableHead>Description</TableHead>
                            <TableHead>Scanner</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {sortedFindings.length > 0 ? (
                            sortedFindings.map((finding, index) => (
                                <TableRow 
                                    key={index} 
                                    className="cursor-pointer hover:bg-muted/50"
                                    onClick={() => onFindingClick(finding)}
                                >
                                    {showSeverity && (
                                        <TableCell>
                                            <Badge variant={
                                                finding.severity === 'CRITICAL' ? 'destructive' :
                                                finding.severity === 'HIGH' ? 'destructive' :
                                                finding.severity === 'MEDIUM' ? 'default' : 'secondary'
                                            }>
                                                {finding.severity}
                                            </Badge>
                                        </TableCell>
                                    )}
                                    <TableCell>
                                        {showSeverity ? finding.type : <Badge variant="outline">{finding.type}</Badge>}
                                    </TableCell>
                                    <TableCell className="font-medium">{finding.component}</TableCell>
                                    <TableCell className="max-w-[300px] truncate" title={finding.description}>
                                        {finding.description}
                                    </TableCell>
                                    <TableCell>
                                        <div className="flex gap-1">
                                            {finding.scanners?.map((s: string) => (
                                                <Badge key={s} variant="outline" className="text-xs">{s}</Badge>
                                            ))}
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ))
                        ) : (
                            <TableRow>
                                <TableCell colSpan={showSeverity ? 5 : 4} className="h-24 text-center">
                                    No findings found.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>
        </div>
    )
}
