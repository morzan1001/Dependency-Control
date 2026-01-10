import { Finding } from "@/types/scan"
import { Badge } from "@/components/ui/badge"
import { ExternalLink, AlertTriangle, Info, BookOpen, Shield, Target, Gauge, ChevronDown, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import ReactMarkdown, { Components } from 'react-markdown'
import { useState } from "react"
import { 
    DetailSection, 
    BadgeList, 
    ReferencesList, 
    RiskBadge, 
    FileLocation 
} from "./shared"
import { getSeverityBgColor } from '@/lib/finding-utils'

// Markdown component overrides - defined outside component to avoid re-creation
const markdownComponents: Partial<Components> = {
    code: ({ className, children, ...props }) => {
        const isInline = !className
        if (isInline) {
            return (
                <code className="bg-muted px-1 py-0.5 rounded text-xs font-mono" {...props}>
                    {children}
                </code>
            )
        }
        return (
            <pre className="bg-muted p-3 rounded-lg overflow-auto">
                <code className="text-xs font-mono" {...props}>
                    {children}
                </code>
            </pre>
        )
    },
    h2: ({ children }) => (
        <h5 className="text-sm font-semibold mt-4 mb-2 flex items-center gap-2">
            <Info className="h-4 w-4" />
            {children}
        </h5>
    ),
    ul: ({ children }) => (
        <ul className="list-disc list-inside space-y-1 text-sm">{children}</ul>
    ),
    li: ({ children }) => (
        <li className="text-sm text-muted-foreground">{children}</li>
    ),
}

export interface ScanContext {
    projectUrl?: string | null
    pipelineUrl?: string | null
    commitHash?: string | null
    branch?: string | null
}


interface SastIssueEntry {
    id: string
    scanner: string
    severity: string
    title: string
    description: string
    details: Record<string, any>
}

interface SastDetailsViewProps {
    readonly finding: Finding
    readonly scanContext?: ScanContext
}

export function SastDetailsView({ finding, scanContext }: SastDetailsViewProps) {
    const details = finding.details || {}
    const [expandedIssues, setExpandedIssues] = useState<Set<string>>(new Set())
    
    // Check for aggregated SAST findings
    const sastFindings = (details.sast_findings as SastIssueEntry[]) || []
    
    // Legacy/Single finding logic
    const isBearer = finding.scanners?.includes('bearer')
    const isOpenGrep = finding.scanners?.includes('opengrep')
    const isKics = finding.scanners?.includes('kics')

    const ruleId = details.rule_id || details.check_id || "Unknown"
    const startLine = details.start?.line || details.line
    const endLine = details.end?.line || details.line || startLine

    const toggleIssue = (id: string) => {
        const newExpanded = new Set(expandedIssues)
        if (newExpanded.has(id)) {
            newExpanded.delete(id)
        } else {
            newExpanded.add(id)
        }
        setExpandedIssues(newExpanded)
    }

    // Single Finding View
    const renderSingleFindingDetails = (details: any, findingTitle: string, findingDesc: string, scannerList: string[]) => {
       const localIsBearer = scannerList.includes('bearer')
       const localIsOpenGrep = scannerList.includes('opengrep')
       const localIsKics = scannerList.includes('kics')
       
       const localRuleId = details.rule_id || details.check_id || "Unknown"
       
       return (
         <div className="space-y-4">
            {/* Rule Info */}
            <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                <DetailSection label="Rule ID" compact>
                    <code className="font-mono text-sm bg-background px-2 py-0.5 rounded">{localRuleId}</code>
                </DetailSection>
                <DetailSection label="Scanner" compact>
                     <div className="flex flex-wrap gap-1">
                        {scannerList.map(scanner => (
                            <Badge key={scanner} variant="secondary" className="text-xs">
                                {scanner}
                            </Badge>
                        ))}
                    </div>
                </DetailSection>
            </div>

            {/* Bearer/OpenGrep: Title */}
            {(localIsBearer || localIsOpenGrep) && details.title && details.title !== findingDesc && (
                <DetailSection label="Issue" compact>
                    <p className="text-sm font-medium">{details.title}</p>
                </DetailSection>
            )}

            {/* CWE IDs */}
            {details.cwe_ids && details.cwe_ids.length > 0 && (
                <DetailSection label="CWE References">
                    <BadgeList
                        items={details.cwe_ids}
                        variant="outline"
                        icon={AlertTriangle}
                        formatLabel={(cwe: string) => `CWE-${cwe}`}
                        buildUrl={(cwe: string) => `https://cwe.mitre.org/data/definitions/${cwe}.html`}
                    />
                </DetailSection>
            )}

            {/* OWASP References (OpenGrep) */}
            {details.owasp && details.owasp.length > 0 && (
                <DetailSection label="OWASP References">
                    <BadgeList
                        items={details.owasp}
                        variant="outline"
                        icon={Shield}
                        badgeClassName="text-orange-600 border-orange-300"
                    />
                </DetailSection>
            )}

            {/* Category Groups */}
            {details.category_groups && details.category_groups.length > 0 && (
                <DetailSection label="Categories">
                    <BadgeList items={details.category_groups} variant="secondary" />
                </DetailSection>
            )}

            {/* Risk Assessment (OpenGrep) */}
            {localIsOpenGrep && (details.confidence || details.likelihood || details.impact) && (
                <div className="grid grid-cols-3 gap-4 p-4 bg-muted/50 rounded-lg border">
                    {details.confidence && (
                        <DetailSection label="Confidence" icon={Target} compact>
                            <RiskBadge level={details.confidence} />
                        </DetailSection>
                    )}
                    {details.likelihood && (
                        <DetailSection label="Likelihood" icon={Gauge} compact>
                            <RiskBadge level={details.likelihood} />
                        </DetailSection>
                    )}
                    {details.impact && (
                        <DetailSection label="Impact" icon={AlertTriangle} compact>
                            <RiskBadge level={details.impact} />
                        </DetailSection>
                    )}
                </div>
            )}

            {/* Vulnerability Class, Technology, Subcategory (OpenGrep) */}
            {localIsOpenGrep && (
                ((details.vulnerability_class?.length ?? 0) > 0) ||
                ((details.technology?.length ?? 0) > 0) ||
                ((details.subcategory?.length ?? 0) > 0)
            ) && (
                <div className="flex flex-wrap gap-4">
                    {details.vulnerability_class && details.vulnerability_class.length > 0 && (
                        <DetailSection label="Vulnerability Class">
                            <BadgeList 
                                items={details.vulnerability_class} 
                                variant="outline"
                                badgeClassName="text-red-600 border-red-300"
                            />
                        </DetailSection>
                    )}
                    {details.technology && details.technology.length > 0 && (
                        <DetailSection label="Technology">
                            <BadgeList items={details.technology} variant="secondary" />
                        </DetailSection>
                    )}
                    {details.subcategory && details.subcategory.length > 0 && (
                        <DetailSection label="Subcategory">
                            <BadgeList items={details.subcategory} variant="outline" />
                        </DetailSection>
                    )}
                </div>
            )}

            {/* Code Extract */}
            {details.code_extract && (
                <DetailSection label="Code">
                    <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs font-mono border">
                        <code>{details.code_extract}</code>
                    </pre>
                </DetailSection>
            )}

            {/* Description */}
            {findingDesc && (
                <DetailSection label="Description & Remediation">
                    <div className="prose prose-sm dark:prose-invert max-w-none bg-muted/30 p-4 rounded-lg border">
                        <ReactMarkdown components={markdownComponents}>
                            {findingDesc}
                        </ReactMarkdown>
                    </div>
                </DetailSection>
            )}

            {/* References */}
            {details.references && details.references.length > 0 && (
                <DetailSection label="References">
                    <ReferencesList urls={details.references} />
                </DetailSection>
            )}

            {/* Source Rule URL */}
            {localIsOpenGrep && details.source_rule_url && (
                <DetailSection label="Rule Source">
                    <a
                        href={details.source_rule_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline inline-flex items-center gap-1"
                    >
                        <ExternalLink className="h-3 w-3" />
                        {details.source_rule_url}
                    </a>
                </DetailSection>
            )}
             
            {/* License (OpenGrep) */}
            {localIsOpenGrep && details.license && (
                <DetailSection label="Rule License" compact>
                    <p className="text-xs text-muted-foreground">{details.license}</p>
                </DetailSection>
            )}

            {/* Documentation Link */}
            {details.documentation_url && (
                <div className="pt-2">
                    <Button variant="outline" size="sm" asChild>
                        <a 
                            href={details.documentation_url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-2"
                        >
                            <BookOpen className="h-4 w-4" />
                            View Full Documentation
                            <ExternalLink className="h-3 w-3" />
                        </a>
                    </Button>
                </div>
            )}

            {/* KICS-specific fields */}
            {localIsKics && (
                <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                    {details.category && (
                        <DetailSection label="Category" compact>
                            <p className="text-sm">{details.category}</p>
                        </DetailSection>
                    )}
                    {details.platform && (
                        <DetailSection label="Platform" compact>
                            <p className="text-sm">{details.platform}</p>
                        </DetailSection>
                    )}
                    {details.expected_value && (
                        <DetailSection label="Expected" compact>
                            <p className="text-sm font-mono text-green-600">{details.expected_value}</p>
                        </DetailSection>
                    )}
                    {details.actual_value && (
                        <DetailSection label="Actual" compact>
                            <p className="text-sm font-mono text-red-600">{details.actual_value}</p>
                        </DetailSection>
                    )}
                </div>
            )}
         </div>
       )
    }

    if (sastFindings.length > 0) {
        // Aggregated view
        return (
             <div className="space-y-6">
                 {/* File and Location with Source Link (Common) */}
                <FileLocation
                    filePath={finding.component || "Unknown"}
                    startLine={startLine}
                    endLine={endLine}
                    startCol={details.start?.column}
                    endCol={details.end?.column}
                    scmContext={scanContext}
                />
                
                <p className="text-sm text-muted-foreground">
                    Aggregated findings from <strong>{finding.scanners?.length || 0}</strong> scanners at this location.
                </p>

                {/* List of individual findings */}
                <div className="space-y-3">
                    {sastFindings.map((issue, idx) => {
                        const isExpanded = expandedIssues.has(issue.id)
                        return (
                             <div key={idx} className="border rounded-lg overflow-hidden bg-card text-card-foreground shadow-sm">
                                <div 
                                    className="flex items-center justify-between p-3 cursor-pointer hover:bg-muted/50 transition-colors"
                                    onClick={() => toggleIssue(issue.id)}
                                >
                                     <div className="flex items-center gap-3 overflow-hidden">
                                        {isExpanded ? <ChevronDown className="h-4 w-4 flex-shrink-0" /> : <ChevronRight className="h-4 w-4 flex-shrink-0" />}
                                        
                                        <div className="flex flex-col gap-1 min-w-0">
                                            <div className="flex items-center gap-2">
                                                 <Badge variant={getSeverityBgColor(issue.severity) as any} className="flex-shrink-0">
                                                    {issue.severity}
                                                </Badge>
                                                <span className="font-medium truncate text-sm">{issue.title}</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                                <Badge variant="outline" className="text-[10px] py-0 h-5">
                                                    {issue.scanner}
                                                </Badge>
                                                <span className="truncate">{issue.id}</span>
                                            </div>
                                        </div>
                                     </div>
                                </div>
                                
                                {isExpanded && (
                                    <div className="p-4 pt-0 border-t bg-muted/10">
                                        <div className="mt-4">
                                            {renderSingleFindingDetails(issue.details, issue.title, issue.description, [issue.scanner])}
                                        </div>
                                    </div>
                                )}
                             </div>
                        )
                    })}
                </div>
             </div>
        )
    }

    // Default: Single finding view
    return (
        <div className="space-y-4">
            {/* File and Location with Source Link */}
            <FileLocation
                filePath={finding.component || "Unknown"}
                startLine={startLine}
                endLine={endLine}
                startCol={details.start?.column}
                endCol={details.end?.column}
                scmContext={scanContext}
            />
            
            {renderSingleFindingDetails(details, finding.details?.title, finding.description, finding.scanners || [])}

            {/* Fingerprint for debugging/reference (Classic view only) */}
            {details.fingerprint && (
                <div className="pt-2 border-t">
                    <p className="text-xs text-muted-foreground">
                        Fingerprint: <code className="font-mono">{details.fingerprint}</code>
                    </p>
                </div>
            )}
        </div>
    )
}

