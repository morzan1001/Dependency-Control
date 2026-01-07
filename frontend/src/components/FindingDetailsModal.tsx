import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { useState } from "react"
import { Finding, NestedVulnerability } from "@/types/scan"
import { AlertTriangle, ExternalLink, Shield, ShieldAlert } from "lucide-react"
import { useAuth } from "@/context/useAuth"
import { useNavigate } from "react-router-dom"
import { FindingTypeBadge } from '@/components/findings/FindingTypeBadge'
import { CollapsibleReferences } from '@/components/findings/CollapsibleReferences'
import { getSeverityBadgeVariant } from '@/lib/finding-utils'
import { ContextBannersSection } from '@/components/findings/details/ContextBannersSection'
import { OriginBadge } from '@/components/findings/details/OriginBadge'
import { LicenseDetailsView } from '@/components/findings/details/LicenseDetailsView'
import { AggregatedQualityView, MaintainerRiskDetailsView } from '@/components/findings/details/QualityDetails'
import { AdditionalDetailsView } from '@/components/findings/details/AdditionalDetailsView'
import { WaiverForm } from '@/components/findings/details/WaiverForm'
import { SastDetailsView, ScanContext } from '@/components/findings/details/SastDetailsView'
import { DetailSection, FileLocation, BadgeList } from '@/components/findings/details/shared'
import {
  getFindingId,
  getFindingPackage,
  getFindingTitle,
  getFindingVersion,
} from '@/components/findings/details/finding-details-helpers'

interface FindingDetailsModalProps {
    finding: Finding | null
    isOpen: boolean
    onClose: () => void
    projectId: string
    scanId?: string
    scanContext?: ScanContext
    onSelectFinding?: (id: string) => void
    onNavigate?: () => void  // Called before navigation to allow parent cleanup
}

export function FindingDetailsModal({ finding, isOpen, onClose, projectId, scanId, scanContext, onSelectFinding, onNavigate }: FindingDetailsModalProps) {
    const [showWaiverForm, setShowWaiverForm] = useState(false)
    const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null)
    const { hasPermission } = useAuth()
    const navigate = useNavigate()
    
    if (!finding) return null

    const handleWaive = (vulnId?: string) => {
        setSelectedVulnId(vulnId || null)
        setShowWaiverForm(true)
    }
    
    // Navigate to Raw tab with SBOM anchor
    const handleSbomClick = (source: string) => {
        if (!scanId) return
        // Extract SBOM index from source name (e.g., "SBOM #1" -> 0)
        const match = source.match(/SBOM #(\d+)/i)
        const sbomIndex = match ? parseInt(match[1], 10) - 1 : 0
        // Close this modal and notify parent to close as well
        onClose()
        onNavigate?.()  // Allow parent modals to close
        navigate(`/projects/${projectId}/scans/${scanId}?tab=raw&sbom=${sbomIndex}`)
    }

    return (
        <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
                <DialogContent className="max-w-3xl max-h-[90vh] flex flex-col">
                <DialogHeader className="pb-1">
                    <DialogTitle className="flex items-center gap-2 leading-normal">
                        {finding.severity && (
                            <Badge variant={getSeverityBadgeVariant(finding.severity)}>
                                {finding.severity}
                            </Badge>
                        )}
                        <span className="truncate leading-normal">{getFindingTitle(finding)}</span>
                    </DialogTitle>
                    <DialogDescription className="flex flex-wrap items-center gap-2">
                        <span className="flex items-center gap-1">
                            <Badge variant="outline">{finding.type}</Badge>
                            {/* Show additional absorbed finding types */}
                            {finding.details?.additional_finding_types?.map((addType: { type: string; severity: string }, idx: number) => (
                                <FindingTypeBadge key={idx} type={addType.type} />
                            ))}
                        </span>
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto pr-4">
                    {showWaiverForm ? (
                        <WaiverForm 
                            finding={finding} 
                            vulnId={selectedVulnId}
                            projectId={projectId} 
                            onCancel={() => setShowWaiverForm(false)} 
                            onSuccess={() => {
                                setShowWaiverForm(false)
                                onClose()
                            }}
                        />
                    ) : (
                      <div className="space-y-6 pt-2 pb-4">
                            <div className="grid grid-cols-2 gap-4">
                                <DetailSection label="Component" compact>
                                    <p className="font-medium">{getFindingPackage(finding)}</p>
                                </DetailSection>
                                <DetailSection label="Version" compact>
                                    <p className="font-medium">{getFindingVersion(finding)}</p>
                                </DetailSection>
                                <DetailSection label="Fixed Version" compact>
                                    <p className="font-medium text-green-600">{finding.details?.fixed_version || "None"}</p>
                                </DetailSection>
                                <DetailSection label="ID" compact>
                                    <p className="font-mono text-sm">{getFindingId(finding)}</p>
                                </DetailSection>
                                {finding.scanners && finding.scanners.length > 0 && (
                                    <div className="col-span-2">
                                        <DetailSection label="Detected By" compact>
                                            <BadgeList 
                                                items={finding.scanners} 
                                                variant="outline" 
                                                badgeClassName="font-mono text-xs"
                                            />
                                        </DetailSection>
                                    </div>
                                )}
                                {finding.found_in && finding.found_in.length > 0 && (
                                    <div className="col-span-2">
                                        <DetailSection label="Found In Sources">
                                            <div className="flex flex-wrap gap-2 items-start">
                                            {finding.found_in.map((source) => {
                                                // Check if this looks like an SBOM reference
                                                const isSbomRef = source.match(/SBOM #\d+/i) || !source.includes('/')
                                                return (
                                                    <Badge 
                                                        key={source} 
                                                        variant="secondary" 
                                                        className={`font-mono text-xs ${scanId && isSbomRef ? 'cursor-pointer hover:bg-primary/20 transition-colors' : ''}`}
                                                        onClick={scanId && isSbomRef ? (e) => {
                                                            e.preventDefault()
                                                            e.stopPropagation()
                                                            handleSbomClick(source)
                                                        } : undefined}
                                                    >
                                                        {source}
                                                        {scanId && isSbomRef && <ExternalLink className="h-3 w-3 ml-1" />}
                                                    </Badge>
                                                )
                                            })}
                                            {finding.source_type && (
                                                <OriginBadge finding={finding} />
                                            )}
                                        </div>
                                        </DetailSection>
                                    </div>
                                )}
                                {/* Origin Badge for findings without found_in */}
                                {(!finding.found_in || finding.found_in.length === 0) && finding.source_type && (
                                    <div className="col-span-2">
                                        <OriginBadge finding={finding} />
                                    </div>
                                )}
                                {finding.related_findings && finding.related_findings.length > 0 && (
                                    <div className="col-span-2">
                                        <DetailSection label="Related Findings" compact>
                                            <div className="flex flex-wrap gap-2">
                                            {finding.related_findings.map((relatedId) => {
                                                // Format the label and determine badge color based on type
                                                let label = relatedId;
                                                let badgeClass = "font-mono text-xs cursor-pointer ";
                                                
                                                if (relatedId.startsWith("OUTDATED-")) {
                                                    // OUTDATED-{component} format
                                                    const component = relatedId.replace("OUTDATED-", "");
                                                    label = `Outdated: ${component}`;
                                                    badgeClass += "border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100";
                                                } else if (relatedId.startsWith("QUALITY:")) {
                                                    // QUALITY:{component}:{version} format
                                                    const parts = relatedId.split(":");
                                                    label = `Quality: ${parts[1]}${parts[2] ? ` (${parts[2]})` : ""}`;
                                                    badgeClass += "border-yellow-200 bg-yellow-50 text-yellow-700 hover:bg-yellow-100";
                                                } else if (relatedId.startsWith("LIC-")) {
                                                    // LIC-{license} format
                                                    const license = relatedId.replace("LIC-", "");
                                                    label = `License: ${license}`;
                                                    badgeClass += "border-purple-200 bg-purple-50 text-purple-700 hover:bg-purple-100";
                                                } else if (relatedId.startsWith("EOL-")) {
                                                    // EOL-{component}-{cycle} format
                                                    const info = relatedId.replace("EOL-", "");
                                                    label = `EOL: ${info}`;
                                                    badgeClass += "border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100";
                                                } else if (relatedId.startsWith("AGG:VULN:")) {
                                                    // Handle legacy AGG:VULN: format
                                                    const parts = relatedId.split(":");
                                                    if (parts.length >= 4) {
                                                        label = `Vuln: ${parts[2]} (${parts[3]})`;
                                                    }
                                                    badgeClass += "border-red-200 bg-red-50 text-red-700 hover:bg-red-100";
                                                } else if (relatedId.includes(":") && !relatedId.startsWith("AGG:")) {
                                                    // component:version format (vulnerabilities)
                                                    const parts = relatedId.split(":");
                                                    if (parts.length === 2) {
                                                        label = `Vuln: ${parts[0]} (${parts[1]})`;
                                                    }
                                                    badgeClass += "border-red-200 bg-red-50 text-red-700 hover:bg-red-100";
                                                } else {
                                                    // Unknown format - default styling
                                                    badgeClass += "border-gray-200 bg-gray-50 text-gray-700 hover:bg-gray-100";
                                                }
                                                
                                                return (
                                                    <Badge 
                                                        key={relatedId} 
                                                        variant="outline" 
                                                        className={badgeClass}
                                                        onClick={() => onSelectFinding?.(relatedId)}
                                                    >
                                                        {label}
                                                    </Badge>
                                                );
                                            })}
                                        </div>
                                            <p className="text-xs text-muted-foreground mt-1">
                                                Click to view related findings for this component.
                                            </p>
                                        </DetailSection>
                                    </div>
                                )}
                            </div>

                            {finding.description && finding.type !== 'vulnerability' && finding.type !== 'sast' && finding.type !== 'iac' && (
                                <DetailSection label="Description">
                                    <p className="text-sm leading-relaxed">{finding.description}</p>
                                </DetailSection>
                            )}

                            {finding.type === 'secret' && (
                                <div className="space-y-4">
                                    {/* File location with link */}
                                    {scanContext && finding.component && (
                                        <FileLocation
                                            filePath={finding.component}
                                            startLine={finding.details?.line}
                                            scmContext={scanContext}
                                        />
                                    )}
                                    <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                                        <DetailSection label="Detector" compact>
                                            <p className="font-medium">{finding.details?.detector || "Unknown"}</p>
                                        </DetailSection>
                                        <DetailSection label="Verified" compact>
                                            <Badge variant={finding.details?.verified ? "destructive" : "secondary"}>
                                                {finding.details?.verified ? "Verified Live" : "Unverified"}
                                            </Badge>
                                        </DetailSection>
                                        {finding.details?.redacted && (
                                            <div className="col-span-2">
                                                <DetailSection label="Redacted Secret" compact>
                                                    <code className="bg-background p-2 rounded border block w-full font-mono text-sm break-all">
                                                        {finding.details.redacted}
                                                    </code>
                                                </DetailSection>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}

                            {finding.type === 'sast' && (
                                <SastDetailsView finding={finding} scanContext={scanContext} />
                            )}

                            {finding.type === 'iac' && (
                                <SastDetailsView finding={finding} scanContext={scanContext} />
                            )}

                            {finding.type === 'vulnerability' && (
                                <div className="space-y-4">
                                    {(() => {
                                        // Normalize to a list of vulnerabilities
                                        const vulns: NestedVulnerability[] = finding.details?.vulnerabilities && finding.details.vulnerabilities.length > 0 
                                            ? finding.details.vulnerabilities 
                                            : [(finding.details || {}) as NestedVulnerability]; // Fallback for legacy or single vuln structure

                                        return (
                                            <div className="space-y-4">
                                                {vulns.length > 1 && (
                                                    <p className="text-sm text-muted-foreground mb-2">
                                                        Found {vulns.length} vulnerabilities in {getFindingPackage(finding)}
                                                    </p>
                                                )}
                                                
                                                {/* Unified context banners section */}
                                                <ContextBannersSection finding={finding} />
                                                
                                                {vulns.map((vuln: NestedVulnerability, idx: number) => {
                                                    const vulnId = vuln.id || getFindingId(finding);
                                                    const isCve = vulnId?.startsWith('CVE-');
                                                    const isGhsa = vulnId?.startsWith('GHSA-');
                                                    const resolvedCve = vuln.resolved_cve;
                                                    const githubAdvisoryUrl = vuln.github_advisory_url || finding.details?.github_advisory_url;
                                                    
                                                    // Determine the best link for the vulnerability
                                                    let vulnLink = null;
                                                    if (isCve) {
                                                        vulnLink = `https://nvd.nist.gov/vuln/detail/${vulnId}`;
                                                    } else if (isGhsa) {
                                                        vulnLink = githubAdvisoryUrl || `https://github.com/advisories/${vulnId}`;
                                                    }
                                                    
                                                    return (
                                                    <div key={idx} className="border rounded-lg p-4 space-y-3">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                {vulnLink ? (
                                                                    <a
                                                                        href={vulnLink}
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                        className="inline-flex items-center gap-1"
                                                                        onClick={(e) => e.stopPropagation()}
                                                                    >
                                                                        <Badge variant="outline" className="hover:bg-muted cursor-pointer">
                                                                            {vulnId}
                                                                            <ExternalLink className="h-3 w-3 ml-1" />
                                                                        </Badge>
                                                                    </a>
                                                                ) : (
                                                                    <Badge variant="outline">{vulnId}</Badge>
                                                                )}
                                                                {/* Show resolved CVE if GHSA was resolved */}
                                                                {isGhsa && resolvedCve && (
                                                                    <a
                                                                        href={`https://nvd.nist.gov/vuln/detail/${resolvedCve}`}
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                        className="inline-flex items-center gap-1"
                                                                        onClick={(e) => e.stopPropagation()}
                                                                    >
                                                                        <Badge variant="secondary" className="hover:bg-muted cursor-pointer text-xs">
                                                                            {resolvedCve}
                                                                            <ExternalLink className="h-3 w-3 ml-1" />
                                                                        </Badge>
                                                                    </a>
                                                                )}
                                                                <Badge variant={
                                                                    (vuln.severity || finding.severity) === 'CRITICAL' ? 'destructive' :
                                                                    (vuln.severity || finding.severity) === 'HIGH' ? 'destructive' :
                                                                    (vuln.severity || finding.severity) === 'MEDIUM' ? 'default' : 
                                                                    'secondary'
                                                                }>{vuln.severity || finding.severity}</Badge>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-xs text-muted-foreground">
                                                                    Fixed in: <span className="font-medium text-foreground">{vuln.fixed_version || finding.details?.fixed_version || "None"}</span>
                                                                </span>
                                                                {hasPermission('waiver:manage') && (
                                                                    <Button variant="ghost" size="sm" className="h-6 px-2" onClick={() => handleWaive(vuln.id || getFindingId(finding))}>
                                                                        <ShieldAlert className="h-3 w-3 mr-1" />
                                                                        Waive
                                                                    </Button>
                                                                )}
                                                            </div>
                                                        </div>
                                                        <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                                                            {vuln.description || (finding.details?.vulnerabilities ? "" : finding.description) || "No description available."}
                                                        </p>
                                                        
                                                        <div className="flex flex-wrap gap-4 text-xs">
                                                            {(vuln.cvss_score || finding.details?.cvss_score) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium">CVSS: {vuln.cvss_score || finding.details?.cvss_score}</span>
                                                                    {(vuln.cvss_vector || finding.details?.cvss_vector) && <span className="font-mono text-muted-foreground">{vuln.cvss_vector || finding.details?.cvss_vector}</span>}
                                                                </div>
                                                            )}
                                                            {(vuln.epss_score !== undefined || finding.details?.epss_score !== undefined) && (() => {
                                                                const epssScore = vuln.epss_score ?? finding.details?.epss_score ?? 0
                                                                const epssPercentile = vuln.epss_percentile ?? finding.details?.epss_percentile
                                                                const epssDate = vuln.epss_date ?? finding.details?.epss_date
                                                                return (
                                                                <div className="flex items-center gap-2">
                                                                    <span className={`font-medium ${
                                                                        epssScore >= 0.1 ? 'text-red-500' :
                                                                        epssScore >= 0.01 ? 'text-orange-500' : ''
                                                                    }`}>
                                                                        EPSS: {(epssScore * 100).toFixed(2)}%
                                                                    </span>
                                                                    {epssPercentile !== undefined && (
                                                                        <span className="text-muted-foreground">(Top {(100 - epssPercentile).toFixed(0)}%)</span>
                                                                    )}
                                                                    {epssDate && (
                                                                        <span className="text-muted-foreground text-[10px]">as of {new Date(epssDate).toLocaleDateString()}</span>
                                                                    )}
                                                                </div>
                                                                )
                                                            })()}
                                                            {(vuln.in_kev || finding.details?.in_kev) && (() => {
                                                                const kevDateAdded = vuln.kev_date_added ?? finding.details?.kev_date_added
                                                                return (
                                                                <div className="flex items-center gap-1 px-2 py-0.5 bg-red-500/10 text-red-600 rounded-md flex-wrap">
                                                                    <AlertTriangle className="h-3 w-3" />
                                                                    <span className="font-medium">Known Exploited</span>
                                                                    {(vuln.kev_ransomware_use || finding.details?.kev_ransomware_use) && (
                                                                        <Badge variant="destructive" className="text-[10px] py-0 h-4">Ransomware</Badge>
                                                                    )}
                                                                    {kevDateAdded && (
                                                                        <span className="text-muted-foreground text-[10px] ml-1">
                                                                            (since {new Date(kevDateAdded).toLocaleDateString()})
                                                                        </span>
                                                                    )}
                                                                </div>
                                                                )
                                                            })()}
                                                            {/* Reachability Analysis */}
                                                            {(vuln.reachability || finding.details?.reachability) && (() => {
                                                                const reachability = vuln.reachability ?? finding.details?.reachability
                                                                const confidenceScore = reachability?.confidence_score
                                                                return (
                                                                <div className={`flex items-center gap-1 px-2 py-0.5 rounded-md flex-wrap ${
                                                                    reachability?.is_reachable
                                                                        ? 'bg-red-500/10 text-red-600'
                                                                        : 'bg-green-500/10 text-green-600'
                                                                }`}>
                                                                    {reachability?.is_reachable ? (
                                                                        <>
                                                                            <AlertTriangle className="h-3 w-3" />
                                                                            <span className="font-medium">Reachable</span>
                                                                        </>
                                                                    ) : (
                                                                        <>
                                                                            <Shield className="h-3 w-3" />
                                                                            <span className="font-medium">Not Reachable</span>
                                                                        </>
                                                                    )}
                                                                    {reachability?.analysis_level && (
                                                                        <Badge variant="outline" className="text-[10px] py-0 h-4 ml-1">
                                                                            {reachability.analysis_level}
                                                                        </Badge>
                                                                    )}
                                                                    {confidenceScore !== undefined && (
                                                                        <span className="text-muted-foreground text-[10px] ml-1">
                                                                            ({Math.round(confidenceScore * 100)}% confidence)
                                                                        </span>
                                                                    )}
                                                                </div>
                                                                )
                                                            })()}
                                                            {/* Reachability matched symbols */}
                                                            {((vuln.reachability?.matched_symbols || finding.details?.reachability?.matched_symbols)?.length ?? 0) > 0 && (() => {
                                                                const matchedSymbols = vuln.reachability?.matched_symbols ?? finding.details?.reachability?.matched_symbols ?? []
                                                                return (
                                                                <div className="flex items-start gap-2 w-full">
                                                                    <span className="font-medium text-muted-foreground shrink-0">Affected Symbols:</span>
                                                                    <div className="flex flex-wrap gap-1">
                                                                        {matchedSymbols.slice(0, 5).map((symbol: string, idx: number) => (
                                                                            <Badge key={idx} variant="outline" className="font-mono text-xs">
                                                                                {symbol}
                                                                            </Badge>
                                                                        ))}
                                                                        {matchedSymbols.length > 5 && (
                                                                            <Badge variant="secondary" className="text-[10px]">
                                                                                +{matchedSymbols.length - 5} more
                                                                            </Badge>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                                )
                                                            })()}
                                                            {(vuln.kev_required_action || finding.details?.kev_required_action) && (
                                                                <div className="flex items-center gap-2 w-full">
                                                                    <span className="font-medium text-muted-foreground">Required Action:</span>
                                                                    <span className="text-red-600">{vuln.kev_required_action || finding.details?.kev_required_action}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.exploit_maturity || finding.details?.exploit_maturity) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Exploit:</span>
                                                                    <span className={`${
                                                                        (vuln.exploit_maturity || finding.details?.exploit_maturity) === 'high' ? 'text-red-500 font-medium' :
                                                                        (vuln.exploit_maturity || finding.details?.exploit_maturity) === 'functional' ? 'text-orange-500' :
                                                                        (vuln.exploit_maturity || finding.details?.exploit_maturity) === 'poc' ? 'text-yellow-600' : ''
                                                                    }`}>{vuln.exploit_maturity || finding.details?.exploit_maturity}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.details?.published_date || finding.details?.published_date) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Published:</span>
                                                                    <span>{new Date(vuln.details?.published_date ?? finding.details?.published_date ?? '').toLocaleDateString()}</span>
                                                                </div>
                                                            )}
                                                            {((vuln.details?.cwe_ids ?? finding.details?.cwe_ids)?.length ?? 0) > 0 && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">CWE:</span>
                                                                    <span className="font-mono">{(vuln.details?.cwe_ids ?? finding.details?.cwe_ids ?? []).join(', ')}</span>
                                                                </div>
                                                            )}
                                                            {((vuln.aliases ?? finding.aliases)?.length ?? 0) > 0 && (
                                                                <div className="flex items-center gap-2 flex-wrap">
                                                                    <span className="font-medium text-muted-foreground">Aliases:</span>
                                                                    <div className="flex flex-wrap gap-1">
                                                                        {(vuln.aliases ?? finding.aliases ?? []).map((alias: string, aliasIdx: number) => {
                                                                            const isCve = alias.startsWith('CVE-');
                                                                            const isGhsa = alias.startsWith('GHSA-');
                                                                            const link = isCve 
                                                                                ? `https://nvd.nist.gov/vuln/detail/${alias}`
                                                                                : isGhsa 
                                                                                    ? `https://github.com/advisories/${alias}`
                                                                                    : null;
                                                                            
                                                                            return link ? (
                                                                                <a
                                                                                    key={aliasIdx}
                                                                                    href={link}
                                                                                    target="_blank"
                                                                                    rel="noopener noreferrer"
                                                                                    className="font-mono text-primary hover:underline text-xs"
                                                                                    onClick={(e) => e.stopPropagation()}
                                                                                >
                                                                                    {alias}
                                                                                </a>
                                                                            ) : (
                                                                                <span key={aliasIdx} className="font-mono text-xs">{alias}</span>
                                                                            );
                                                                        })}
                                                                    </div>
                                                                </div>
                                                            )}
                                                            {(vuln.scanners || finding.scanners) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Detected by:</span>
                                                                    <span className="font-mono">{(vuln.scanners || finding.scanners).join(', ')}</span>
                                                                </div>
                                                            )}
                                                        </div>

                                                        <CollapsibleReferences references={vuln.references || finding.details?.references} />
                                                    </div>
                                                    );
                                                })}
                                            </div>
                                        );
                                    })()}
                                </div>
                            )}

                            {/* License Compliance findings */}
                            {finding.type === 'license' && finding.details && (
                                <>
                                    <ContextBannersSection finding={finding} />
                                    <LicenseDetailsView details={finding.details} />
                                </>
                            )}

                            {/* Quality findings (aggregated: quality_issues list) */}
                            {finding.type === 'quality' && finding.details && (
                                <>
                                    <ContextBannersSection finding={finding} />
                                    <AggregatedQualityView details={finding.details} />
                                </>
                            )}

                            {/* Outdated findings */}
                            {finding.type === 'outdated' && (
                                <ContextBannersSection finding={finding} />
                            )}

                            {/* EOL findings */}
                            {finding.type === 'eol' && (
                                <ContextBannersSection finding={finding} />
                            )}

                            {/* Legacy 'other' type with maintainer_risk data */}
                            {finding.type === 'other' && finding.details?.risks && finding.details?.maintainer_info && (
                                <MaintainerRiskDetailsView details={finding.details} />
                            )}

                            {finding.details && finding.type !== 'secret' && finding.type !== 'sast' && finding.type !== 'vulnerability' && finding.type !== 'outdated' && finding.type !== 'quality' && finding.type !== 'license' && !(finding.type === 'other' && finding.details?.risks && finding.details?.maintainer_info) && (
                                <DetailSection label="Additional Details">
                                    <AdditionalDetailsView details={finding.details} />
                                </DetailSection>
                            )}
                        </div>
                    )}
                </div>

                {!showWaiverForm && (
                    <DialogFooter className="gap-2 sm:gap-0">
                        {hasPermission('waiver:manage') && (
                            <Button variant="outline" onClick={() => setShowWaiverForm(true)}>
                                <ShieldAlert className="mr-2 h-4 w-4" />
                                Create Waiver
                            </Button>
                        )}
                        <Button onClick={onClose}>Close</Button>
                    </DialogFooter>
                )}
            </DialogContent>
        </Dialog>
    )
}
