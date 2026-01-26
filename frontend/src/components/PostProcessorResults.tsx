/**
 * Post-Processor Results Components
 * 
 * Renders EPSS/KEV and Reachability analysis results in a user-friendly format
 * instead of raw JSON.
 */

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  AlertTriangle, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Target, 
  TrendingUp,
  AlertCircle,
  CheckCircle,
  XCircle,
  Activity,
  Skull,
  Bug,
  Clock,
  Package,
  ChevronDown
} from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { getSeverityBadgeVariant } from "@/lib/finding-utils";
import { formatDateTime } from "@/lib/utils";

// Type definitions
interface EPSSKEVSummary {
  total_vulnerabilities: number;
  epss_enriched: number;
  kev_matches: number;
  kev_ransomware: number;
  epss_scores: {
    high: number;
    medium: number;
    low: number;
  };
  exploit_maturity: {
    weaponized: number;
    active: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  avg_epss_score: number | null;
  max_epss_score: number | null;
  avg_risk_score: number | null;
  max_risk_score: number | null;
  kev_details: Array<{
    cve: string;
    component: string;
    due_date: string | null;
    ransomware: boolean;
  }>;
  high_risk_cves: Array<{
    cve: string;
    component: string;
    version: string;
    risk_score: number;
    epss_score: number | null;
    in_kev: boolean;
    exploit_maturity: string;
  }>;
  timestamp: string;
}

interface ReachabilitySummary {
  total_vulnerabilities: number;
  analyzed: number;
  reachability_levels: {
    confirmed: number;
    likely: number;
    unknown: number;
    unreachable: number;
  };
  callgraph_info: {
    language: string;
    total_modules: number;
    total_imports: number;
    generated_at: string;
  };
  reachable_vulnerabilities: Array<{
    cve: string;
    component: string;
    version: string;
    severity: string;
    reachability_level: string;
    reachable_functions: string[];
  }>;
  unreachable_vulnerabilities: Array<{
    cve: string;
    component: string;
    version: string;
    severity: string;
    reachability_level: string;
  }>;
  timestamp: string;
}

// EPSS/KEV Results Component
export function EPSSKEVResults({ data }: { data: EPSSKEVSummary }) {
  const getMaturityColor = (maturity: string) => {
    switch (maturity) {
      case "weaponized": return "bg-red-600";
      case "active": return "bg-red-500";
      case "high": return "bg-orange-500";
      case "medium": return "bg-yellow-500";
      case "low": return "bg-green-500";
      default: return "bg-gray-400";
    }
  };

  const getMaturityLabel = (maturity: string) => {
    switch (maturity) {
      case "weaponized": return "Weaponized (Ransomware)";
      case "active": return "Active Exploitation (KEV)";
      case "high": return "High (EPSS > 10%)";
      case "medium": return "Medium (EPSS 1-10%)";
      case "low": return "Low (EPSS < 1%)";
      default: return "Unknown";
    }
  };

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-blue-100 dark:bg-blue-900">
                <Activity className="h-6 w-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">EPSS Enriched</p>
                <p className="text-2xl font-bold">{data.epss_enriched} / {data.total_vulnerabilities}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-red-100 dark:bg-red-900">
                <ShieldAlert className="h-6 w-6 text-severity-critical" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">In CISA KEV</p>
                <p className="text-2xl font-bold">{data.kev_matches}</p>
                {data.kev_ransomware > 0 && (
                  <p className="text-xs text-severity-critical flex items-center gap-1">
                    <Skull className="h-3 w-3" /> {data.kev_ransomware} Ransomware
                  </p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-orange-100 dark:bg-orange-900">
                <TrendingUp className="h-6 w-6 text-severity-high" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Avg EPSS Score</p>
                <p className="text-2xl font-bold">
                  {data.avg_epss_score !== null 
                    ? `${(data.avg_epss_score * 100).toFixed(2)}%` 
                    : "N/A"}
                </p>
                {data.max_epss_score !== null && (
                  <p className="text-xs text-muted-foreground">
                    Max: {(data.max_epss_score * 100).toFixed(2)}%
                  </p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-purple-100 dark:bg-purple-900">
                <Target className="h-6 w-6 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Avg Risk Score</p>
                <p className="text-2xl font-bold">
                  {data.avg_risk_score !== null 
                    ? data.avg_risk_score.toFixed(1) 
                    : "N/A"}
                </p>
                {data.max_risk_score !== null && (
                  <p className="text-xs text-muted-foreground">
                    Max: {data.max_risk_score.toFixed(1)}
                  </p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Exploit Maturity Distribution */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Bug className="h-4 w-4" />
            Exploit Maturity Distribution
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Object.entries(data.exploit_maturity)
              .filter(([, count]) => count > 0)
              .sort(([a], [b]) => {
                const order = ["weaponized", "active", "high", "medium", "low", "unknown"];
                return order.indexOf(a) - order.indexOf(b);
              })
              .map(([maturity, count]) => (
                <div key={maturity} className="flex items-center gap-3">
                  <div className="w-32 text-sm">{getMaturityLabel(maturity)}</div>
                  <div className="flex-1">
                    <Progress 
                      value={(count / data.total_vulnerabilities) * 100} 
                      className={`h-3 ${getMaturityColor(maturity)}`}
                    />
                  </div>
                  <div className="w-12 text-right text-sm font-medium">{count}</div>
                </div>
              ))}
          </div>
        </CardContent>
      </Card>

      {/* EPSS Score Distribution */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="h-4 w-4" />
            EPSS Score Distribution
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="flex items-center justify-between p-4 rounded-lg bg-red-50 dark:bg-red-950">
              <div>
                <p className="text-sm font-medium text-severity-critical">High (&gt;10%)</p>
                <p className="text-xs text-severity-critical">Likely to be exploited</p>
              </div>
              <span className="text-2xl font-bold text-severity-critical">
                {data.epss_scores.high}
              </span>
            </div>
            <div className="flex items-center justify-between p-4 rounded-lg bg-yellow-50 dark:bg-yellow-950">
              <div>
                <p className="text-sm font-medium text-severity-medium">Medium (1-10%)</p>
                <p className="text-xs text-severity-medium">Moderate probability</p>
              </div>
              <span className="text-2xl font-bold text-severity-medium">
                {data.epss_scores.medium}
              </span>
            </div>
            <div className="flex items-center justify-between p-4 rounded-lg bg-green-50 dark:bg-green-950">
              <div>
                <p className="text-sm font-medium text-success">Low (&lt;1%)</p>
                <p className="text-xs text-success">Low probability</p>
              </div>
              <span className="text-2xl font-bold text-success">
                {data.epss_scores.low}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* KEV Details */}
      {data.kev_details.length > 0 && (
        <Card className="border-red-200 dark:border-red-800">
          <CardHeader className="bg-red-50 dark:bg-red-950">
            <CardTitle className="text-base flex items-center gap-2 text-severity-critical">
              <ShieldAlert className="h-4 w-4" />
              CISA Known Exploited Vulnerabilities ({data.kev_details.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="space-y-2">
              {data.kev_details.map((kev, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                  <div className="flex items-center gap-3">
                    {kev.ransomware ? (
                      <Skull className="h-5 w-5 text-red-600" />
                    ) : (
                      <AlertTriangle className="h-5 w-5 text-orange-500" />
                    )}
                    <div>
                      <p className="font-mono text-sm font-medium">{kev.cve}</p>
                      <p className="text-xs text-muted-foreground">{kev.component}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {kev.ransomware && (
                      <Badge variant="destructive" className="text-xs">Ransomware</Badge>
                    )}
                    {kev.due_date && (
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger>
                            <Badge variant="outline" className="text-xs flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {kev.due_date}
                            </Badge>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>CISA Remediation Due Date</p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* High Risk CVEs */}
      {data.high_risk_cves.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              High Risk Vulnerabilities (Risk Score &gt; 70)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.high_risk_cves.slice(0, 10).map((cve, idx) => (
                <Collapsible key={idx}>
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-3 rounded-lg bg-muted/50 hover:bg-muted transition-colors">
                    <div className="flex items-center gap-4">
                      <span className="font-mono text-sm">{cve.cve}</span>
                      <Badge 
                        variant={cve.risk_score >= 80 ? "destructive" : "default"}
                      >
                        Risk: {cve.risk_score}
                      </Badge>
                    </div>
                    <ChevronDown className="h-4 w-4 transition-transform duration-200" />
                  </CollapsibleTrigger>
                  <CollapsibleContent className="px-3 py-2">
                    <div className="grid gap-2 text-sm pl-2 border-l-2 border-muted ml-2">
                      <div className="flex items-center gap-2">
                        <Package className="h-4 w-4 text-muted-foreground" />
                        <span>{cve.component}@{cve.version}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <TrendingUp className="h-4 w-4 text-muted-foreground" />
                        <span>EPSS: {cve.epss_score ? `${(cve.epss_score * 100).toFixed(2)}%` : "N/A"}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {cve.in_kev ? (
                          <ShieldAlert className="h-4 w-4 text-red-500" />
                        ) : (
                          <Shield className="h-4 w-4 text-muted-foreground" />
                        )}
                        <span>KEV: {cve.in_kev ? "Yes" : "No"}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Bug className="h-4 w-4 text-muted-foreground" />
                        <span>Maturity: {cve.exploit_maturity}</span>
                      </div>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Timestamp */}
      <p className="text-xs text-muted-foreground text-right">
        Enriched at: {formatDateTime(data.timestamp)}
      </p>
    </div>
  );
}

// Reachability Results Component
export function ReachabilityResults({ data }: { data: ReachabilitySummary }) {
  const totalAnalyzed = 
    data.reachability_levels.confirmed + 
    data.reachability_levels.likely + 
    data.reachability_levels.unknown + 
    data.reachability_levels.unreachable;

  const reachableCount = 
    data.reachability_levels.confirmed + 
    data.reachability_levels.likely;

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-blue-100 dark:bg-blue-900">
                <Target className="h-6 w-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Analyzed</p>
                <p className="text-2xl font-bold">{data.analyzed} / {data.total_vulnerabilities}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-red-100 dark:bg-red-900">
                <AlertCircle className="h-6 w-6 text-severity-critical" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Reachable</p>
                <p className="text-2xl font-bold">{reachableCount}</p>
                <p className="text-xs text-muted-foreground">
                  {data.reachability_levels.confirmed} confirmed, {data.reachability_levels.likely} likely
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-green-100 dark:bg-green-900">
                <ShieldCheck className="h-6 w-6 text-success" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Unreachable</p>
                <p className="text-2xl font-bold">{data.reachability_levels.unreachable}</p>
                <p className="text-xs text-success">Can be deprioritized</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-gray-100 dark:bg-gray-800">
                <AlertTriangle className="h-6 w-6 text-severity-info" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Unknown</p>
                <p className="text-2xl font-bold">{data.reachability_levels.unknown}</p>
                <p className="text-xs text-muted-foreground">Needs manual review</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Callgraph Info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Callgraph Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="flex items-center gap-3">
              <Badge variant="outline" className="capitalize">{data.callgraph_info.language}</Badge>
              <span className="text-sm text-muted-foreground">Language</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-lg">{data.callgraph_info.total_modules}</span>
              <span className="text-sm text-muted-foreground">Modules analyzed</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-lg">{data.callgraph_info.total_imports}</span>
              <span className="text-sm text-muted-foreground">Import mappings</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Reachability Distribution */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Reachability Analysis Results</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {totalAnalyzed > 0 && (
              <>
                <div className="flex items-center gap-3">
                  <div className="w-32 text-sm flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-red-500" />
                    Confirmed
                  </div>
                  <div className="flex-1">
                    <Progress 
                      value={(data.reachability_levels.confirmed / totalAnalyzed) * 100} 
                      className="h-3 bg-red-100 [&>div]:bg-red-500"
                    />
                  </div>
                  <div className="w-12 text-right text-sm font-medium">
                    {data.reachability_levels.confirmed}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-32 text-sm flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-orange-500" />
                    Likely
                  </div>
                  <div className="flex-1">
                    <Progress 
                      value={(data.reachability_levels.likely / totalAnalyzed) * 100} 
                      className="h-3 bg-orange-100 [&>div]:bg-orange-500"
                    />
                  </div>
                  <div className="w-12 text-right text-sm font-medium">
                    {data.reachability_levels.likely}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-32 text-sm flex items-center gap-2">
                    <XCircle className="h-4 w-4 text-green-500" />
                    Unreachable
                  </div>
                  <div className="flex-1">
                    <Progress 
                      value={(data.reachability_levels.unreachable / totalAnalyzed) * 100} 
                      className="h-3 bg-green-100 [&>div]:bg-green-500"
                    />
                  </div>
                  <div className="w-12 text-right text-sm font-medium">
                    {data.reachability_levels.unreachable}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-32 text-sm flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-gray-400" />
                    Unknown
                  </div>
                  <div className="flex-1">
                    <Progress 
                      value={(data.reachability_levels.unknown / totalAnalyzed) * 100} 
                      className="h-3 bg-gray-100 [&>div]:bg-gray-400"
                    />
                  </div>
                  <div className="w-12 text-right text-sm font-medium">
                    {data.reachability_levels.unknown}
                  </div>
                </div>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Reachable Vulnerabilities */}
      {data.reachable_vulnerabilities.length > 0 && (
        <Card className="border-red-200 dark:border-red-800">
          <CardHeader className="bg-red-50 dark:bg-red-950">
            <CardTitle className="text-base flex items-center gap-2 text-severity-critical">
              <AlertCircle className="h-4 w-4" />
              Reachable Vulnerabilities ({data.reachable_vulnerabilities.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="space-y-2">
              {data.reachable_vulnerabilities.slice(0, 15).map((vuln, idx) => (
                <Collapsible key={idx}>
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-3 rounded-lg bg-red-50/50 dark:bg-red-950/50 hover:bg-red-100/50 dark:hover:bg-red-900/50 transition-colors">
                    <div className="flex items-center gap-4">
                      <span className="font-mono text-sm">{vuln.cve}</span>
                      <Badge variant={getSeverityBadgeVariant(vuln.severity)} className="capitalize">
                        {vuln.severity}
                      </Badge>
                      <Badge 
                        variant="outline" 
                        className={`${
                          vuln.reachability_level === "confirmed" 
                            ? "border-red-500 text-red-500" 
                            : "border-orange-500 text-orange-500"
                        }`}
                      >
                        {vuln.reachability_level}
                      </Badge>
                    </div>
                    <ChevronDown className="h-4 w-4 transition-transform duration-200" />
                  </CollapsibleTrigger>
                  <CollapsibleContent className="px-3 py-2">
                    <div className="space-y-2 text-sm pl-2 border-l-2 border-red-200 dark:border-red-800 ml-2">
                      <div className="flex items-center gap-2">
                        <Package className="h-4 w-4 text-muted-foreground" />
                        <span>{vuln.component}@{vuln.version}</span>
                      </div>
                      {vuln.reachable_functions.length > 0 && (
                        <div>
                          <p className="text-muted-foreground mb-1">Reachable functions:</p>
                          <div className="flex flex-wrap gap-1">
                            {vuln.reachable_functions.map((fn, i) => (
                              <code key={i} className="text-xs bg-muted px-1.5 py-0.5 rounded">
                                {fn}
                              </code>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Unreachable Vulnerabilities */}
      {data.unreachable_vulnerabilities.length > 0 && (
        <Card className="border-green-200 dark:border-green-800">
          <CardHeader className="bg-green-50 dark:bg-green-950">
            <CardTitle className="text-base flex items-center gap-2 text-success">
              <ShieldCheck className="h-4 w-4" />
              Unreachable Vulnerabilities ({data.unreachable_vulnerabilities.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <p className="text-sm text-muted-foreground mb-4">
              These vulnerabilities exist in dependencies but the vulnerable code paths are not used by your application.
            </p>
            <div className="grid gap-2">
              {data.unreachable_vulnerabilities.slice(0, 10).map((vuln, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 rounded bg-muted/50">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-sm">{vuln.cve}</span>
                    <span className="text-sm text-muted-foreground">
                      {vuln.component}@{vuln.version}
                    </span>
                  </div>
                  <Badge variant={getSeverityBadgeVariant(vuln.severity)} className="capitalize">
                    {vuln.severity}
                  </Badge>
                </div>
              ))}
              {data.unreachable_vulnerabilities.length > 10 && (
                <p className="text-sm text-muted-foreground text-center pt-2">
                  +{data.unreachable_vulnerabilities.length - 10} more
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Timestamp */}
      <p className="text-xs text-muted-foreground text-right">
        Analyzed at: {formatDateTime(data.timestamp)}
      </p>
    </div>
  );
}

// Render the appropriate component for post-processor results
export function PostProcessorResultCard({ analyzerName, result }: { analyzerName: string; result: unknown }) {
  const getIcon = () => {
    switch (analyzerName) {
      case "epss_kev":
        return <TrendingUp className="h-5 w-5" />;
      case "reachability":
        return <Target className="h-5 w-5" />;
      default:
        return <Shield className="h-5 w-5" />;
    }
  };

  const getTitle = () => {
    switch (analyzerName) {
      case "epss_kev":
        return "EPSS & CISA KEV Enrichment";
      case "reachability":
        return "Reachability Analysis";
      default:
        return analyzerName;
    }
  };

  const getDescription = () => {
    switch (analyzerName) {
      case "epss_kev":
        return "Exploit Prediction Scoring System & Known Exploited Vulnerabilities";
      case "reachability":
        return "Analysis of vulnerable code path reachability";
      default:
        return "";
    }
  };

  return (
    <Card className="overflow-hidden">
      <CardHeader className="bg-gradient-to-r from-primary/10 to-primary/5 pb-4">
        <CardTitle className="text-lg flex items-center justify-between">
          <div className="flex items-center gap-2">
            {getIcon()}
            <div>
              <span>{getTitle()}</span>
              <p className="text-sm font-normal text-muted-foreground">{getDescription()}</p>
            </div>
          </div>
          <Badge variant="secondary">Post-Processor</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-6">
        {analyzerName === "epss_kev" && (
          <EPSSKEVResults data={result as EPSSKEVSummary} />
        )}
        {analyzerName === "reachability" && (
          <ReachabilityResults data={result as ReachabilitySummary} />
        )}
      </CardContent>
    </Card>
  );
}
