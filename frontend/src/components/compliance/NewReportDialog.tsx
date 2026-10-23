import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ProjectCombobox } from "@/components/ui/project-combobox";
import { createReport } from "@/api/compliance";
import type { ReportFormat, ReportFramework } from "@/types/compliance";
import { useAuth } from "@/context/useAuth";
import { useTeams } from "@/hooks/queries/use-teams";
import { useCurrentUser } from "@/hooks/queries/use-users";
import { REPORT_FRAMEWORK_LABELS } from "@/lib/constants";

const FORMATS: { value: ReportFormat; label: string }[] = [
  { value: "pdf", label: "PDF" },
  { value: "csv", label: "CSV" },
  { value: "json", label: "JSON" },
  { value: "sarif", label: "SARIF" },
];

type Scope = "user" | "project" | "team" | "global";

interface ScopeOption {
  value: Scope;
  label: string;
  description: string;
}

interface Props {
  onClose: () => void;
  defaultFramework?: ReportFramework;
  defaultFormat?: ReportFormat;
}

export function NewReportDialog({
  onClose, defaultFramework = "nist-sp-800-131a", defaultFormat = "pdf",
}: Readonly<Props>) {
  const qc = useQueryClient();
  const { hasPermission } = useAuth();
  const canGlobal = hasPermission("system:manage") || hasPermission("analytics:global");

  const scopeOptions = useMemo<ScopeOption[]>(() => {
    const opts: ScopeOption[] = [
      { value: "user", label: "User (personal)", description: "Only visible to you." },
      { value: "project", label: "Project", description: "Report for a single project." },
      { value: "team", label: "Team", description: "Report aggregated across a team." },
    ];
    if (canGlobal) {
      opts.push({
        value: "global",
        label: "Global",
        description: "System-wide report across all projects (admin).",
      });
    }
    return opts;
  }, [canGlobal]);

  const [framework, setFramework] = useState<ReportFramework>(defaultFramework);
  const [format, setFormat] = useState<ReportFormat>(defaultFormat);
  const [comment, setComment] = useState("");
  const [scope, setScope] = useState<Scope>("user");
  const [scopeId, setScopeId] = useState("");
  const [scopeError, setScopeError] = useState<string | null>(null);

  const needsScopeId = scope === "project" || scope === "team";
  const readsAllProjects = canGlobal || hasPermission("project:read_all");
  // The report gate admits these callers to teams or projects that GET /teams or GET /projects would not list.
  const typesScopeId = scope === "team"
    ? readsAllProjects && !hasPermission("team:read_all")
    : hasPermission("project:update") && !hasPermission("project:read") && !hasPermission("project:read_all");
  const { data: teams } = useTeams(undefined, "name", "asc", { enabled: scope === "team" && !typesScopeId });
  const { data: me } = useCurrentUser();
  // team:read_all lists every team, but without all projects the report gate admits only the caller's own.
  const offeredTeams = readsAllProjects ? teams : teams?.filter((t) => t.members?.some((m) => m.user_id === me?.id));
  const pickScopeId = (id: string) => { setScopeId(id); setScopeError(null); };
  const scopeIdField = {
    id: "report-scope-id",
    "aria-invalid": !!scopeError,
    "aria-describedby": scopeError ? "report-scope-id-error" : undefined,
  };

  const submit = useMutation({
    mutationFn: () => createReport({
      scope,
      scope_id: needsScopeId ? scopeId : null,
      framework,
      format,
      comment: comment || undefined,
    }),
    onSuccess: () => {
      toast.success("Report queued");
      qc.invalidateQueries({ queryKey: ["compliance-reports"] });
      onClose();
    },
    meta: { errorTitle: "Failed to queue report" },
  });

  const handleSubmit = () => {
    if (needsScopeId && !scopeId) {
      setScopeError(`Select a ${scope} for ${scope} scope`);
      return;
    }
    setScopeError(null);
    submit.mutate();
  };

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Generate Compliance Report</DialogTitle></DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="report-scope">Scope</Label>
            <Select value={scope} onValueChange={(v) => { setScope(v as Scope); pickScopeId(""); }}>
              <SelectTrigger id="report-scope"><SelectValue /></SelectTrigger>
              <SelectContent>
                {scopeOptions.map((s) => (
                  <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {scopeOptions.find((s) => s.value === scope)?.description}
            </p>
          </div>
          {needsScopeId && (
            <div className="grid grid-cols-1 gap-2">
              <Label htmlFor={scopeIdField.id}>{scope === "project" ? "Project" : "Team"}</Label>
              {typesScopeId && (
                <Input {...scopeIdField} value={scopeId} onChange={(e) => pickScopeId(e.target.value.trim())} placeholder={scope === "project" ? "Project ID" : "Team ID"} />
              )}
              {scope === "project" && !typesScopeId && (
                <ProjectCombobox {...scopeIdField} value={scopeId} onValueChange={pickScopeId} />
              )}
              {scope === "team" && !typesScopeId && (
                <Select value={scopeId} onValueChange={pickScopeId}>
                  <SelectTrigger {...scopeIdField}><SelectValue placeholder="Select a team..." /></SelectTrigger>
                  <SelectContent>
                    {offeredTeams?.map((t) => <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>)}
                  </SelectContent>
                </Select>
              )}
              {scopeError && (
                <p id="report-scope-id-error" role="alert" className="text-xs text-destructive">{scopeError}</p>
              )}
            </div>
          )}
          <div className="grid gap-2">
            <Label htmlFor="report-framework">Framework</Label>
            <Select value={framework} onValueChange={(v) => setFramework(v as ReportFramework)}>
              <SelectTrigger id="report-framework"><SelectValue /></SelectTrigger>
              <SelectContent>
                {Object.entries(REPORT_FRAMEWORK_LABELS).map(([value, label]) => <SelectItem key={value} value={value}>{label}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="report-format">Format</Label>
            <Select value={format} onValueChange={(v) => setFormat(v as ReportFormat)}>
              <SelectTrigger id="report-format"><SelectValue /></SelectTrigger>
              <SelectContent>
                {FORMATS.map((f) => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="report-comment">Audit comment (optional)</Label>
            <Textarea
              id="report-comment"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={2}
              maxLength={1000}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={submit.isPending} onClick={handleSubmit}>
            {submit.isPending ? "Queueing\u2026" : "Generate"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
