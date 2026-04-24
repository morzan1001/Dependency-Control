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
import { createReport } from "@/api/compliance";
import type { ReportFormat, ReportFramework } from "@/types/compliance";
import { useAuth } from "@/context/useAuth";

const FRAMEWORKS: { value: ReportFramework; label: string }[] = [
  { value: "nist-sp-800-131a", label: "NIST SP 800-131A" },
  { value: "bsi-tr-02102", label: "BSI TR-02102" },
  { value: "cnsa-2.0", label: "CNSA 2.0" },
  { value: "fips-140-3", label: "FIPS 140-3 (algorithm-level)" },
  { value: "iso-19790", label: "ISO/IEC 19790 (algorithm-level)" },
  { value: "pqc-migration-plan", label: "PQC Migration Plan" },
];

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
  open: boolean;
  onClose: () => void;
  defaultFramework?: ReportFramework;
  defaultFormat?: ReportFormat;
}

export function NewReportDialog({
  open, onClose, defaultFramework = "nist-sp-800-131a", defaultFormat = "pdf",
}: Props) {
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

  const submit = useMutation({
    mutationFn: () => createReport({
      scope,
      scope_id: needsScopeId ? scopeId.trim() : null,
      framework,
      format,
      comment: comment || undefined,
    }),
    onSuccess: () => {
      toast.success("Report queued");
      qc.invalidateQueries({ queryKey: ["compliance-reports"] });
      setComment("");
      setScope("user");
      setScopeId("");
      setScopeError(null);
      onClose();
    },
    onError: (e: Error) => toast.error(`Failed to queue report: ${e.message}`),
  });

  const handleSubmit = () => {
    if (needsScopeId && !scopeId.trim()) {
      setScopeError(`A ${scope} ID is required for ${scope} scope.`);
      return;
    }
    setScopeError(null);
    submit.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader><DialogTitle>Generate Compliance Report</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <label className="block text-sm">
            <span className="text-muted-foreground">Scope</span>
            <Select value={scope} onValueChange={(v) => { setScope(v as Scope); setScopeError(null); }}>
              <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
              <SelectContent>
                {scopeOptions.map((s) => (
                  <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <span className="mt-1 block text-xs text-muted-foreground">
              {scopeOptions.find((s) => s.value === scope)?.description}
            </span>
          </label>
          {needsScopeId && (
            <label className="block text-sm">
              <span className="text-muted-foreground">
                {scope === "project" ? "Project ID" : "Team ID"}
              </span>
              <Input
                value={scopeId}
                onChange={(e) => { setScopeId(e.target.value); setScopeError(null); }}
                placeholder={scope === "project" ? "e.g. 64f1…" : "e.g. team-frontend"}
                className="mt-1"
              />
              {scopeError && (
                <span className="mt-1 block text-xs text-destructive">{scopeError}</span>
              )}
            </label>
          )}
          <label className="block text-sm">
            <span className="text-muted-foreground">Framework</span>
            <Select value={framework} onValueChange={(v) => setFramework(v as ReportFramework)}>
              <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
              <SelectContent>
                {FRAMEWORKS.map((f) => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">Format</span>
            <Select value={format} onValueChange={(v) => setFormat(v as ReportFormat)}>
              <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
              <SelectContent>
                {FORMATS.map((f) => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">Audit comment (optional)</span>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              className="mt-1 w-full rounded border p-2 text-sm"
              rows={2}
              maxLength={1000}
            />
          </label>
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
