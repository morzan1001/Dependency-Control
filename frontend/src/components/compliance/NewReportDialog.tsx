import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { createReport } from "@/api/compliance";
import type { ReportFormat, ReportFramework } from "@/types/compliance";

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
  const [framework, setFramework] = useState<ReportFramework>(defaultFramework);
  const [format, setFormat] = useState<ReportFormat>(defaultFormat);
  const [comment, setComment] = useState("");

  const submit = useMutation({
    mutationFn: () => createReport({ scope: "user", framework, format, comment: comment || undefined }),
    onSuccess: () => {
      toast.success("Report queued");
      qc.invalidateQueries({ queryKey: ["compliance-reports"] });
      setComment("");
      onClose();
    },
    onError: (e: Error) => toast.error(`Failed to queue report: ${e.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader><DialogTitle>Generate Compliance Report</DialogTitle></DialogHeader>
        <div className="space-y-3">
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
          <Button disabled={submit.isPending} onClick={() => submit.mutate()}>
            {submit.isPending ? "Queueing…" : "Generate"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
