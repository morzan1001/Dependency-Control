import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ChevronDown, ChevronRight, RotateCcw, Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useDialogState } from "@/hooks/use-dialog-state";
import { extractErrorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/utils";
import {
  listSystemAudit, listProjectAudit,
  revertSystemPolicy, revertProjectPolicy,
  pruneSystemAudit, pruneProjectAudit,
} from "@/api/policyAudit";
import type { PolicyAuditEntry } from "@/types/policyAudit";
import { PolicyDiffView } from "./PolicyDiffView";
import { RevertConfirmDialog } from "./RevertConfirmDialog";
import { PruneAuditDialog } from "./PruneAuditDialog";

const PAGE_SIZE = 50;

interface Props {
  policyScope: "system" | "project";
  projectId?: string;
  canRevert?: boolean;
}

export function PolicyAuditTimeline({ policyScope, projectId, canRevert = false }: Props) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [revertTarget, setRevertTarget] = useState<number | null>(null);
  const pruneDialog = useDialogState();

  const { data } = useQuery({
    queryKey: ["policy-audit", policyScope, projectId],
    queryFn: async () => {
      if (policyScope === "system") return listSystemAudit({ limit: PAGE_SIZE });
      return listProjectAudit(projectId!, { limit: PAGE_SIZE });
    },
    enabled: policyScope === "system" || !!projectId,
  });

  const entries: PolicyAuditEntry[] = data?.entries ?? [];

  const doRevert = useMutation({
    mutationFn: async ({ version, comment }: { version: number; comment: string }) => {
      if (policyScope === "system") await revertSystemPolicy(version, comment);
      else await revertProjectPolicy(projectId!, version, comment);
    },
    onSuccess: () => {
      toast.success("Policy reverted");
      qc.invalidateQueries({ queryKey: ["policy-audit"] });
      qc.invalidateQueries({ queryKey: ["crypto-policy", policyScope, projectId] });
    },
    onError: (e: Error) => toast.error(`Revert failed: ${e.message}`),
  });

  const doPrune = useMutation({
    mutationFn: async (before: string) => {
      if (policyScope === "system") return pruneSystemAudit(before);
      return pruneProjectAudit(projectId!, before);
    },
    onSuccess: (res) => {
      toast.success(`Pruned ${res.deleted} entr${res.deleted === 1 ? "y" : "ies"}`);
      qc.invalidateQueries({ queryKey: ["policy-audit"] });
      pruneDialog.closeDialog();
    },
    onError: (e: unknown) => toast.error(`Prune failed: ${extractErrorMessage(e)}`),
  });

  return (
    <div className="rounded-md border">
      <div className="flex items-center justify-between border-b bg-muted/30 p-2">
        <span className="text-sm font-medium">Policy audit history</span>
        {canRevert && (
          <Button
            variant="outline"
            size="sm"
            onClick={pruneDialog.openDialog}
            title="Prune old audit entries"
          >
            <Trash2 className="mr-1 h-3 w-3" />
            Prune old entries
          </Button>
        )}
      </div>
      {entries.length === 0 ? (
        <div className="p-4 text-sm text-muted-foreground">No audit entries yet.</div>
      ) : (
        <ul className="divide-y">
          {entries.map((entry, idx) => {
            const isOpen = expanded.has(entry._id);
            const previous = entries[idx + 1];
            const isLast = idx === entries.length - 1;
            // `previous` may be undefined just because of pagination, not because we hit v1.
            const windowTruncated =
              isLast && !previous && entries.length >= PAGE_SIZE && entry.version > 1;
            return (
              <li key={entry._id} className="p-3 text-sm">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      const next = new Set(expanded);
                      if (isOpen) next.delete(entry._id);
                      else next.add(entry._id);
                      setExpanded(next);
                    }}
                    className="flex items-center gap-1 text-left"
                  >
                    {isOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                    <span className="font-mono text-xs text-muted-foreground">v{entry.version}</span>
                    <span className="text-xs uppercase text-muted-foreground">{entry.action}</span>
                    <span className="font-medium">{entry.actor_display_name ?? "(system)"}</span>
                    <span className="text-muted-foreground">—</span>
                    <span>{entry.change_summary}</span>
                  </button>
                  <div className="ml-auto text-xs text-muted-foreground">
                    {formatDateTime(entry.timestamp)}
                  </div>
                  {canRevert && entry.action !== "revert" && (
                    <Button
                      variant="ghost" size="sm"
                      onClick={() => setRevertTarget(entry.version)}
                      title="Revert to this version"
                    >
                      <RotateCcw className="h-3 w-3" />
                    </Button>
                  )}
                </div>
                {entry.comment && (
                  <div className="mt-1 ml-5 text-xs italic text-muted-foreground">
                    "{entry.comment}"
                  </div>
                )}
                {isOpen && (
                  <div className="mt-3 ml-5">
                    {windowTruncated ? (
                      <div className="rounded border border-dashed p-3 text-xs text-muted-foreground">
                        Previous version is beyond the loaded window
                        (showing the most recent {PAGE_SIZE} entries).
                        Showing snapshot only.
                        <pre className="mt-2 max-h-64 overflow-auto rounded bg-muted/50 p-2 text-[11px]">
                          {JSON.stringify(entry.snapshot, null, 2)}
                        </pre>
                      </div>
                    ) : (
                      <PolicyDiffView current={entry} previous={previous} />
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <RevertConfirmDialog
        open={revertTarget !== null}
        targetVersion={revertTarget}
        onClose={() => setRevertTarget(null)}
        onConfirm={async (comment) => {
          if (revertTarget !== null) await doRevert.mutateAsync({ version: revertTarget, comment });
        }}
      />
      <PruneAuditDialog
        open={pruneDialog.open}
        busy={doPrune.isPending}
        onClose={pruneDialog.closeDialog}
        onConfirm={async (before) => { await doPrune.mutateAsync(before); }}
      />
    </div>
  );
}
