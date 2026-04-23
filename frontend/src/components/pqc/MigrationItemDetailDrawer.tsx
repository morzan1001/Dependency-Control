import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import type { MigrationItem } from "@/types/pqcMigration";

interface Props {
  item: MigrationItem | null;
  onClose: () => void;
}

export function MigrationItemDetailDrawer({ item, onClose }: Props) {
  return (
    <Dialog open={!!item} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-2xl">
        {item && (
          <>
            <DialogHeader>
              <DialogTitle className="font-mono">
                {item.source_family} → {item.recommended_pqc}
              </DialogTitle>
            </DialogHeader>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <dt className="text-muted-foreground">Priority score</dt><dd>{item.priority_score}</dd>
              <dt className="text-muted-foreground">Status</dt><dd>{item.status}</dd>
              <dt className="text-muted-foreground">Primitive</dt><dd>{item.source_primitive}</dd>
              <dt className="text-muted-foreground">Use case</dt><dd>{item.use_case}</dd>
              <dt className="text-muted-foreground">Standard</dt><dd>{item.recommended_standard}</dd>
              <dt className="text-muted-foreground">Key size</dt>
              <dd>{item.asset_key_size_bits ? `${item.asset_key_size_bits} bits` : "—"}</dd>
              <dt className="text-muted-foreground">Variant</dt><dd>{item.asset_variant ?? "—"}</dd>
              <dt className="text-muted-foreground">Asset count</dt><dd>{item.asset_count}</dd>
              <dt className="text-muted-foreground">Deadline</dt>
              <dd>
                {item.recommended_deadline
                  ? new Date(item.recommended_deadline).toLocaleDateString()
                  : "—"}
              </dd>
            </dl>
            <div className="mt-4">
              <div className="text-xs font-medium text-muted-foreground">Notes</div>
              <p className="mt-1 whitespace-pre-line text-sm">{item.notes}</p>
            </div>
            {item.project_ids.length > 0 && (
              <div className="mt-4">
                <div className="text-xs font-medium text-muted-foreground">Projects</div>
                <ul className="mt-1 list-inside list-disc font-mono text-xs">
                  {item.project_ids.map((p) => <li key={p}>{p}</li>)}
                </ul>
              </div>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
