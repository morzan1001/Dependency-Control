import { useMemo, useState } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface Props {
  open: boolean;
  onClose: () => void;
  onConfirm: (beforeIsoDate: string) => Promise<void>;
  busy?: boolean;
}

function defaultCutoffISO(): string {
  // 180 days ago, at 00:00 UTC
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - 180);
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString().slice(0, 10);
}

export function PruneAuditDialog({ open, onClose, onConfirm, busy }: Props) {
  const defaultDate = useMemo(() => defaultCutoffISO(), []);
  const [beforeDate, setBeforeDate] = useState<string>(defaultDate);

  const handleConfirm = async () => {
    if (!beforeDate) return;
    // Convert YYYY-MM-DD to ISO 8601 at 00:00 UTC
    const iso = new Date(`${beforeDate}T00:00:00.000Z`).toISOString();
    await onConfirm(iso);
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o && !busy) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Prune audit entries</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 text-sm">
          <div className="rounded border border-destructive/40 bg-destructive/5 p-2 text-destructive">
            <strong>Destructive:</strong> audit entries older than the selected
            date will be permanently removed and cannot be recovered.
          </div>
          <label className="block">
            <span className="text-muted-foreground">Prune entries before</span>
            <input
              type="date"
              value={beforeDate}
              onChange={(e) => setBeforeDate(e.target.value)}
              className="mt-1 block w-full rounded border bg-background p-2 text-sm"
              max={new Date().toISOString().slice(0, 10)}
            />
          </label>
          <p className="text-xs text-muted-foreground">
            The backend enforces a minimum cutoff and may reject dates that are
            too recent.
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={handleConfirm}
            disabled={busy || !beforeDate}
          >
            {busy ? "Pruning\u2026" : "Prune"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
