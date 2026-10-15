import { useMemo, useState } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface Props {
  open: boolean;
  onClose: () => void;
  onConfirm: (beforeIsoDate: string) => void;
  busy?: boolean;
}

function defaultCutoffISO(): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - 180);
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString().slice(0, 10);
}

export function PruneAuditDialog({ open, onClose, onConfirm, busy }: Readonly<Props>) {
  const defaultDate = useMemo(() => defaultCutoffISO(), []);
  const [beforeDate, setBeforeDate] = useState<string>(defaultDate);

  const handleConfirm = () => onConfirm(new Date(`${beforeDate}T00:00:00.000Z`).toISOString());

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o && !busy) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Prune audit entries</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 text-sm">
          <div className="rounded border border-destructive/40 bg-destructive/5 p-2 text-destructive">
            <strong>Destructive:</strong> audit entries older than the selected
            date will be permanently removed and cannot be recovered.
          </div>
          <div className="grid gap-2">
            <Label htmlFor="prune-before">Prune entries before</Label>
            <Input
              id="prune-before"
              type="date"
              value={beforeDate}
              onChange={(e) => setBeforeDate(e.target.value)}
              max={new Date().toISOString().slice(0, 10)}
            />
            <p className="text-xs text-muted-foreground">
              The backend enforces a minimum cutoff and may reject dates that are
              too recent.
            </p>
          </div>
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
