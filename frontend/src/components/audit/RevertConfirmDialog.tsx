import { useState } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface Props {
  open: boolean;
  targetVersion: number | null;
  onClose: () => void;
  onConfirm: (comment: string) => Promise<void>;
}

export function RevertConfirmDialog({ open, targetVersion, onClose, onConfirm }: Props) {
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader><DialogTitle>Revert to version {targetVersion}?</DialogTitle></DialogHeader>
        <p className="text-sm text-muted-foreground">
          This creates a new policy version whose rules match version{" "}
          <strong>{targetVersion}</strong>. The history is preserved.
        </p>
        <label className="block text-sm">
          <span className="text-muted-foreground">Comment (required for revert)</span>
          <textarea
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            className="mt-1 w-full rounded border p-2 text-sm"
            rows={3}
            maxLength={1000}
          />
        </label>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            disabled={busy || !comment.trim()}
            onClick={async () => {
              setBusy(true);
              try { await onConfirm(comment); onClose(); } finally { setBusy(false); }
            }}
          >
            {busy ? "Reverting…" : "Confirm revert"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
