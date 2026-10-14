import { useState } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

interface Props {
  open: boolean;
  targetVersion: number | null;
  onClose: () => void;
  onConfirm: (comment: string) => Promise<void>;
}

export function RevertConfirmDialog({ open, targetVersion, onClose, onConfirm }: Readonly<Props>) {
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const close = () => { setComment(""); onClose(); };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) close(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader><DialogTitle>Revert to version {targetVersion}?</DialogTitle></DialogHeader>
        <p className="text-sm text-muted-foreground">
          This creates a new policy version whose rules match version{" "}
          <strong>{targetVersion}</strong>. The history is preserved.
        </p>
        <div className="grid gap-2">
          <Label htmlFor="revert-comment">Comment (required for revert)</Label>
          <Textarea
            id="revert-comment"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            rows={3}
            maxLength={1000}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={close}>Cancel</Button>
          <Button
            disabled={busy || !comment.trim()}
            onClick={async () => {
              setBusy(true);
              try {
                await onConfirm(comment);
                close();
              } catch {
                // The caller's toast reports the failure; the dialog stays open for another try.
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Reverting…" : "Confirm revert"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
