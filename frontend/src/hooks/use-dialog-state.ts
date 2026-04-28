/**
 * useDialogState — tiny hook that owns the typical
 *   const [open, setOpen] = useState(false);
 *   const close = () => setOpen(false);
 * boilerplate every shadcn Dialog needs.
 *
 * Returns a stable object with `open`, `openDialog`, `closeDialog`,
 * `toggleDialog`, and a low-level `setOpen`. Pass `openDialog.open` into
 * the Dialog's `open` prop and `onOpenChange={(next) => !next && closeDialog()}`
 * (or pass `closeDialog` directly to your "Cancel" button).
 */

import { useCallback, useState } from "react";

export interface DialogState {
  open: boolean;
  openDialog: () => void;
  closeDialog: () => void;
  toggleDialog: () => void;
  setOpen: (next: boolean) => void;
}

export function useDialogState(initialOpen = false): DialogState {
  const [open, setOpen] = useState<boolean>(initialOpen);
  const openDialog = useCallback(() => setOpen(true), []);
  const closeDialog = useCallback(() => setOpen(false), []);
  const toggleDialog = useCallback(() => setOpen((v) => !v), []);
  return { open, openDialog, closeDialog, toggleDialog, setOpen };
}
