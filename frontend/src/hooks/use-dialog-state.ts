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
