import { useCallback, useState } from "react";

export interface DialogState {
  open: boolean;
  openDialog: () => void;
  closeDialog: () => void;
  setOpen: (next: boolean) => void;
}

export function useDialogState(initialOpen = false): DialogState {
  const [open, setOpen] = useState<boolean>(initialOpen);
  const openDialog = useCallback(() => setOpen(true), []);
  const closeDialog = useCallback(() => setOpen(false), []);
  return { open, openDialog, closeDialog, setOpen };
}
