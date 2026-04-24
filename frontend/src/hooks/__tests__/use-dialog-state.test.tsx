import { describe, it, expect } from "vitest";
import { act, renderHook } from "@testing-library/react";

import { useDialogState } from "../use-dialog-state";

describe("useDialogState", () => {
  it("starts closed by default", () => {
    const { result } = renderHook(() => useDialogState());
    expect(result.current.open).toBe(false);
  });

  it("respects the initialOpen argument", () => {
    const { result } = renderHook(() => useDialogState(true));
    expect(result.current.open).toBe(true);
  });

  it("openDialog / closeDialog flip the flag", () => {
    const { result } = renderHook(() => useDialogState());
    act(() => result.current.openDialog());
    expect(result.current.open).toBe(true);
    act(() => result.current.closeDialog());
    expect(result.current.open).toBe(false);
  });

  it("toggleDialog inverts the flag", () => {
    const { result } = renderHook(() => useDialogState());
    act(() => result.current.toggleDialog());
    expect(result.current.open).toBe(true);
    act(() => result.current.toggleDialog());
    expect(result.current.open).toBe(false);
  });
});
