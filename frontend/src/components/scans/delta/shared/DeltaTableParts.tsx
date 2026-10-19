import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { TableCell, TableRow } from "@/components/ui/table";

export function DeltaFilterBar({ children }: { readonly children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border bg-muted/30 p-2 text-xs">
      {children}
    </div>
  );
}

export function DeltaFilterGroup<T extends string>({ label, options, isActive, onSelect, labelOf }: Readonly<{
  label: string;
  options: readonly T[];
  isActive: (option: T) => boolean;
  onSelect: (option: T) => void;
  labelOf?: (option: T) => string;
}>) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-muted-foreground">{label}:</span>
      {options.map((option) => (
        <Button key={option} size="sm" variant={isActive(option) ? "default" : "outline"} onClick={() => onSelect(option)}>
          {labelOf?.(option) ?? option}
        </Button>
      ))}
    </div>
  );
}

const SKELETON_ROWS = ["s1", "s2", "s3"];
const SKELETON_CELLS = ["c1", "c2", "c3", "c4", "c5", "c6"];

export function DeltaLoadingRows({ isLoading, columns }: Readonly<{ isLoading: boolean; columns: number }>) {
  if (!isLoading) return null;
  return (
    <>
      {SKELETON_ROWS.map((row) => (
        <TableRow key={row}>
          {SKELETON_CELLS.slice(0, columns).map((cell) => (
            <TableCell key={cell}>
              <Skeleton className="h-5 w-20" />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
}

export function DeltaEmptyText({ isLoading, rows, text }: Readonly<{ isLoading: boolean; rows: number; text: string }>) {
  if (isLoading || rows > 0) return null;
  return <p className="py-8 text-center text-sm text-muted-foreground">{text}</p>;
}
