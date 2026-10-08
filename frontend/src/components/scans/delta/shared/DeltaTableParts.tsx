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

export function DeltaFilterGroup<T extends string>({ label, options, isActive, onSelect }: Readonly<{
  label: string;
  options: readonly T[];
  isActive: (option: T) => boolean;
  onSelect: (option: T) => void;
}>) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-muted-foreground">{label}:</span>
      {options.map((option) => (
        <Button key={option} size="sm" variant={isActive(option) ? "default" : "outline"} onClick={() => onSelect(option)}>
          {option}
        </Button>
      ))}
    </div>
  );
}

const SKELETON_ROWS = ["s1", "s2", "s3"];
const SKELETON_CELLS = ["c1", "c2", "c3", "c4", "c5", "c6"];

export function DeltaStatusRows({ isLoading, rows, columns, emptyText }: Readonly<{
  isLoading: boolean;
  rows: number;
  columns: number;
  emptyText: string;
}>) {
  if (isLoading) {
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
  if (rows > 0) return null;
  return (
    <TableRow>
      <TableCell colSpan={columns} className="py-8 text-center text-muted-foreground">
        {emptyText}
      </TableCell>
    </TableRow>
  );
}
