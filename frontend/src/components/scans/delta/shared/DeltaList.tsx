import { ReactNode } from "react";

interface Props<T extends { id?: string | number }> {
  items: T[];
  renderRow: (item: T, index: number) => ReactNode;
  emptyMessage: string;
  isLoading: boolean;
}

export function DeltaList<T extends { id?: string | number }>({
  items,
  renderRow,
  emptyMessage,
  isLoading,
}: Props<T>) {
  if (isLoading) {
    return (
      <div data-testid="delta-list-skeleton" className="space-y-1">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-6 animate-pulse rounded bg-muted/40" />
        ))}
      </div>
    );
  }
  if (items.length === 0) {
    return <div className="py-4 text-sm text-muted-foreground">{emptyMessage}</div>;
  }
  return (
    <ul className="divide-y divide-border">
      {items.map((it, i) => (
        <li key={it.id ?? i} className="py-2 text-sm">
          {renderRow(it, i)}
        </li>
      ))}
    </ul>
  );
}
