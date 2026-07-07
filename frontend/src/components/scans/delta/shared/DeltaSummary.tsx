interface Props {
  readonly added: number;
  readonly removed: number;
  readonly unchanged: number;
  readonly changed?: number;
}

export function DeltaSummary({ added, removed, unchanged, changed }: Props) {
  return (
    <div className="rounded border bg-muted/20 p-2 text-xs">
      +{added} added · -{removed} removed
      {changed !== undefined && <> · ↻{changed} changed</>}
      {" · "}
      {unchanged} unchanged
    </div>
  );
}
