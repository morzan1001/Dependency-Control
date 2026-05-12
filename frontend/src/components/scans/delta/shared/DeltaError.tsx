interface Props {
  readonly category: "findings" | "components" | "crypto";
}

export function DeltaError({ category }: Props) {
  return <div className="text-destructive text-sm">Failed to load {category} delta.</div>;
}
