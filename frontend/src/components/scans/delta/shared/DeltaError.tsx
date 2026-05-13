import type { DeltaCategory } from "@/types/scanDelta";

interface Props {
  readonly category: DeltaCategory;
}

export function DeltaError({ category }: Props) {
  return <div className="text-destructive text-sm">Failed to load {category} delta.</div>;
}
