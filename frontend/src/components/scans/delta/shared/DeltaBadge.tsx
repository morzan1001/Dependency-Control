import { Badge } from "@/components/ui/badge";

interface Props {
  count: number | null; // null = not loaded yet
}

export function DeltaBadge({ count }: Props) {
  if (count === null) {
    return (
      <Badge variant="secondary" className="ml-2">
        —
      </Badge>
    );
  }
  return (
    <Badge variant="secondary" className="ml-2">
      {count}
    </Badge>
  );
}
