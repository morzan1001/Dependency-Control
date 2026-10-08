import { Badge } from "@/components/ui/badge";

interface Props {
  count: number | null; // null = not loaded yet
}

export function DeltaBadge({ count }: Readonly<Props>) {
  return (
    <Badge variant="secondary" className="ml-2">
      {count ?? "—"}
    </Badge>
  );
}
