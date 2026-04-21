import { useQueries } from "@tanstack/react-query";
import { scanApi } from "@/api/scans";
import { Finding } from "@/types/scan";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { FindingTypeBadge } from "@/components/findings/FindingTypeBadge";

const CRYPTO_TYPES = [
  "crypto_weak_algorithm",
  "crypto_weak_key",
  "crypto_quantum_vulnerable",
] as const;

interface Props {
  projectId: string;
  scanId?: string;
}

export function CryptoFindingsView({ projectId, scanId }: Props) {
  const results = useQueries({
    queries: CRYPTO_TYPES.map((type) => ({
      queryKey: ["findings", scanId, "crypto", type],
      queryFn: () =>
        scanApi.getFindings(scanId!, { type, skip: 0, limit: 200 }),
      enabled: !!scanId && !!projectId,
    })),
  });

  const isLoading = results.some((r) => r.isLoading);
  const isError = results.some((r) => r.isError);

  const allFindings: Finding[] = results.flatMap((r) => r.data?.items ?? []);

  if (!scanId) {
    return (
      <p className="text-sm text-muted-foreground">
        No scan available. Run a scan to see crypto findings.
      </p>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <p className="text-sm text-destructive">Failed to load crypto findings.</p>
    );
  }

  if (allFindings.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No crypto findings found.</p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-[120px]">Severity</TableHead>
          <TableHead className="w-[160px]">Type</TableHead>
          <TableHead>Component</TableHead>
          <TableHead className="w-[80px]">Version</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {allFindings.map((finding) => (
          <TableRow key={finding.id}>
            <TableCell className="p-4 align-middle">
              <SeverityBadge severity={finding.severity} />
            </TableCell>
            <TableCell className="p-4 align-middle">
              <FindingTypeBadge type={finding.type} />
            </TableCell>
            <TableCell className="p-4 align-middle font-medium">
              {finding.component ?? "—"}
            </TableCell>
            <TableCell className="p-4 align-middle text-sm text-muted-foreground">
              {finding.version ?? "—"}
            </TableCell>
            <TableCell className="p-4 align-middle text-sm">
              {finding.description ?? "—"}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
