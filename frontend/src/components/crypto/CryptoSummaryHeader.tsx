import { useQuery } from "@tanstack/react-query";
import { getCryptoSummary } from "@/api/crypto";
import { Card } from "@/components/ui/card";

interface Props {
  projectId: string;
  scanId: string;
}

export function CryptoSummaryHeader({ projectId, scanId }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["crypto-summary", projectId, scanId],
    queryFn: () => getCryptoSummary(projectId, scanId),
    enabled: !!projectId && !!scanId,
  });

  if (isLoading || !data) {
    return <div className="h-20" aria-busy />;
  }

  const byType = data.by_type ?? {};
  const algorithms = byType.algorithm ?? 0;
  const certificates = byType.certificate ?? 0;
  const protocols = byType.protocol ?? 0;
  const material = byType["related-crypto-material"] ?? 0;

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
      <SummaryCard label="Total Assets" value={data.total} />
      <SummaryCard label="Algorithms" value={algorithms} />
      <SummaryCard label="Certificates" value={certificates} />
      <SummaryCard label="Protocols" value={protocols} />
      <SummaryCard label="Key Material" value={material} />
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: number }) {
  return (
    <Card className="p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </Card>
  );
}
