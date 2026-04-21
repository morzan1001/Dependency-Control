import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { TrendsTimeSeriesChart } from "@/components/crypto/analytics/TrendsTimeSeriesChart";
import type { TrendBucket, TrendMetric } from "@/types/cryptoAnalytics";

const METRICS: TrendMetric[] = [
  "total_crypto_findings",
  "quantum_vulnerable_findings",
  "weak_algo_findings",
  "weak_key_findings",
  "cert_expiring_soon",
  "cert_expired",
  "unique_algorithms",
  "unique_cipher_suites",
];

const PRESETS: { label: string; days: number }[] = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "365d", days: 365 },
];

function autoBucket(days: number): TrendBucket {
  if (days <= 14) return "day";
  if (days <= 90) return "week";
  return "month";
}

interface Props {
  projectIdOverride?: string;
}

export function CryptoTrendsPage({ projectIdOverride }: Props = {}) {
  const routeParams = useParams<{ projectId: string }>();
  const projectId = projectIdOverride ?? routeParams.projectId;
  const [metric, setMetric] = useState<TrendMetric>("total_crypto_findings");
  const [days, setDays] = useState(30);

  const range = useMemo(() => {
    const end = new Date();
    const start = new Date(end);
    start.setDate(end.getDate() - days);
    return { start, end };
  }, [days]);

  if (!projectId) return null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Select value={metric} onValueChange={(v) => setMetric(v as TrendMetric)}>
          <SelectTrigger className="w-64"><SelectValue /></SelectTrigger>
          <SelectContent>
            {METRICS.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="flex gap-1">
          {PRESETS.map((p) => (
            <Button
              key={p.days}
              size="sm"
              variant={days === p.days ? "default" : "outline"}
              onClick={() => setDays(p.days)}
            >
              {p.label}
            </Button>
          ))}
        </div>
      </div>
      <TrendsTimeSeriesChart
        scope="project"
        scopeId={projectId}
        metric={metric}
        bucket={autoBucket(days)}
        rangeStart={range.start}
        rangeEnd={range.end}
      />
    </div>
  );
}

export default CryptoTrendsPage;
