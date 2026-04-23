import { useQuery } from "@tanstack/react-query";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { getScanDelta } from "@/api/cryptoAnalytics";

interface Props {
  projectId: string;
  fromScanId: string | null;
  toScanId: string | null;
  onClose: () => void;
}

export function ScanDeltaView({ projectId, fromScanId, toScanId, onClose }: Props) {
  const open = !!(fromScanId && toScanId);
  const { data, isLoading } = useQuery({
    queryKey: ["scan-delta", projectId, fromScanId, toScanId],
    enabled: open,
    queryFn: () => getScanDelta(projectId, fromScanId!, toScanId!),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>Crypto changes between scans</DialogTitle>
        </DialogHeader>
        {isLoading || !data ? (
          <div className="p-4 text-sm">Loading…</div>
        ) : (
          <div className="space-y-4 text-sm">
            <div className="rounded border bg-muted/20 p-3">
              From scan <span className="font-mono">{data.from_scan_id}</span> to{" "}
              <span className="font-mono">{data.to_scan_id}</span> · unchanged:{" "}
              <strong>{data.unchanged_count}</strong>
            </div>
            <DeltaList title="Added" entries={data.added} emphasis="text-green-600" />
            <DeltaList title="Removed" entries={data.removed} emphasis="text-red-600" />
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DeltaList({ title, entries, emphasis }: {
  title: string; entries: { key: string; asset_count: number; project_ids: string[] }[]; emphasis: string;
}) {
  if (entries.length === 0) {
    return <div className={`${emphasis}`}><strong>{title}:</strong> none</div>;
  }
  return (
    <div>
      <div className={`${emphasis} font-medium`}>{title} ({entries.length})</div>
      <ul className="mt-1 list-disc list-inside font-mono text-xs">
        {entries.map((e) => (
          <li key={e.key}>{e.key} — {e.asset_count} asset(s)</li>
        ))}
      </ul>
    </div>
  );
}
