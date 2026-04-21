import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CryptoAssetTable } from "@/components/crypto/CryptoAssetTable";
import { CryptoAssetDetailDrawer } from "@/components/crypto/CryptoAssetDetailDrawer";
import { CryptoSummaryHeader } from "@/components/crypto/CryptoSummaryHeader";
import { CryptoFindingsView } from "@/components/crypto/CryptoFindingsView";
import { useProjectScans } from "@/hooks/queries/use-scans";
import { Skeleton } from "@/components/ui/skeleton";
import type { CryptoAsset } from "@/types/crypto";

interface Props {
  projectId: string;
}

export function CryptographyTab({ projectId }: Props) {
  const [selected, setSelected] = useState<CryptoAsset | null>(null);

  const { data: scans, isLoading: isLoadingScans } = useProjectScans(projectId, {
    page: 1,
    limit: 1,
    sortBy: "created_at",
    sortOrder: "desc",
    excludeRescans: false,
    excludeDeletedBranches: false,
  });

  const latestScanId = scans?.[0]?.id;

  if (isLoadingScans) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!latestScanId) {
    return (
      <p className="text-sm text-muted-foreground">
        No scans found for this project. Run a scan to view cryptography data.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <CryptoSummaryHeader projectId={projectId} scanId={latestScanId} />
      <Tabs defaultValue="inventory">
        <TabsList>
          <TabsTrigger value="inventory">Inventory</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
        </TabsList>
        <TabsContent value="inventory">
          <CryptoAssetTable projectId={projectId} scanId={latestScanId} onSelect={setSelected} />
        </TabsContent>
        <TabsContent value="findings">
          <CryptoFindingsView projectId={projectId} scanId={latestScanId} />
        </TabsContent>
      </Tabs>
      <CryptoAssetDetailDrawer asset={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
