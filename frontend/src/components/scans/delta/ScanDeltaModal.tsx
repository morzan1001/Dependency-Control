import { useCallback, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FindingsDeltaTab } from "./tabs/FindingsDeltaTab";
import { ComponentsDeltaTab } from "./tabs/ComponentsDeltaTab";
import { CryptoDeltaTab } from "./tabs/CryptoDeltaTab";
import { DeltaBadge } from "./shared/DeltaBadge";

interface Props {
  readonly projectId: string;
  readonly fromScanId: string | null;
  readonly toScanId: string | null;
  readonly onClose: () => void;
}

interface BodyProps {
  readonly projectId: string;
  readonly fromScanId: string;
  readonly toScanId: string;
}

type TabId = "findings" | "components" | "crypto";

export function ScanDeltaModal({ projectId, fromScanId, toScanId, onClose }: Props) {
  const open = !!(fromScanId && toScanId);
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <DialogContent className="flex max-h-[90vh] max-w-4xl flex-col">
        <DialogHeader className="shrink-0">
          <DialogTitle>Scan delta</DialogTitle>
          <DialogDescription>
            Added, removed, and changed entries between the two selected scans.
          </DialogDescription>
        </DialogHeader>
        {open && fromScanId && toScanId && (
          // key remounts on scan-pair change to reset tab/visited/count state
          <ScanDeltaBody
            key={`${fromScanId}->${toScanId}`}
            projectId={projectId}
            fromScanId={fromScanId}
            toScanId={toScanId}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function ScanDeltaBody({ projectId, fromScanId, toScanId }: BodyProps) {
  const [active, setActive] = useState<TabId>("findings");
  const [visited, setVisited] = useState<Set<TabId>>(new Set(["findings"]));
  const [counts, setCounts] = useState<Record<TabId, number | null>>({
    findings: null,
    components: null,
    crypto: null,
  });

  const onTabChange = (id: string) => {
    const tab = id as TabId;
    setActive(tab);
    if (!visited.has(tab)) {
      setVisited(new Set(visited).add(tab));
    }
  };

  const onFindingsCount = useCallback((n: number) => {
    setCounts((prev) => ({ ...prev, findings: n }));
  }, []);
  const onComponentsCount = useCallback((n: number) => {
    setCounts((prev) => ({ ...prev, components: n }));
  }, []);
  const onCryptoCount = useCallback((n: number) => {
    setCounts((prev) => ({ ...prev, crypto: n }));
  }, []);

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="shrink-0 pb-2 text-xs text-muted-foreground">
        From <span className="font-mono">{fromScanId}</span> to{" "}
        <span className="font-mono">{toScanId}</span>
      </div>
      <Tabs value={active} onValueChange={onTabChange} className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <TabsList className="shrink-0">
          <TabsTrigger value="findings">
            Findings <DeltaBadge count={counts.findings} />
          </TabsTrigger>
          <TabsTrigger value="components">
            Components <DeltaBadge count={counts.components} />
          </TabsTrigger>
          <TabsTrigger value="crypto">
            Crypto <DeltaBadge count={counts.crypto} />
          </TabsTrigger>
        </TabsList>
        <TabsContent value="findings" className="min-h-0 flex-1 overflow-y-auto">
          {visited.has("findings") && (
            <FindingsDeltaTab
              projectId={projectId}
              fromScanId={fromScanId}
              toScanId={toScanId}
              onCountLoaded={onFindingsCount}
            />
          )}
        </TabsContent>
        <TabsContent value="components" className="min-h-0 flex-1 overflow-y-auto">
          {visited.has("components") && (
            <ComponentsDeltaTab
              projectId={projectId}
              fromScanId={fromScanId}
              toScanId={toScanId}
              onCountLoaded={onComponentsCount}
            />
          )}
        </TabsContent>
        <TabsContent value="crypto" className="min-h-0 flex-1 overflow-y-auto">
          {visited.has("crypto") && (
            <CryptoDeltaTab
              projectId={projectId}
              fromScanId={fromScanId}
              toScanId={toScanId}
              onCountLoaded={onCryptoCount}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
