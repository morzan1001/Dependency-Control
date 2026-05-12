import { useCallback, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
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

type TabId = "findings" | "components" | "crypto";

export function ScanDeltaModal({ projectId, fromScanId, toScanId, onClose }: Props) {
  const open = !!(fromScanId && toScanId);
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
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Scan delta</DialogTitle>
        </DialogHeader>
        {open && fromScanId && toScanId && (
          <>
            <div className="text-xs text-muted-foreground pb-2">
              From <span className="font-mono">{fromScanId}</span> to{" "}
              <span className="font-mono">{toScanId}</span>
            </div>
            <Tabs value={active} onValueChange={onTabChange}>
              <TabsList>
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
              <TabsContent value="findings">
                {visited.has("findings") && (
                  <FindingsDeltaTab
                    projectId={projectId}
                    fromScanId={fromScanId}
                    toScanId={toScanId}
                    onCountLoaded={onFindingsCount}
                  />
                )}
              </TabsContent>
              <TabsContent value="components">
                {visited.has("components") && (
                  <ComponentsDeltaTab
                    projectId={projectId}
                    fromScanId={fromScanId}
                    toScanId={toScanId}
                    onCountLoaded={onComponentsCount}
                  />
                )}
              </TabsContent>
              <TabsContent value="crypto">
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
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
