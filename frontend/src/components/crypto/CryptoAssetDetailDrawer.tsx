import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { CryptoAsset } from "@/types/crypto";

interface Props {
  asset: CryptoAsset | null;
  onClose: () => void;
}

export function CryptoAssetDetailDrawer({ asset, onClose }: Props) {
  return (
    <Dialog open={!!asset} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-w-2xl">
        {asset && (
          <>
            <DialogHeader>
              <DialogTitle className="font-mono">{asset.name}</DialogTitle>
            </DialogHeader>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <FieldRow label="Asset type" value={asset.asset_type} />
              <FieldRow label="bom-ref" value={asset.bom_ref} />
              <FieldRow label="Primitive" value={asset.primitive} />
              <FieldRow label="Variant" value={asset.variant} />
              <FieldRow label="Key size (bits)" value={asset.key_size_bits?.toString()} />
              <FieldRow label="Mode" value={asset.mode} />
              <FieldRow label="Padding" value={asset.padding} />
              <FieldRow label="Curve" value={asset.curve} />
              <FieldRow label="Subject" value={asset.subject_name} />
              <FieldRow label="Issuer" value={asset.issuer_name} />
              <FieldRow label="Not valid after" value={asset.not_valid_after} />
              <FieldRow label="Protocol" value={asset.protocol_type} />
              <FieldRow label="Version" value={asset.version} />
              <FieldRow label="Detection" value={asset.detection_context} />
              <FieldRow
                label="Confidence"
                value={asset.confidence != null ? `${(asset.confidence * 100).toFixed(0)}%` : null}
              />
            </dl>
            {asset.occurrence_locations.length > 0 && (
              <div>
                <div className="mt-4 text-xs font-medium text-muted-foreground">Locations</div>
                <ul className="mt-1 list-inside list-disc text-sm">
                  {asset.occurrence_locations.map((l, i) => <li key={i}>{l}</li>)}
                </ul>
              </div>
            )}
            {asset.related_dependency_purls.length > 0 && (
              <div>
                <div className="mt-4 text-xs font-medium text-muted-foreground">Related dependencies</div>
                <ul className="mt-1 list-inside list-disc text-sm font-mono">
                  {asset.related_dependency_purls.map((p, i) => <li key={i}>{p}</li>)}
                </ul>
              </div>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function FieldRow({ label, value }: { label: string; value?: string | null }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{value ?? "—"}</dd>
    </>
  );
}
