import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";
import type { Waiver } from "@/types/waiver";

/**
 * Renders a waiver's expiration cell. Shows the formatted date (or "Never"),
 * plus an "Expired" badge when the backend marks the waiver inactive — so the
 * user can spot dead waivers without re-deriving the rule client-side.
 */
export function WaiverExpiryCell({ waiver }: { readonly waiver: Waiver }) {
  return (
    <div className="flex items-center gap-1.5">
      <span>{waiver.expiration_date ? formatDate(waiver.expiration_date) : "Never"}</span>
      {waiver.is_active === false && (
        <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
          Expired
        </Badge>
      )}
    </div>
  );
}
