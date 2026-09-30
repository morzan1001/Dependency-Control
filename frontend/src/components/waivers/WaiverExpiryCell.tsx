import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";
import type { Waiver } from "@/types/waiver";

export function WaiverExpiryCell({ waiver }: { readonly waiver: Waiver }) {
  return (
    <div className="flex items-center gap-1.5">
      <span>
        {/* The picked day is stored as its end in UTC, so any other zone can show a neighbouring day. */}
        {waiver.expiration_date
          ? formatDate(waiver.expiration_date, { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" })
          : "Never"}
      </span>
      {waiver.is_active === false && (
        <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
          Expired
        </Badge>
      )}
    </div>
  );
}
