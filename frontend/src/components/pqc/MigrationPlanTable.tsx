import { MIGRATION_STATUS_LABEL } from "@/lib/constants";
import { formatDate } from "@/lib/utils";
import type { MigrationItem, MigrationItemStatus } from "@/types/pqcMigration";

interface Props {
  items: MigrationItem[];
  onSelect: (item: MigrationItem) => void;
}

const STATUS_COLOR: Record<MigrationItemStatus, string> = {
  migrate_now: "bg-red-500/90 text-white",
  migrate_soon: "bg-orange-500/80 text-white",
  plan_migration: "bg-yellow-500/60",
  monitor: "bg-muted text-foreground",
};

export function MigrationPlanTable({ items, onSelect }: Readonly<Props>) {
  if (!items.length) {
    return <div className="p-4 text-sm text-muted-foreground">No quantum-vulnerable crypto assets detected.</div>;
  }
  return (
    <div className="rounded-md border overflow-x-auto">
      <table className="w-full min-w-[920px] text-sm">
        <thead className="bg-muted/50 text-left">
          <tr>
            <th className="p-2">Status</th>
            <th className="p-2 w-20">Priority</th>
            <th className="p-2">Family</th>
            <th className="p-2">Variant / Key</th>
            <th className="p-2">→ Recommended PQC</th>
            <th className="p-2">Standard</th>
            <th className="p-2 w-24">Occurrences</th>
            <th className="p-2 w-24">Projects</th>
            <th className="p-2">Deadline</th>
          </tr>
        </thead>
        <tbody>
          {items.map((it) => (
            <tr
              key={it.asset_bom_ref}
              role="button"
              tabIndex={0}
              className="cursor-pointer border-t hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              onClick={() => onSelect(it)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(it);
                }
              }}
            >
              <td className="p-2">
                <span className={`rounded px-2 py-0.5 text-xs ${STATUS_COLOR[it.status]}`}>
                  {MIGRATION_STATUS_LABEL[it.status]}
                </span>
              </td>
              <td className="p-2 font-mono">{it.priority_score}</td>
              <td className="p-2 font-mono">{it.source_family}</td>
              <td className="p-2 text-xs">
                {it.asset_variant ?? (it.asset_key_size_bits ? `${it.asset_key_size_bits} bits` : "—")}
              </td>
              <td className="p-2 font-mono">{it.recommended_pqc}</td>
              <td className="p-2 text-xs">{it.recommended_standard}</td>
              <td className="p-2">{it.asset_count}</td>
              <td className="p-2">{it.project_ids.length}</td>
              <td className="p-2 text-xs">
                {it.recommended_deadline ? formatDate(it.recommended_deadline) : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
