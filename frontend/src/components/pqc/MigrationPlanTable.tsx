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

const STATUS_LABEL: Record<MigrationItemStatus, string> = {
  migrate_now: "Migrate now",
  migrate_soon: "Migrate soon",
  plan_migration: "Plan migration",
  monitor: "Monitor",
};

export function MigrationPlanTable({ items, onSelect }: Props) {
  if (!items.length) {
    return <div className="p-4 text-sm text-muted-foreground">No quantum-vulnerable crypto assets detected.</div>;
  }
  return (
    <div className="rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-muted/50 text-left">
          <tr>
            <th className="p-2">Status</th>
            <th className="p-2 w-20">Priority</th>
            <th className="p-2">Family</th>
            <th className="p-2">Variant / Key</th>
            <th className="p-2">→ Recommended PQC</th>
            <th className="p-2">Standard</th>
            <th className="p-2 w-24">Assets</th>
            <th className="p-2 w-24">Projects</th>
            <th className="p-2">Deadline</th>
          </tr>
        </thead>
        <tbody>
          {items.map((it) => (
            <tr
              key={it.asset_bom_ref}
              className="cursor-pointer border-t hover:bg-muted/30"
              onClick={() => onSelect(it)}
            >
              <td className="p-2">
                <span className={`rounded px-2 py-0.5 text-xs ${STATUS_COLOR[it.status]}`}>
                  {STATUS_LABEL[it.status]}
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
                {it.recommended_deadline ? new Date(it.recommended_deadline).toLocaleDateString() : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
