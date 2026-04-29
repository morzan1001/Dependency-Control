import type { PolicyAuditEntry } from "@/types/policyAudit";

interface Props {
  current: PolicyAuditEntry;
  previous?: PolicyAuditEntry;
}

type RuleSnap = { rule_id?: string; [k: string]: unknown };

export function PolicyDiffView({ current, previous }: Props) {
  const currentRules = (current.snapshot?.rules as RuleSnap[] | undefined) ?? [];
  const previousRules = (previous?.snapshot?.rules as RuleSnap[] | undefined) ?? [];

  const currentById = new Map(currentRules.map((r) => [r.rule_id, r]));
  const previousById = new Map(previousRules.map((r) => [r.rule_id, r]));

  const added = currentRules.filter((r) => !previousById.has(r.rule_id));
  const removed = previousRules.filter((r) => !currentById.has(r.rule_id));
  const modified = currentRules.filter((r) => {
    const prev = previousById.get(r.rule_id);
    return prev && JSON.stringify(prev) !== JSON.stringify(r);
  });

  return (
    <div className="space-y-3 text-xs">
      <Section title="Added" color="text-green-600" rules={added} />
      <Section title="Removed" color="text-red-600" rules={removed} />
      <Section title="Modified" color="text-amber-600" rules={modified} />
      {added.length === 0 && removed.length === 0 && modified.length === 0 && (
        <div className="text-muted-foreground">No effective rule changes.</div>
      )}
    </div>
  );
}

function Section({ title, color, rules }: { title: string; color: string; rules: RuleSnap[] }) {
  if (rules.length === 0) return null;
  return (
    <div>
      <div className={`${color} font-medium`}>{title} ({rules.length})</div>
      <ul className="mt-1 list-inside list-disc font-mono">
        {rules.map((r, i) => (
          <li key={`${r.rule_id}-${i}`}>{r.rule_id as string}</li>
        ))}
      </ul>
    </div>
  );
}
