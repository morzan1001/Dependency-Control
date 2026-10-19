import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import type { Severity } from "@/types/common";
import type {
  CryptoRule, CryptoFindingType, CryptoPolicySource,
} from "@/types/cryptoPolicy";
import { CRYPTO_FINDING_TYPES } from "@/lib/constants";

interface Props {
  // Effective rules (system + overrides) in merged mode; diffed against systemRules on save.
  initialRules: CryptoRule[];
  // When set, enables merged mode: Status column, per-row Revert, and onSave emits only the override delta.
  systemRules?: CryptoRule[];
  onSave: (rules: CryptoRule[]) => Promise<void>;
  onResetOverride?: () => void;
  readOnly?: boolean;
  title?: string;
  subtitle?: string;
}

type RuleStatus = "system" | "overridden" | "custom";
type StatusFilter = "all" | RuleStatus;

const SEVERITIES: Severity[] = [
  "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN",
];
const SOURCES: CryptoPolicySource[] = [
  "nist-sp-800-131a", "bsi-tr-02102", "cnsa-2.0", "nist-pqc", "custom",
];

function emptyRule(): CryptoRule {
  return {
    rule_id: "",
    name: "",
    description: "",
    finding_type: "crypto_weak_algorithm",
    default_severity: "HIGH",
    match_primitive: null,
    match_name_patterns: [],
    match_min_key_size_bits: null,
    match_curves: [],
    match_protocol_versions: [],
    quantum_vulnerable: null,
    enabled: false,
    source: "custom",
    references: [],
  };
}

function splitPatterns(text: string): string[] {
  return text.split(",").map(s => s.trim()).filter(Boolean);
}

// Every key counts: the API also returns the certificate thresholds this editor does not show.
function rulesEqual(a: CryptoRule, b: CryptoRule): boolean {
  const keys = Object.keys({ ...a, ...b }) as (keyof CryptoRule)[];
  return keys.every((k) => JSON.stringify(a[k]) === JSON.stringify(b[k]));
}

function getRuleStatus(rule: CryptoRule, systemMap: Map<string, CryptoRule>): RuleStatus {
  const sys = systemMap.get(rule.rule_id);
  if (!sys) return "custom";
  return rulesEqual(rule, sys) ? "system" : "overridden";
}

function StatusBadge({ status }: Readonly<{ status: RuleStatus }>) {
  const styles: Record<RuleStatus, string> = {
    system: "bg-muted text-muted-foreground",
    overridden: "bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200",
    custom: "bg-blue-100 text-blue-900 dark:bg-blue-900/40 dark:text-blue-200",
  };
  const labels: Record<RuleStatus, string> = {
    system: "System default",
    overridden: "Overridden",
    custom: "Custom",
  };
  return (
    <span className={`inline-block whitespace-nowrap text-xs px-2 py-0.5 rounded-full ${styles[status]}`}>
      {labels[status]}
    </span>
  );
}

export function CryptoPolicyEditor({
  initialRules, systemRules, onSave, onResetOverride, readOnly, title, subtitle,
}: Readonly<Props>) {
  const [rules, setRules] = useState<CryptoRule[]>(initialRules);
  // Resync editor state when the parent supplies a new initialRules reference (useState only reads it once).
  const [syncedRules, setSyncedRules] = useState<CryptoRule[]>(initialRules);
  if (initialRules !== syncedRules) {
    setSyncedRules(initialRules);
    setRules(initialRules);
  }
  const [addOpen, setAddOpen] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<CryptoPolicySource | "all">("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [saving, setSaving] = useState(false);

  const mergedMode = systemRules !== undefined;
  const actionColumn = !readOnly && !mergedMode;
  const systemMap = useMemo(
    () => new Map((systemRules ?? []).map(r => [r.rule_id, r])),
    [systemRules],
  );

  const visibleRules = useMemo(() => {
    return rules.filter(r => {
      if (sourceFilter !== "all" && r.source !== sourceFilter) return false;
      if (mergedMode && statusFilter !== "all" && getRuleStatus(r, systemMap) !== statusFilter) {
        return false;
      }
      return true;
    });
  }, [rules, sourceFilter, statusFilter, mergedMode, systemMap]);

  const updateRule = (idx: number, patch: Partial<CryptoRule>) => {
    setRules(rs => rs.map((r, i) => (i === idx ? { ...r, ...patch } : r)));
  };

  const removeRule = (rule_id: string) => {
    setRules(rs => rs.filter(r => r.rule_id !== rule_id));
  };

  const revertRule = (rule_id: string) => {
    const sys = systemMap.get(rule_id);
    if (!sys) return;
    setRules(rs => rs.map(r => (r.rule_id === rule_id ? { ...sys } : r)));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const toEmit = mergedMode
        ? rules.filter(r => getRuleStatus(r, systemMap) !== "system")
        : rules;
      await onSave(toEmit);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-3">
      {(title || subtitle) && (
        <div>
          {title && <h2 className="text-lg font-semibold">{title}</h2>}
          {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <Select
          value={sourceFilter}
          onValueChange={(v) => setSourceFilter(v as typeof sourceFilter)}
        >
          <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All sources</SelectItem>
            {SOURCES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        {mergedMode && (
          <Select
            value={statusFilter}
            onValueChange={(v) => setStatusFilter(v as StatusFilter)}
          >
            <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="system">System default</SelectItem>
              <SelectItem value="overridden">Overridden</SelectItem>
              <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
          </Select>
        )}
        {!readOnly && (
          <Button size="sm" onClick={() => setAddOpen(true)}>Add custom rule</Button>
        )}
        <div className="flex-1" />
        {!readOnly && onResetOverride && (
          <Button variant="outline" size="sm" onClick={onResetOverride}>
            Reset all overrides
          </Button>
        )}
        {!readOnly && (
          <Button onClick={handleSave} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </Button>
        )}
      </div>

      <div className="rounded-md border overflow-x-auto">
        {/* Rule takes what the fixed columns leave, never less than 200px; a project's 960px fit the 989px a 1440px screen leaves. */}
        <table
          className="w-full table-fixed text-sm"
          style={{ minWidth: 840 + (mergedMode ? 120 : 0) + (actionColumn ? 96 : 0) }}
        >
          <thead className="bg-muted/50 text-left">
            <tr>
              <th className="p-2 w-18">Enabled</th>
              <th className="p-2 w-auto">Rule</th>
              <th className="p-2 w-48">Finding type</th>
              <th className="p-2 w-30">Severity</th>
              <th className="p-2 w-24">Min key size</th>
              <th className="p-2 w-40">Name patterns</th>
              {mergedMode && <th className="p-2 w-30">Status</th>}
              {actionColumn && <th className="p-2 w-24" />}
            </tr>
          </thead>
          <tbody>
            {visibleRules.map((r) => {
              const idx = rules.findIndex(x => x.rule_id === r.rule_id);
              const status = mergedMode ? getRuleStatus(r, systemMap) : "system";
              const revertable = mergedMode && status === "overridden";
              const removable = (!mergedMode || status === "custom") && r.source === "custom";
              const action = !readOnly && (revertable || removable) && (
                <Button
                  variant="outline" size="sm" className="h-6 text-xs"
                  onClick={() => (revertable ? revertRule(r.rule_id) : removeRule(r.rule_id))}
                >
                  {revertable ? "Revert" : "Remove"}
                </Button>
              );
              return (
                <tr key={r.rule_id} className="border-t">
                  <td className="p-2">
                    <Switch
                      checked={r.enabled}
                      disabled={readOnly}
                      onCheckedChange={(v) => updateRule(idx, { enabled: v })}
                    />
                  </td>
                  <td className="p-2">
                    <Textarea
                      disabled={readOnly}
                      value={r.name}
                      title={r.name}
                      onChange={(e) => updateRule(idx, { name: e.target.value.replaceAll(/\s*\n\s*/g, " ") })}
                      className="min-h-10 resize-none field-sizing-content"
                    />
                    <div className="mt-1 font-mono text-xs text-muted-foreground">{r.source}</div>
                  </td>
                  <td className="p-2">
                    <Select
                      value={r.finding_type}
                      disabled={readOnly}
                      onValueChange={(v) => updateRule(idx, { finding_type: v as CryptoFindingType })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {CRYPTO_FINDING_TYPES.map((f) => (
                          <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </td>
                  <td className="p-2">
                    <Select
                      value={r.default_severity}
                      disabled={readOnly}
                      onValueChange={(v) => updateRule(idx, { default_severity: v as Severity })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </td>
                  <td className="p-2">
                    <Input
                      type="number"
                      disabled={readOnly}
                      value={r.match_min_key_size_bits ?? ""}
                      onChange={(e) => updateRule(idx, {
                        match_min_key_size_bits: e.target.value === "" ? null : Number(e.target.value),
                      })}
                      placeholder="—"
                      className="w-20"
                    />
                  </td>
                  <td className="p-2">
                    {/* Parsed on blur so a trailing comma survives typing; the key reloads it on revert or resync. */}
                    <Input
                      key={r.match_name_patterns.join(",")}
                      disabled={readOnly}
                      defaultValue={r.match_name_patterns.join(", ")}
                      onBlur={(e) => updateRule(idx, { match_name_patterns: splitPatterns(e.target.value) })}
                      placeholder="comma-separated"
                    />
                  </td>
                  {mergedMode && (
                    <td className="p-2">
                      <div className="flex flex-col items-start gap-1">
                        <StatusBadge status={status} />
                        {action}
                      </div>
                    </td>
                  )}
                  {actionColumn && <td className="p-2 text-right">{action}</td>}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {addOpen && (
        <AddRuleDialog
          existingIds={new Set(rules.map((r) => r.rule_id))}
          onClose={() => setAddOpen(false)}
          onAdd={(r) => { setRules((rs) => [...rs, r]); setAddOpen(false); }}
        />
      )}
    </div>
  );
}

function AddRuleDialog({
  existingIds, onClose, onAdd,
}: Readonly<{
  existingIds: Set<string>;
  onClose: () => void;
  onAdd: (r: CryptoRule) => void;
}>) {
  const [rule, setRule] = useState<CryptoRule>(emptyRule());
  const [patternsText, setPatternsText] = useState("");
  const [error, setError] = useState<{ field: "rule_id" | "name"; message: string } | null>(null);

  const edit = (patch: Partial<CryptoRule>) => {
    setRule((r) => ({ ...r, ...patch }));
    setError(null);
  };

  const submit = () => {
    if (!rule.rule_id) { setError({ field: "rule_id", message: "Enter a rule ID" }); return; }
    if (existingIds.has(rule.rule_id)) { setError({ field: "rule_id", message: "A rule with this ID already exists" }); return; }
    if (!rule.name) { setError({ field: "name", message: "Enter a name" }); return; }
    onAdd({ ...rule, match_name_patterns: splitPatterns(patternsText) });
  };

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Add custom crypto rule</DialogTitle></DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="rule-id">Rule ID</Label>
            <Input
              id="rule-id"
              value={rule.rule_id}
              onChange={(e) => edit({ rule_id: e.target.value })}
              placeholder="e.g. custom-block-rc4"
              aria-invalid={error?.field === "rule_id"}
              aria-describedby={error?.field === "rule_id" ? "rule-id-error" : undefined}
            />
            {error?.field === "rule_id" && (
              <p id="rule-id-error" role="alert" className="text-xs text-destructive">{error.message}</p>
            )}
          </div>
          <div className="grid gap-2">
            <Label htmlFor="rule-name">Name</Label>
            <Input
              id="rule-name"
              value={rule.name}
              onChange={(e) => edit({ name: e.target.value })}
              aria-invalid={error?.field === "name"}
              aria-describedby={error?.field === "name" ? "rule-name-error" : undefined}
            />
            {error?.field === "name" && (
              <p id="rule-name-error" role="alert" className="text-xs text-destructive">{error.message}</p>
            )}
          </div>
          <div className="grid gap-2">
            <Label htmlFor="rule-description">Description</Label>
            <Input id="rule-description" value={rule.description}
              onChange={(e) => edit({ description: e.target.value })} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="rule-patterns">Name patterns (comma-separated)</Label>
            <Input id="rule-patterns" value={patternsText} onChange={(e) => setPatternsText(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={submit}>Add</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
