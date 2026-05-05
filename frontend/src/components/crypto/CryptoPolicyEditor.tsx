import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import type {
  CryptoRule, Severity, CryptoFindingType, CryptoPolicySource,
} from "@/types/cryptoPolicy";
import type { CryptoPrimitive } from "@/types/crypto";

interface Props {
  /**
   * Rules to display. In merged mode this is the *effective* list (system
   * rules with overrides applied); the editor diffs against `systemRules`
   * on save to emit only the override delta.
   */
  initialRules: CryptoRule[];
  /**
   * When provided, the editor renders a Status column (System / Overridden
   * / Custom), exposes a "Revert" action per overridden row, and `onSave`
   * receives only the rules that differ from the system baseline.
   */
  systemRules?: CryptoRule[];
  onSave: (rules: CryptoRule[]) => Promise<void>;
  onResetOverride?: () => Promise<void>;
  readOnly?: boolean;
  title?: string;
  subtitle?: string;
}

type RuleStatus = "system" | "overridden" | "custom";
type StatusFilter = "all" | RuleStatus;

const SEVERITIES: Severity[] = [
  "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN",
];
const FINDING_TYPES: { value: CryptoFindingType; label: string }[] = [
  { value: "crypto_weak_algorithm", label: "Weak algorithm" },
  { value: "crypto_weak_key", label: "Weak key" },
  { value: "crypto_quantum_vulnerable", label: "Quantum-vulnerable" },
  { value: "crypto_cert_expired", label: "Certificate expired" },
  { value: "crypto_cert_expiring_soon", label: "Certificate expiring soon" },
  { value: "crypto_cert_not_yet_valid", label: "Certificate not yet valid" },
  { value: "crypto_cert_weak_signature", label: "Certificate weak signature" },
  { value: "crypto_cert_weak_key", label: "Certificate weak key" },
  { value: "crypto_cert_self_signed", label: "Certificate self-signed" },
  { value: "crypto_cert_validity_too_long", label: "Certificate validity too long" },
  { value: "crypto_weak_protocol", label: "Weak protocol" },
  { value: "crypto_key_management", label: "Key management misuse" },
];
const SOURCES: CryptoPolicySource[] = [
  "nist-sp-800-131a", "bsi-tr-02102", "cnsa-2.0", "nist-pqc", "custom",
];
const PRIMITIVES: CryptoPrimitive[] = [
  "block-cipher", "stream-cipher", "hash", "mac", "pke", "signature",
  "kem", "kdf", "drbg", "other",
];

// Reserved for AddRuleDialog primitive selection.
void PRIMITIVES;

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
    enabled: true,
    source: "custom",
    references: [],
  };
}

function arraysEqual<T>(a: T[], b: T[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

function rulesEqual(a: CryptoRule, b: CryptoRule): boolean {
  return (
    a.name === b.name
    && a.description === b.description
    && a.finding_type === b.finding_type
    && a.default_severity === b.default_severity
    && a.match_primitive === b.match_primitive
    && a.match_min_key_size_bits === b.match_min_key_size_bits
    && a.quantum_vulnerable === b.quantum_vulnerable
    && a.enabled === b.enabled
    && a.source === b.source
    && arraysEqual(a.match_name_patterns, b.match_name_patterns)
    && arraysEqual(a.match_curves, b.match_curves)
    && arraysEqual(a.match_protocol_versions, b.match_protocol_versions)
    && arraysEqual(a.references, b.references)
  );
}

function getRuleStatus(rule: CryptoRule, systemMap: Map<string, CryptoRule>): RuleStatus {
  const sys = systemMap.get(rule.rule_id);
  if (!sys) return "custom";
  return rulesEqual(rule, sys) ? "system" : "overridden";
}

function StatusBadge({ status }: { status: RuleStatus }) {
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
    <span className={`inline-block text-xs px-2 py-0.5 rounded-full ${styles[status]}`}>
      {labels[status]}
    </span>
  );
}

export function CryptoPolicyEditor({
  initialRules, systemRules, onSave, onResetOverride, readOnly, title, subtitle,
}: Props) {
  const [rules, setRules] = useState<CryptoRule[]>(initialRules);
  const [addOpen, setAddOpen] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<CryptoPolicySource | "all">("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [saving, setSaving] = useState(false);

  const mergedMode = systemRules !== undefined;
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
      // In merged mode emit only the override delta (rules that differ from
      // the system baseline). In standalone mode emit the rules as-is — the
      // system-policy admin page uses that.
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

      <div className="rounded-md border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-left">
            <tr>
              <th className="p-2 w-16">Enabled</th>
              <th className="p-2">Rule</th>
              <th className="p-2">Finding type</th>
              <th className="p-2 w-28">Severity</th>
              <th className="p-2 w-32">Min key size</th>
              <th className="p-2">Name patterns</th>
              <th className="p-2 w-32">Source</th>
              {mergedMode && <th className="p-2 w-32">Status</th>}
              {!readOnly && <th className="p-2 w-24" />}
            </tr>
          </thead>
          <tbody>
            {visibleRules.map((r) => {
              const idx = rules.findIndex(x => x.rule_id === r.rule_id);
              const status = mergedMode ? getRuleStatus(r, systemMap) : "system";
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
                    <Input
                      disabled={readOnly}
                      value={r.name}
                      onChange={(e) => updateRule(idx, { name: e.target.value })}
                      className="mt-1"
                    />
                  </td>
                  <td className="p-2">
                    <Select
                      value={r.finding_type}
                      disabled={readOnly}
                      onValueChange={(v) => updateRule(idx, { finding_type: v as CryptoFindingType })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {FINDING_TYPES.map((f) => (
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
                      className="w-24"
                    />
                  </td>
                  <td className="p-2">
                    <Input
                      disabled={readOnly}
                      value={r.match_name_patterns.join(", ")}
                      onChange={(e) => updateRule(idx, {
                        match_name_patterns: e.target.value.split(",").map(s => s.trim()).filter(Boolean),
                      })}
                      placeholder="comma-separated"
                    />
                  </td>
                  <td className="p-2 font-mono text-xs">{r.source}</td>
                  {mergedMode && (
                    <td className="p-2"><StatusBadge status={status} /></td>
                  )}
                  {!readOnly && (
                    <td className="p-2 text-right">
                      {mergedMode && status === "overridden" && (
                        <Button variant="outline" size="sm"
                          onClick={() => revertRule(r.rule_id)}>
                          Revert
                        </Button>
                      )}
                      {(!mergedMode || status === "custom") && r.source === "custom" && (
                        <Button variant="outline" size="sm"
                          onClick={() => removeRule(r.rule_id)}>
                          Remove
                        </Button>
                      )}
                    </td>
                  )}
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
}: {
  existingIds: Set<string>;
  onClose: () => void;
  onAdd: (r: CryptoRule) => void;
}) {
  const [rule, setRule] = useState<CryptoRule>(emptyRule());
  const [error, setError] = useState<string | null>(null);

  const submit = () => {
    if (!rule.rule_id) { setError("rule_id is required"); return; }
    if (existingIds.has(rule.rule_id)) { setError("rule_id already exists"); return; }
    if (!rule.name) { setError("name is required"); return; }
    onAdd(rule);
  };

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-xl">
        <DialogHeader><DialogTitle>Add custom crypto rule</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <label className="block text-sm">
            <span className="text-muted-foreground">rule_id</span>
            <Input value={rule.rule_id}
              onChange={(e) => setRule({ ...rule, rule_id: e.target.value })}
              placeholder="e.g. custom-block-rc4" />
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">name</span>
            <Input value={rule.name}
              onChange={(e) => setRule({ ...rule, name: e.target.value })} />
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">description</span>
            <Input value={rule.description}
              onChange={(e) => setRule({ ...rule, description: e.target.value })} />
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">match name patterns (comma-separated)</span>
            <Input
              value={rule.match_name_patterns.join(", ")}
              onChange={(e) => setRule({
                ...rule,
                match_name_patterns: e.target.value.split(",").map(s => s.trim()).filter(Boolean),
              })}
            />
          </label>
          {error && <div className="text-sm text-destructive">{error}</div>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={submit}>Add</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
